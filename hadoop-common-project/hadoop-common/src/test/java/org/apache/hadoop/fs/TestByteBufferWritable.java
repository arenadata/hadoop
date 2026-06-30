/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.fs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Random;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.CryptoCodec;
import org.apache.hadoop.crypto.CryptoOutputStream;
import org.apache.hadoop.util.DataChecksum;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the write(ByteBuffer) path added for HDFS-15693
 * ({@link ByteBufferWritable} / {@link StreamCapabilities#WRITEBYTEBUFFER}).
 *
 * The contract under test: writing through {@link FSOutputSummer#write(ByteBuffer)}
 * must produce exactly the same stream of data chunks and checksums as the
 * pre-existing {@code write(byte[])} path, whether the buffer is direct (fast
 * path), heap, or the stream does not advertise the capability (both drain to
 * the byte[] path).
 */
public class TestByteBufferWritable {

  private static final int BPC = 512;
  // Sizes around chunk and 9-chunk local-buffer boundaries, plus a large one.
  private static final int[] SIZES = {
      0, 1, 3, 511, 512, 513, 1024, 4607, 4608, 4609, 5000,
      9 * BPC, 9 * BPC + 1, 13947, 1 << 20, (1 << 20) + 7};

  /** Records every writeChunk(byte[]...) call so the two paths can be compared. */
  private static final class CapturingSummer extends FSOutputSummer {
    private final ByteArrayOutputStream data = new ByteArrayOutputStream();
    private final ByteArrayOutputStream cks = new ByteArrayOutputStream();
    private final boolean advertise;

    CapturingSummer(boolean advertise) {
      super(DataChecksum.newDataChecksum(DataChecksum.Type.CRC32C, BPC));
      this.advertise = advertise;
    }

    @Override
    protected void writeChunk(byte[] b, int off, int len, byte[] checksum,
        int ckoff, int cklen) {
      data.write(b, off, len);
      cks.write(checksum, ckoff, cklen);
    }

    @Override
    protected void checkClosed() { }

    @Override
    public boolean hasCapability(String capability) {
      return advertise
          && StreamCapabilities.WRITEBYTEBUFFER.equalsIgnoreCase(capability);
    }

    /** Flush the trailing partial chunk too, so streams are fully comparable. */
    void finish() throws IOException {
      flushBuffer();
    }
  }

  @FunctionalInterface
  private interface Writer {
    void write(CapturingSummer s) throws IOException;
  }

  private static byte[] payload(int n) {
    byte[] p = new byte[n];
    new Random(n * 2654435761L + 17).nextBytes(p);
    return p;
  }

  private static ByteBuffer direct(byte[] p) {
    ByteBuffer bb = ByteBuffer.allocateDirect(p.length);
    bb.put(p);
    bb.flip();
    return bb;
  }

  /** Direct buffer holding p at [pre, pre+p.length), position=pre, limit<capacity. */
  private static ByteBuffer directWithOffset(byte[] p, int pre, int post) {
    ByteBuffer bb = ByteBuffer.allocateDirect(pre + p.length + post);
    for (int i = 0; i < pre; i++) {
      bb.put((byte) 0xAA);
    }
    bb.put(p);
    for (int i = 0; i < post; i++) {
      bb.put((byte) 0xBB);
    }
    bb.position(pre);
    bb.limit(pre + p.length);
    return bb;
  }

  private static byte[][] capture(boolean advertise, Writer w) throws IOException {
    CapturingSummer s = new CapturingSummer(advertise);
    w.write(s);
    s.finish();
    return new byte[][] {s.data.toByteArray(), s.cks.toByteArray()};
  }

  private void assertMatchesByteArrayPath(int n, boolean advertise, Writer variant)
      throws IOException {
    final byte[] p = payload(n);
    byte[][] ref = capture(false, s -> s.write(p, 0, n));
    byte[][] got = capture(advertise, variant);
    assertArrayEquals("data mismatch, n=" + n, ref[0], got[0]);
    assertArrayEquals("checksum mismatch, n=" + n, ref[1], got[1]);
    assertEquals("data length, n=" + n, n, got[0].length);
  }

  /** Direct buffer + advertised capability takes the zero-copy checksum path. */
  @Test
  public void testDirectByteBufferMatchesByteArray() throws IOException {
    for (int n : SIZES) {
      final byte[] p = payload(n);
      assertMatchesByteArrayPath(n, true, s -> s.write(direct(p)));
    }
  }

  /** Heap buffers have no direct benefit and must drain through the byte[] path. */
  @Test
  public void testHeapByteBufferMatchesByteArray() throws IOException {
    for (int n : SIZES) {
      final byte[] p = payload(n);
      assertMatchesByteArrayPath(n, true, s -> s.write(ByteBuffer.wrap(p)));
    }
  }

  /** A stream that does not advertise the capability must drain a direct buffer. */
  @Test
  public void testDirectByteBufferWithoutCapabilityDrains() throws IOException {
    for (int n : SIZES) {
      final byte[] p = payload(n);
      assertMatchesByteArrayPath(n, false, s -> s.write(direct(p)));
    }
  }

  /** byte[] prefix then a direct ByteBuffer remainder exercises partial carry-over. */
  @Test
  public void testInterleavedByteArrayAndByteBuffer() throws IOException {
    for (int n : SIZES) {
      final byte[] p = payload(n);
      final int k = Math.min(n, 700); // non-aligned, leaves count>0 in the buffer
      assertMatchesByteArrayPath(n, true, s -> {
        s.write(p, 0, k);
        s.write(direct(java.util.Arrays.copyOfRange(p, k, n)));
      });
    }
  }

  /** A direct buffer entering with position>0 and limit<capacity. */
  @Test
  public void testNonZeroPositionDirectBuffer() throws IOException {
    for (int n : SIZES) {
      final byte[] p = payload(n);
      assertMatchesByteArrayPath(n, true, s -> s.write(directWithOffset(p, 7, 5)));
    }
  }

  // ---- FSDataOutputStream / PositionCache plumbing ----

  /** Wrapped stream that records bytes and advertises direct-write support. */
  private static final class RecordingOut extends OutputStream
      implements ByteBufferWritable, StreamCapabilities {
    final ByteArrayOutputStream got = new ByteArrayOutputStream();
    @Override public void write(int b) { got.write(b); }
    @Override public void write(byte[] b, int off, int len) { got.write(b, off, len); }
    @Override public void write(ByteBuffer buf) {
      while (buf.hasRemaining()) {
        got.write(buf.get());
      }
    }
    @Override public boolean hasCapability(String c) {
      return StreamCapabilities.WRITEBYTEBUFFER.equalsIgnoreCase(c);
    }
  }

  @Test
  public void testFSDataOutputStreamForwardsAndTracksPosition() throws IOException {
    RecordingOut rec = new RecordingOut();
    try (FSDataOutputStream out = new FSDataOutputStream(rec, null)) {
      assertTrue(out.hasCapability(StreamCapabilities.WRITEBYTEBUFFER));
      byte[] p = payload(5000);
      out.write(direct(p));
      assertEquals(5000, out.getPos());
      assertArrayEquals(p, rec.got.toByteArray());
    }
  }

  @Test
  public void testFSDataOutputStreamDrainsNonByteBufferWritable() throws IOException {
    ByteArrayOutputStream plain = new ByteArrayOutputStream();
    try (FSDataOutputStream out = new FSDataOutputStream(plain, null)) {
      assertFalse(out.hasCapability(StreamCapabilities.WRITEBYTEBUFFER));
      byte[] p = payload(3000);
      out.write(direct(p));
      assertEquals(3000, out.getPos());
      assertArrayEquals(p, plain.toByteArray());
    }
  }

  /** CryptoOutputStream suppresses WRITEBYTEBUFFER even over a capable stream. */
  @Test
  public void testCryptoOutputStreamSuppressesCapability() throws IOException {
    CryptoCodec codec = CryptoCodec.getInstance(new Configuration());
    RecordingOut rec = new RecordingOut();
    assertTrue(rec.hasCapability(StreamCapabilities.WRITEBYTEBUFFER));
    try (CryptoOutputStream cos =
        new CryptoOutputStream(rec, codec, new byte[16], new byte[16])) {
      assertFalse(cos.hasCapability(StreamCapabilities.WRITEBYTEBUFFER));
    }
  }
}
