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
package org.apache.hadoop.hdfs;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Random;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.StreamCapabilities;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * End-to-end test of {@link FSDataOutputStream#write(ByteBuffer)} (HDFS-15693)
 * against a mini-cluster: data written through the direct ByteBuffer path must
 * round-trip byte-for-byte, matching the byte[] write path.
 */
public class TestByteBufferWrite {

  private static MiniDFSCluster cluster;
  private static FileSystem fs;

  private static final long SEED = 0xBEEFCAFEL;
  private static final int BLOCK_SIZE = 4096;
  // Spans several blocks and is not a multiple of the chunk/block size.
  private static final int FILE_SIZE = 12 * BLOCK_SIZE + 1234;

  @BeforeClass
  public static void setup() throws IOException {
    Configuration conf = new Configuration();
    conf.setLong(DFSConfigKeys.DFS_BLOCK_SIZE_KEY, BLOCK_SIZE);
    cluster = new MiniDFSCluster.Builder(conf).numDataNodes(3).build();
    cluster.waitActive();
    fs = cluster.getFileSystem();
  }

  @AfterClass
  public static void teardown() throws IOException {
    if (fs != null) {
      fs.close();
    }
    if (cluster != null) {
      cluster.shutdown();
    }
  }

  private static byte[] randomBytes(int n) {
    byte[] b = new byte[n];
    new Random(SEED).nextBytes(b);
    return b;
  }

  private static ByteBuffer direct(byte[] b) {
    ByteBuffer bb = ByteBuffer.allocateDirect(b.length);
    bb.put(b);
    bb.flip();
    return bb;
  }

  private byte[] readBack(Path p) throws IOException {
    byte[] read = new byte[(int) fs.getFileStatus(p).getLen()];
    try (FSDataInputStream in = fs.open(p)) {
      in.readFully(read);
    }
    return read;
  }

  /** A replicated DFS output stream advertises the write(ByteBuffer) capability. */
  @Test
  public void testCapabilityAdvertised() throws IOException {
    Path p = new Path("/bbwrite-cap.dat");
    try (FSDataOutputStream out = fs.create(p, (short) 3)) {
      assertTrue("DFSOutputStream should advertise WRITEBYTEBUFFER",
          out.hasCapability(StreamCapabilities.WRITEBYTEBUFFER));
      assertFalse(out.hasCapability("no:such:capability"));
    }
  }

  /** Write the whole file from a single direct ByteBuffer and read it back. */
  @Test
  public void testWriteDirectByteBuffer() throws IOException {
    Path p = new Path("/bbwrite-direct.dat");
    byte[] data = randomBytes(FILE_SIZE);
    try (FSDataOutputStream out = fs.create(p, (short) 3)) {
      ByteBuffer bb = direct(data);
      out.write(bb);
      assertFalse("whole buffer should be consumed", bb.hasRemaining());
      assertEquals(FILE_SIZE, out.getPos());
    }
    assertArrayEquals(data, readBack(p));
  }

  /** Heap ByteBuffers must round-trip too (they drain through the byte[] path). */
  @Test
  public void testWriteHeapByteBuffer() throws IOException {
    Path p = new Path("/bbwrite-heap.dat");
    byte[] data = randomBytes(FILE_SIZE);
    try (FSDataOutputStream out = fs.create(p, (short) 3)) {
      out.write(ByteBuffer.wrap(data));
      assertEquals(FILE_SIZE, out.getPos());
    }
    assertArrayEquals(data, readBack(p));
  }

  /**
   * Mix byte[], direct-ByteBuffer and heap-ByteBuffer writes (simulating a
   * native caller streaming chunks of varying size) and verify the round-trip.
   */
  @Test
  public void testWriteMixedChunks() throws IOException {
    Path p = new Path("/bbwrite-mixed.dat");
    byte[] data = randomBytes(FILE_SIZE);
    try (FSDataOutputStream out = fs.create(p, (short) 3)) {
      int off = 0;
      int[] chunks = {37, 512, 4096, 5000, 700, 8192};
      boolean useDirect = true;
      for (int c : chunks) {
        int len = Math.min(c, FILE_SIZE - off);
        if (len == 0) {
          break;
        }
        if (off % 3 == 0) {
          out.write(data, off, len);                 // byte[] path
        } else if (useDirect) {
          out.write(direct(java.util.Arrays.copyOfRange(data, off, off + len)));
        } else {
          out.write(ByteBuffer.wrap(data, off, len));
        }
        useDirect = !useDirect;
        off += len;
      }
      // remainder via one direct buffer
      if (off < FILE_SIZE) {
        out.write(direct(java.util.Arrays.copyOfRange(data, off, FILE_SIZE)));
      }
      assertEquals(FILE_SIZE, out.getPos());
    }
    assertArrayEquals(data, readBack(p));
  }

  /** Many small direct writes (the libhdfs/Impala ~50-64KB pattern). */
  @Test
  public void testManySmallDirectWrites() throws IOException {
    Path p = new Path("/bbwrite-small.dat");
    byte[] data = randomBytes(FILE_SIZE);
    final int step = 50 * 1024;
    try (FSDataOutputStream out = fs.create(p, (short) 3)) {
      for (int off = 0; off < FILE_SIZE; off += step) {
        int len = Math.min(step, FILE_SIZE - off);
        out.write(direct(java.util.Arrays.copyOfRange(data, off, off + len)));
      }
      assertEquals(FILE_SIZE, out.getPos());
    }
    assertArrayEquals(data, readBack(p));
  }

  /** A direct buffer entering with position>0 / limit<capacity round-trips. */
  @Test
  public void testWriteDirectByteBufferWithOffset() throws IOException {
    Path p = new Path("/bbwrite-offset.dat");
    byte[] data = randomBytes(FILE_SIZE);
    final int pre = 777, post = 333;
    ByteBuffer bb = ByteBuffer.allocateDirect(pre + FILE_SIZE + post);
    bb.position(pre);
    bb.put(data);
    bb.position(pre);
    bb.limit(pre + FILE_SIZE);
    try (FSDataOutputStream out = fs.create(p, (short) 3)) {
      out.write(bb);
      assertFalse(bb.hasRemaining());
      assertEquals(FILE_SIZE, out.getPos());
    }
    assertArrayEquals(data, readBack(p));
  }

  /** hflush on the ByteBuffer path makes the written prefix visible before close. */
  @Test
  public void testHflushVisibility() throws IOException {
    Path p = new Path("/bbwrite-hflush.dat");
    byte[] first = randomBytes(5000);
    byte[] second = randomBytes(3000);
    try (FSDataOutputStream out = fs.create(p, (short) 3)) {
      out.write(direct(first));
      out.hflush();
      try (FSDataInputStream in = fs.open(p)) {
        byte[] got = new byte[first.length];
        in.readFully(got);
        assertArrayEquals(first, got);
      }
      out.write(direct(second));
    }
    byte[] all = new byte[first.length + second.length];
    System.arraycopy(first, 0, all, 0, first.length);
    System.arraycopy(second, 0, all, first.length, second.length);
    assertArrayEquals(all, readBack(p));
  }

  /** EC streams opt out of WRITEBYTEBUFFER; a direct write still drains correctly. */
  @Test
  public void testErasureCodedOptOut() throws IOException {
    MiniDFSCluster ec = new MiniDFSCluster.Builder(new Configuration())
        .numDataNodes(3).build();
    try {
      ec.waitActive();
      DistributedFileSystem dfs = ec.getFileSystem();
      final String policy = "XOR-2-1-1024k";
      dfs.enableErasureCodingPolicy(policy);
      Path dir = new Path("/ec");
      dfs.mkdirs(dir);
      dfs.setErasureCodingPolicy(dir, policy);
      Path p = new Path(dir, "ec.dat");
      byte[] data = randomBytes(FILE_SIZE);
      try (FSDataOutputStream out = dfs.create(p)) {
        assertFalse("EC stream must not advertise WRITEBYTEBUFFER",
            out.hasCapability(StreamCapabilities.WRITEBYTEBUFFER));
        out.write(direct(data));
        assertEquals(FILE_SIZE, out.getPos());
      }
      byte[] read = new byte[FILE_SIZE];
      try (FSDataInputStream in = dfs.open(p)) {
        in.readFully(read);
      }
      assertArrayEquals(data, read);
    } finally {
      ec.shutdown();
    }
  }
}
