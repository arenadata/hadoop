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

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;
import org.apache.hadoop.util.DataChecksum;
import org.apache.hadoop.tracing.TraceScope;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.zip.Checksum;

/**
 * This is a generic output stream for generating checksums for
 * data before it is written to the underlying stream
 */
@InterfaceAudience.LimitedPrivate({"HDFS"})
@InterfaceStability.Unstable
abstract public class FSOutputSummer extends OutputStream implements
    StreamCapabilities, ByteBufferWritable {
  // data checksum
  private final DataChecksum sum;
  // internal buffer for storing data before it is checksumed
  private byte buf[];
  // internal buffer for storing checksum
  private byte checksum[];
  // The number of valid bytes in the buffer.
  private int count;
  // direct scratch buffer for checksums computed straight off a direct
  // ByteBuffer (NativeCrc32 requires direct buffers); allocated lazily.
  private ByteBuffer directChecksumBuf;
  
  // We want this value to be a multiple of 3 because the native code checksums
  // 3 chunks simultaneously. The chosen value of 9 strikes a balance between
  // limiting the number of JNI calls and flushing to the underlying stream
  // relatively frequently.
  private static final int BUFFER_NUM_CHUNKS = 9;
  
  protected FSOutputSummer(DataChecksum sum) {
    this.sum = sum;
    this.buf = new byte[sum.getBytesPerChecksum() * BUFFER_NUM_CHUNKS];
    this.checksum = new byte[getChecksumSize() * BUFFER_NUM_CHUNKS];
    this.count = 0;
  }
  
  /* write the data chunk in <code>b</code> staring at <code>offset</code> with
   * a length of <code>len > 0</code>, and its checksum
   */
  protected abstract void writeChunk(byte[] b, int bOffset, int bLen,
      byte[] checksum, int checksumOffset, int checksumLen) throws IOException;

  /**
   * Write a single chunk of data straight from a {@link ByteBuffer} (advancing
   * its position by <code>len</code>) together with its precomputed checksum.
   * The default implementation copies the chunk into a temporary array and
   * delegates to {@link #writeChunk(byte[], int, int, byte[], int, int)};
   * subclasses that can consume a ByteBuffer directly (e.g. DFSOutputStream)
   * override this to avoid the copy.
   */
  protected void writeChunk(ByteBuffer b, int len, byte[] checksum,
      int checksumOffset, int checksumLen) throws IOException {
    byte[] tmp = new byte[len];
    b.get(tmp, 0, len);
    writeChunk(tmp, 0, len, checksum, checksumOffset, checksumLen);
  }
  
  /**
   * Check if the implementing OutputStream is closed and should no longer
   * accept writes. Implementations should do nothing if this stream is not
   * closed, and should throw an {@link IOException} if it is closed.
   * 
   * @throws IOException if this stream is already closed.
   */
  protected abstract void checkClosed() throws IOException;

  /** Write one byte */
  @Override
  public synchronized void write(int b) throws IOException {
    buf[count++] = (byte)b;
    if(count == buf.length) {
      flushBuffer();
    }
  }

  /**
   * Writes <code>len</code> bytes from the specified byte array 
   * starting at offset <code>off</code> and generate a checksum for
   * each data chunk.
   *
   * <p> This method stores bytes from the given array into this
   * stream's buffer before it gets checksumed. The buffer gets checksumed 
   * and flushed to the underlying output stream when all data 
   * in a checksum chunk are in the buffer.  If the buffer is empty and
   * requested length is at least as large as the size of next checksum chunk
   * size, this method will checksum and write the chunk directly 
   * to the underlying output stream.  Thus it avoids unnecessary data copy.
   *
   * @param      b     the data.
   * @param      off   the start offset in the data.
   * @param      len   the number of bytes to write.
   * @exception  IOException  if an I/O error occurs.
   */
  @Override
  public synchronized void write(byte b[], int off, int len)
      throws IOException {
    
    checkClosed();
    
    if (off < 0 || len < 0 || off > b.length - len) {
      throw new ArrayIndexOutOfBoundsException();
    }

    for (int n=0;n<len;n+=write1(b, off+n, len-n)) {
    }
  }
  
  /**
   * Write a portion of an array, flushing to the underlying
   * stream at most once if necessary.
   */
  private int write1(byte b[], int off, int len) throws IOException {
    if(count==0 && len>=buf.length) {
      // local buffer is empty and user buffer size >= local buffer size, so
      // simply checksum the user buffer and send it directly to the underlying
      // stream
      final int length = buf.length;
      writeChecksumChunks(b, off, length);
      return length;
    }
    
    // copy user data to local buffer
    int bytesToCopy = buf.length-count;
    bytesToCopy = (len<bytesToCopy) ? len : bytesToCopy;
    System.arraycopy(b, off, buf, count, bytesToCopy);
    count += bytesToCopy;
    if (count == buf.length) {
      // local buffer is full
      flushBuffer();
    }
    return bytesToCopy;
  }

  /**
   * Writes the remaining bytes of the given buffer, generating a checksum for
   * each chunk. When the buffer is a direct {@link ByteBuffer} and the stream
   * advertises {@link StreamCapabilities#WRITEBYTEBUFFER}, full chunks are
   * checksummed straight off the buffer and handed to
   * {@link #writeChunk(ByteBuffer, int, byte[], int, int)} without an
   * intermediate copy onto the Java heap. Otherwise the bytes are drained
   * through the regular {@code byte[]} path.
   */
  @Override
  public synchronized void write(ByteBuffer buf) throws IOException {
    checkClosed();
    if (!buf.isDirect()
        || !hasCapability(StreamCapabilities.WRITEBYTEBUFFER)) {
      writeByteBufferViaArray(buf);
      return;
    }
    while (buf.hasRemaining()) {
      write1(buf);
    }
  }

  /**
   * Drains the remaining bytes of the buffer through {@link #write(byte[], int,
   * int)} and advances the buffer's position to its limit.
   */
  private void writeByteBufferViaArray(ByteBuffer src) throws IOException {
    final int len = src.remaining();
    if (src.hasArray()) {
      write(src.array(), src.arrayOffset() + src.position(), len);
      src.position(src.limit());
    } else {
      byte[] tmp = new byte[len];
      src.get(tmp);
      write(tmp, 0, tmp.length);
    }
  }

  /**
   * Write a portion of a direct ByteBuffer, flushing to the underlying stream
   * at most once if necessary. Mirrors {@link #write1(byte[], int, int)}.
   */
  private int write1(ByteBuffer src) throws IOException {
    final int remaining = src.remaining();
    if (count == 0 && remaining >= buf.length) {
      // local buffer is empty and the source holds at least a full local
      // buffer, so checksum it straight off the source and send it directly to
      // the underlying stream, avoiding a copy into buf.
      final int length = buf.length;
      writeChecksumChunks(src, length);
      return length;
    }

    // copy user data into local buffer
    int bytesToCopy = buf.length - count;
    bytesToCopy = Math.min(remaining, bytesToCopy);
    src.get(buf, count, bytesToCopy);
    count += bytesToCopy;
    if (count == buf.length) {
      // local buffer is full
      flushBuffer();
    }
    return bytesToCopy;
  }

  /* Forces any buffered output bytes to be checksumed and written out to
   * the underlying output stream.
   */
  protected synchronized void flushBuffer() throws IOException {
    flushBuffer(false, true);
  }

  /* Forces buffered output bytes to be checksummed and written out to
   * the underlying output stream. If there is a trailing partial chunk in the
   * buffer,
   * 1) flushPartial tells us whether to flush that chunk
   * 2) if flushPartial is true, keep tells us whether to keep that chunk in the
   * buffer (if flushPartial is false, it is always kept in the buffer)
   *
   * Returns the number of bytes that were flushed but are still left in the
   * buffer (can only be non-zero if keep is true).
   */
  protected synchronized int flushBuffer(boolean keep,
      boolean flushPartial) throws IOException {
    int bufLen = count;
    int partialLen = bufLen % sum.getBytesPerChecksum();
    int lenToFlush = flushPartial ? bufLen : bufLen - partialLen;
    if (lenToFlush != 0) {
      writeChecksumChunks(buf, 0, lenToFlush);
      if (!flushPartial || keep) {
        count = partialLen;
        System.arraycopy(buf, bufLen - count, buf, 0, count);
      } else {
        count = 0;
      }
    }

    // total bytes left minus unflushed bytes left
    return count - (bufLen - lenToFlush);
  }

  /**
   * Checksums all complete data chunks and flushes them to the underlying
   * stream. If there is a trailing partial chunk, it is not flushed and is
   * maintained in the buffer.
   */
  public void flush() throws IOException {
    flushBuffer(false, false);
  }

  /**
   * Return the number of valid bytes currently in the buffer.
   *
   * @return buffer data size.
   */
  protected synchronized int getBufferedDataSize() {
    return count;
  }

  /** @return the size for a checksum. */
  protected int getChecksumSize() {
    return sum.getChecksumSize();
  }

  protected DataChecksum getDataChecksum() {
    return sum;
  }

  protected TraceScope createWriteTraceScope() {
    return null;
  }

  /** Generate checksums for the given data chunks and output chunks & checksums
   * to the underlying output stream.
   */
  private void writeChecksumChunks(byte b[], int off, int len)
  throws IOException {
    sum.calculateChunkedSums(b, off, len, checksum, 0);
    TraceScope scope = createWriteTraceScope();
    try {
      for (int i = 0; i < len; i += sum.getBytesPerChecksum()) {
        int chunkLen = Math.min(sum.getBytesPerChecksum(), len - i);
        int ckOffset = i / sum.getBytesPerChecksum() * getChecksumSize();
        writeChunk(b, off + i, chunkLen, checksum, ckOffset,
            getChecksumSize());
      }
    } finally {
      if (scope != null) {
        scope.close();
      }
    }
  }

  /**
   * Generate checksums for <code>len</code> bytes (a multiple of the chunk
   * size) read straight from <code>src</code> and output the chunks &amp; their
   * checksums to the underlying stream, advancing <code>src</code> by
   * <code>len</code>. The checksums are computed directly off the (direct)
   * source buffer; no copy of the data is made onto the Java heap.
   */
  private void writeChecksumChunks(ByteBuffer src, int len)
  throws IOException {
    final int bytesPerChecksum = sum.getBytesPerChecksum();
    final int checksumSize = getChecksumSize();
    final int numChunks = (len + bytesPerChecksum - 1) / bytesPerChecksum;
    final int ckLen = numChunks * checksumSize;

    // NativeCrc32 needs direct buffers for both data and checksums, so compute
    // into a direct scratch buffer and copy the (tiny) checksums into the heap
    // checksum array that writeChunk expects.
    if (directChecksumBuf == null || directChecksumBuf.capacity() < ckLen) {
      directChecksumBuf = ByteBuffer.allocateDirect(checksum.length);
    }
    directChecksumBuf.clear().limit(ckLen);
    ByteBuffer data = src.duplicate();
    data.limit(data.position() + len);
    sum.calculateChunkedSums(data, directChecksumBuf);
    directChecksumBuf.position(0);
    directChecksumBuf.get(checksum, 0, ckLen);

    TraceScope scope = createWriteTraceScope();
    try {
      for (int i = 0; i < len; i += bytesPerChecksum) {
        int chunkLen = Math.min(bytesPerChecksum, len - i);
        int ckOffset = i / bytesPerChecksum * checksumSize;
        // writeChunk consumes chunkLen bytes from src, advancing its position.
        writeChunk(src, chunkLen, checksum, ckOffset, checksumSize);
      }
    } finally {
      if (scope != null) {
        scope.close();
      }
    }
  }

  /**
   * Converts a checksum integer value to a byte stream
   *
   * @param sum check sum.
   * @param checksumSize check sum size.
   * @return byte stream.
   */
  static public byte[] convertToByteStream(Checksum sum, int checksumSize) {
    return int2byte((int)sum.getValue(), new byte[checksumSize]);
  }

  static byte[] int2byte(int integer, byte[] bytes) {
    if (bytes.length != 0) {
      bytes[0] = (byte) ((integer >>> 24) & 0xFF);
      bytes[1] = (byte) ((integer >>> 16) & 0xFF);
      bytes[2] = (byte) ((integer >>> 8) & 0xFF);
      bytes[3] = (byte) ((integer >>> 0) & 0xFF);
      return bytes;
    }
    return bytes;
  }

  /**
   * Resets existing buffer with a new one of the specified size.
   *
   * @param size size.
   */
  protected synchronized void setChecksumBufSize(int size) {
    this.buf = new byte[size];
    this.checksum = new byte[sum.getChecksumSize(size)];
    this.count = 0;
  }

  protected synchronized void resetChecksumBufSize() {
    setChecksumBufSize(sum.getBytesPerChecksum() * BUFFER_NUM_CHUNKS);
  }

  @Override
  public boolean hasCapability(String capability) {
    return false;
  }
}
