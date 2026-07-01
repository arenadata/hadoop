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

import java.io.IOException;
import java.nio.ByteBuffer;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.classification.InterfaceStability;

/**
 * Implementers of this interface provide a write API that accepts a
 * {@link ByteBuffer}. This is the write-side analog of
 * {@link ByteBufferReadable}: when the buffer is a direct {@link ByteBuffer},
 * native callers (e.g. libhdfs) can hand the bytes to the stream without first
 * copying them onto the Java heap.
 *
 * A stream advertises support through {@link StreamCapabilities} with the
 * {@link StreamCapabilities#WRITEBYTEBUFFER} capability.
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public interface ByteBufferWritable {
  /**
   * Writes all of the remaining bytes of the given buffer
   * ({@code buf.remaining()} bytes starting at {@code buf.position()}),
   * advancing the buffer's position to its limit.
   *
   * Like {@link FSDataOutputStream}, implementations are expected to consume
   * the whole buffer and never do partial writes.
   *
   * @param buf the buffer whose remaining bytes are written.
   * @throws IOException if there is an error writing the data.
   */
  void write(ByteBuffer buf) throws IOException;
}
