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
package org.apache.hadoop.hdfs.protocol.datatransfer.sasl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.EnumSet;

import org.apache.hadoop.hdfs.security.token.block.BlockTokenIdentifier;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.token.Token;
import org.junit.Test;

/**
 * Tests extraction of the block pool ID from a block access token. Extraction
 * must not depend on ServiceLoader visibility over the thread context class
 * loader.
 */
public class TestSaslDataTransferClientBlockPool {

  private static final String BLOCK_POOL_ID =
      "BP-1580553963-10.92.40.94-1787133351684";

  private static Token<BlockTokenIdentifier> newBlockToken(boolean useProto) {
    BlockTokenIdentifier identifier = new BlockTokenIdentifier("testuser",
        BLOCK_POOL_ID, 1073742085L,
        EnumSet.of(BlockTokenIdentifier.AccessMode.READ), null, null, useProto);
    return new Token<>(identifier.getBytes(), new byte[0],
        identifier.getKind(), new Text(""));
  }

  @Test
  public void testGetBlockPoolIdFromLegacyToken() {
    assertEquals(BLOCK_POOL_ID,
        SaslDataTransferClient.getBlockPoolIdFromToken(newBlockToken(false)));
  }

  @Test
  public void testGetBlockPoolIdFromProtobufToken() {
    assertEquals(BLOCK_POOL_ID,
        SaslDataTransferClient.getBlockPoolIdFromToken(newBlockToken(true)));
  }

  @Test
  public void testGetBlockPoolIdFromTokenWithoutServiceLoaderVisibility()
      throws Exception {
    Thread thread = Thread.currentThread();
    ClassLoader original = thread.getContextClassLoader();
    thread.setContextClassLoader(
        new URLClassLoader(new URL[0], ClassLoader.getPlatformClassLoader()));
    try {
      assertEquals(BLOCK_POOL_ID,
          SaslDataTransferClient.getBlockPoolIdFromToken(newBlockToken(false)));
      assertEquals(BLOCK_POOL_ID,
          SaslDataTransferClient.getBlockPoolIdFromToken(newBlockToken(true)));
    } finally {
      thread.setContextClassLoader(original);
    }
  }

  @Test
  public void testGetBlockPoolIdFromNullOrEmptyToken() {
    assertNull(SaslDataTransferClient.getBlockPoolIdFromToken(null));
    assertNull(SaslDataTransferClient.getBlockPoolIdFromToken(
        new Token<>(new byte[0], new byte[0],
            new BlockTokenIdentifier().getKind(), new Text(""))));
  }
}
