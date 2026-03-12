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
package org.apache.hadoop.hdfs.server.federation.router;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.List;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hdfs.DFSConfigKeys;
import org.apache.hadoop.hdfs.protocol.ClientProtocol;
import org.apache.hadoop.hdfs.security.token.block.DataEncryptionKey;
import org.apache.hadoop.hdfs.server.federation.MiniRouterDFSCluster;
import org.apache.hadoop.hdfs.server.federation.MiniRouterDFSCluster.RouterContext;
import org.apache.hadoop.hdfs.server.federation.RouterConfigBuilder;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests that {@link RouterClientProtocol#getDataEncryptionKey(String)}
 * correctly routes to different namespaces based on the block pool ID.
 * This is critical for federated setups with data transfer encryption
 * where each namespace has its own encryption keys.
 */
public class TestRouterDataEncryptionKey {

  private static MiniRouterDFSCluster cluster;
  private static RouterContext router;
  private static ClientProtocol routerProtocol;
  private static String bpId0;
  private static String bpId1;

  @BeforeClass
  public static void setUp() throws Exception {
    Configuration namenodeConf = new Configuration();
    namenodeConf.setBoolean(
        DFSConfigKeys.DFS_BLOCK_ACCESS_TOKEN_ENABLE_KEY, true);
    namenodeConf.setBoolean(
        DFSConfigKeys.DFS_ENCRYPT_DATA_TRANSFER_KEY, true);

    cluster = new MiniRouterDFSCluster(false, 2);
    cluster.addNamenodeOverrides(namenodeConf);
    cluster.startCluster();

    Configuration routerConf = new RouterConfigBuilder()
        .rpc()
        .build();
    cluster.addRouterOverrides(routerConf);
    cluster.startRouters();

    cluster.registerNamenodes();
    cluster.waitNamenodeRegistration();
    cluster.installMockLocations();

    router = cluster.getRandomRouter();
    routerProtocol = router.getClient().getNamenode();

    List<String> nss = cluster.getNameservices();
    bpId0 = cluster.getNamenode(nss.get(0), null).getNamenode()
        .getNamesystem().getBlockPoolId();
    bpId1 = cluster.getNamenode(nss.get(1), null).getNamenode()
        .getNamesystem().getBlockPoolId();
  }

  @AfterClass
  public static void tearDown() {
    if (cluster != null) {
      cluster.shutdown();
    }
  }

  @Test
  public void testBlockPoolIdsAreDifferent() {
    assertNotEquals(
        "Block pool IDs should differ between namespaces", bpId0, bpId1);
  }

  @Test
  public void testRoutesByBlockPoolId() throws IOException {
    DataEncryptionKey key0 = routerProtocol.getDataEncryptionKey(bpId0);
    assertNotNull("Encryption key for ns0 should not be null", key0);
    assertEquals("Key should match ns0 block pool", bpId0, key0.blockPoolId);

    DataEncryptionKey key1 = routerProtocol.getDataEncryptionKey(bpId1);
    assertNotNull("Encryption key for ns1 should not be null", key1);
    assertEquals("Key should match ns1 block pool", bpId1, key1.blockPoolId);

    assertNotEquals("Keys must be from different block pools",
        key0.blockPoolId, key1.blockPoolId);
  }

  @Test
  public void testFallsBackToDefaultWithoutBlockPoolId() throws IOException {
    DataEncryptionKey keyDefault = routerProtocol.getDataEncryptionKey(null);
    assertNotNull("Default encryption key should not be null", keyDefault);
    assertNotNull("Default key block pool should not be null",
        keyDefault.blockPoolId);
  }

  @Test
  public void testNoArgFallsBackToDefault() throws IOException {
    DataEncryptionKey keyDefault = routerProtocol.getDataEncryptionKey();
    assertNotNull("Default encryption key should not be null", keyDefault);
    assertNotNull("Default key block pool should not be null",
        keyDefault.blockPoolId);
  }

  @Test(expected = IOException.class)
  public void testInvalidBlockPoolId() throws IOException {
    routerProtocol.getDataEncryptionKey("BP-invalid-0.0.0.0-0");
  }
}
