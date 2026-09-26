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
package org.apache.hadoop.ha;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.apache.curator.test.InstanceSpec;
import org.apache.curator.test.TestingServer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.RawLocalFileSystem;
import org.apache.hadoop.ha.HAServiceProtocol.HAServiceState;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.hadoop.test.GenericTestUtils;
import org.apache.hadoop.util.curator.TestSecureZKCuratorManager;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Test the ZK failover controller over an SSL/TLS ZooKeeper connection.
 */
public class TestSecureZKFailoverController {
  private static final String TEST_DATA_PATH =
      "src/test/java/org/apache/hadoop/util/curator/resources/data";

  private TestingServer server;
  private Configuration conf;

  @Before
  public void setup() throws Exception {
    conf = TestSecureZKCuratorManager.setUpSecureConfig(new Configuration(), TEST_DATA_PATH);
    int securePort = InstanceSpec.getRandomPort();
    Map<String, Object> serverConf = new HashMap<>();
    serverConf.put("secureClientPort", String.valueOf(securePort));
    serverConf.put("ssl.keyStore.location",
        new File(TEST_DATA_PATH, "ssl/keystore.jks").getAbsolutePath());
    serverConf.put("ssl.keyStore.password", "password");
    serverConf.put("ssl.trustStore.location",
        new File(TEST_DATA_PATH, "ssl/truststore.jks").getAbsolutePath());
    serverConf.put("ssl.trustStore.password", "password");
    serverConf.put("ssl.hostnameVerification", "false");
    InstanceSpec spec = new InstanceSpec(GenericTestUtils.getRandomizedTestDir(), 0, -1, -1,
        true, 1, 100, 10, serverConf);
    server = new TestingServer(spec, true);
    conf.set(ZKFailoverController.ZK_QUORUM_KEY, spec.getHostname() + ":" + securePort);
  }

  @After
  public void teardown() throws Exception {
    if (server != null) {
      server.close();
    }
  }

  /**
   * HDFS is not running when the ZKFC starts, so credential providers stored
   * in HDFS must not be used to resolve the ZooKeeper SSL passwords.
   */
  @Test(timeout = 60000)
  public void testFormatZKWithHdfsCredentialProvider() throws Exception {
    conf.setClass("fs.hdfs.impl", UnavailableFileSystem.class, FileSystem.class);
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH, "jceks://hdfs@nn/zkfc.jceks");
    DummyHAService svc = new DummyHAService(HAServiceState.STANDBY, new InetSocketAddress(0));
    ZKFailoverController zkfc = new SslZKFC(conf, svc);
    assertEquals(0, zkfc.run(new String[] {"-formatZK", "-nonInteractive"}));
  }

  private static class SslZKFC extends MiniZKFCCluster.DummyZKFC {
    SslZKFC(Configuration conf, DummyHAService localTarget) {
      super(conf, localTarget);
    }

    @Override
    protected boolean isSSLEnabled() {
      return true;
    }
  }

  /** A file system that cannot be reached, like HDFS before a NameNode is active. */
  public static class UnavailableFileSystem extends RawLocalFileSystem {
    @Override
    public void initialize(URI uri, Configuration conf) throws IOException {
      throw new IOException("HDFS is not available");
    }
  }
}
