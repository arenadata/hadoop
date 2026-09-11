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

package org.apache.hadoop.security.alias.vault;

import java.io.IOException;
import java.net.URI;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Tests for {@link VaultConnectionInfo}.
 */
public class TestVaultConnectionInfo {

  @Test
  public void testFullUri() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/secret/hadoop/creds");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("https", info.getProtocol());
    assertEquals("vault.example.com", info.getHost());
    assertEquals(8200, info.getPort());
    assertEquals("secret", info.getMount());
    assertEquals("hadoop/creds", info.getBasePath());
    assertEquals("https://vault.example.com:8200", info.getBaseUrl());
  }

  @Test
  public void testHttpProtocol() throws Exception {
    URI uri = new URI("vault://http@vault.internal:8200/secret/data-platform");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("http", info.getProtocol());
    assertEquals("vault.internal", info.getHost());
    assertEquals(8200, info.getPort());
    assertEquals("secret", info.getMount());
    assertEquals("data-platform", info.getBasePath());
    assertEquals("http://vault.internal:8200", info.getBaseUrl());
  }

  @Test
  public void testDefaultProtocol() throws Exception {
    URI uri = new URI("vault://vault.example.com:8200/secret/hadoop");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("vault.example.com", info.getHost());
    assertEquals(8200, info.getPort());
    assertEquals("secret", info.getMount());
    assertEquals("hadoop", info.getBasePath());
  }

  @Test
  public void testDefaultPort() throws Exception {
    URI uri = new URI("vault://https@vault.example.com/secret/hadoop");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("https", info.getProtocol());
    assertEquals("vault.example.com", info.getHost());
    assertEquals(VaultConnectionInfo.DEFAULT_PORT, info.getPort());
    assertEquals("secret", info.getMount());
  }

  @Test
  public void testMountOnly() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/secret");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("secret", info.getMount());
    assertNull(info.getBasePath());
  }

  @Test
  public void testBuildDataPath() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/secret/hadoop/creds");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("secret/data/hadoop/creds/db.password",
        info.buildDataPath("db.password"));
  }

  @Test
  public void testBuildDataPathMountOnly() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/secret");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("secret/data/db.password",
        info.buildDataPath("db.password"));
  }

  @Test
  public void testBuildMetadataPath() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/secret/hadoop/creds");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("secret/metadata/hadoop/creds",
        info.buildMetadataPath());
  }

  @Test
  public void testBuildMetadataPathWithAlias() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/secret/hadoop/creds");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("secret/metadata/hadoop/creds/db.password",
        info.buildMetadataPath("db.password"));
  }

  @Test
  public void testBuildMetadataPathMountOnly() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/secret");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("secret/metadata",
        info.buildMetadataPath());
  }

  @Test(expected = IOException.class)
  public void testInvalidUriNoPath() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200");
    new VaultConnectionInfo(uri);
  }

  @Test(expected = IOException.class)
  public void testInvalidUriEmptyPath() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/");
    new VaultConnectionInfo(uri);
  }

  @Test
  public void testSpecialCharactersInAlias() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/secret/hadoop");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("secret/data/hadoop/my.special-key_1",
        info.buildDataPath("my.special-key_1"));
  }

  @Test
  public void testTrailingSlashInPath() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/secret/hadoop/");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("secret", info.getMount());
    assertEquals("hadoop", info.getBasePath());
  }

  @Test
  public void testDefaultSecretKey() throws Exception {
    URI uri = new URI("vault://https@vault.example.com:8200/secret/hadoop");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("value", info.getSecretKey());
  }

  @Test
  public void testCustomSecretKey() throws Exception {
    URI uri = new URI(
        "vault://https@vault.example.com:8200/secret/hadoop?key=password");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("password", info.getSecretKey());
    assertEquals("secret", info.getMount());
    assertEquals("hadoop", info.getBasePath());
  }

  @Test
  public void testEmptyKeyDefaultsToValue() throws Exception {
    URI uri = new URI(
        "vault://https@vault.example.com:8200/secret/hadoop?key=");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("value", info.getSecretKey());
  }

  @Test
  public void testKeyWithOtherParams() throws Exception {
    URI uri = new URI(
        "vault://https@vault.example.com:8200/secret/hadoop?foo=bar&key=secret");
    VaultConnectionInfo info = new VaultConnectionInfo(uri);

    assertEquals("secret", info.getSecretKey());
  }

  @Test
  public void testGetApiUrl() throws Exception {
    VaultConnectionInfo info = new VaultConnectionInfo(
        new URI("vault://https@vault.example.com:8200/secret/hadoop"));
    assertEquals("https://vault.example.com:8200/v1/secret/data/hadoop/x",
        info.getApiUrl(info.buildDataPath("x")));
  }

  @Test
  public void testSurroundingSlashesInPath() throws Exception {
    VaultConnectionInfo info = new VaultConnectionInfo(
        new URI("vault://https@vault.example.com:8200//secret/hadoop//"));
    assertEquals("secret", info.getMount());
    assertEquals("hadoop", info.getBasePath());
  }
}
