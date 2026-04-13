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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.hadoop.conf.Configuration;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Tests for {@link VaultCredentialProviderConfig}, focusing on
 * systemd credential resolution.
 */
public class TestVaultCredentialProviderConfig {

  @Rule
  public TemporaryFolder tempDir = new TemporaryFolder();

  @Test
  public void testReadSystemdCredential() throws Exception {
    File credDir = tempDir.newFolder("credentials");
    File credFile = new File(credDir, "vault-token");
    writeFile(credFile, "s.systemd-token-123");

    String token = VaultCredentialProviderConfig.readSystemdCredential(
        new Configuration(), credDir.getAbsolutePath());
    assertEquals("s.systemd-token-123", token);
  }

  @Test
  public void testReadSystemdCredentialTrimsWhitespace() throws Exception {
    File credDir = tempDir.newFolder("credentials-trim");
    File credFile = new File(credDir, "vault-token");
    writeFile(credFile, "  s.token-with-spaces  \n");

    String token = VaultCredentialProviderConfig.readSystemdCredential(
        new Configuration(), credDir.getAbsolutePath());
    assertEquals("s.token-with-spaces", token);
  }

  @Test
  public void testReadSystemdCredentialCustomName() throws Exception {
    File credDir = tempDir.newFolder("credentials-custom");
    File credFile = new File(credDir, "my-vault-token");
    writeFile(credFile, "s.custom-name-token");

    Configuration conf = new Configuration();
    conf.set(VaultCredentialProviderConfig.SYSTEMD_CREDENTIAL_NAME_KEY,
        "my-vault-token");

    String token = VaultCredentialProviderConfig.readSystemdCredential(
        conf, credDir.getAbsolutePath());
    assertEquals("s.custom-name-token", token);
  }

  @Test
  public void testReadSystemdCredentialMissingFile() throws Exception {
    File credDir = tempDir.newFolder("credentials-missing");
    // Don't create the file

    String token = VaultCredentialProviderConfig.readSystemdCredential(
        new Configuration(), credDir.getAbsolutePath());
    assertNull(token);
  }

  @Test
  public void testReadSystemdCredentialEmptyFile() throws Exception {
    File credDir = tempDir.newFolder("credentials-empty");
    File credFile = new File(credDir, "vault-token");
    writeFile(credFile, "");

    String token = VaultCredentialProviderConfig.readSystemdCredential(
        new Configuration(), credDir.getAbsolutePath());
    assertNull(token);
  }

  @Test
  public void testReadSystemdCredentialNoCredentialsDirectory()
      throws Exception {
    // CREDENTIALS_DIRECTORY not set (null)
    String token = VaultCredentialProviderConfig.readSystemdCredential(
        new Configuration(), null);
    assertNull(token);
  }

  @Test
  public void testConfigTokenTakesPriority() throws Exception {
    Configuration conf = new Configuration();
    conf.set(VaultCredentialProviderConfig.TOKEN_KEY, "s.config-token");

    String token = VaultCredentialProviderConfig.resolveToken(conf);
    assertEquals("s.config-token", token);
  }

  private static void writeFile(File file, String content)
      throws IOException {
    try (FileOutputStream fos = new FileOutputStream(file)) {
      fos.write(content.getBytes(StandardCharsets.UTF_8));
    }
  }
}
