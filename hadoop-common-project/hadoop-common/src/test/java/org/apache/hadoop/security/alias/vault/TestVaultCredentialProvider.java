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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.hadoop.security.alias.CredentialProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link VaultCredentialProvider} using mocked VaultHttpClient.
 */
public class TestVaultCredentialProvider {

  private static final String TEST_URI =
      "vault://https@vault.example.com:8200/secret/hadoop/creds";
  private VaultHttpClient mockClient;
  private VaultConnectionInfo connInfo;
  private VaultCredentialProvider provider;

  @Before
  public void setUp() throws Exception {
    VaultCredentialProvider.clearCaches();
    URI uri = new URI(TEST_URI);
    connInfo = new VaultConnectionInfo(uri);
    mockClient = mock(VaultHttpClient.class);
    provider = new VaultCredentialProvider(uri, connInfo, mockClient);
  }

  @After
  public void tearDown() {
    VaultCredentialProvider.clearCaches();
  }

  @Test
  public void testGetCredentialEntry() throws Exception {
    when(mockClient.readSecret("secret/data/hadoop/creds/db.password", "value"))
        .thenReturn("p@ssw0rd");

    CredentialProvider.CredentialEntry entry =
        provider.getCredentialEntry("db.password");

    assertNotNull(entry);
    assertEquals("db.password", entry.getAlias());
    assertArrayEquals("p@ssw0rd".toCharArray(), entry.getCredential());
  }

  @Test
  public void testGetCredentialEntryNotFound() throws Exception {
    when(mockClient.readSecret("secret/data/hadoop/creds/missing", "value"))
        .thenReturn(null);

    CredentialProvider.CredentialEntry entry =
        provider.getCredentialEntry("missing");

    assertNull(entry);
  }

  @Test
  public void testGetCredentialEntryNullAlias() throws Exception {
    assertNull(provider.getCredentialEntry(null));
  }

  @Test
  public void testGetCredentialEntryEmptyAlias() throws Exception {
    assertNull(provider.getCredentialEntry(""));
  }

  @Test
  public void testGetAliases() throws Exception {
    when(mockClient.listSecrets("secret/metadata/hadoop/creds"))
        .thenReturn(Arrays.asList("key1", "key2", "key3"));

    List<String> aliases = provider.getAliases();

    assertEquals(3, aliases.size());
    assertTrue(aliases.contains("key1"));
    assertTrue(aliases.contains("key2"));
    assertTrue(aliases.contains("key3"));
  }

  @Test
  public void testGetAliasesEmpty() throws Exception {
    when(mockClient.listSecrets("secret/metadata/hadoop/creds"))
        .thenReturn(Collections.emptyList());

    List<String> aliases = provider.getAliases();

    assertTrue(aliases.isEmpty());
  }

  @Test
  public void testCreateCredentialEntry() throws Exception {
    when(mockClient.readSecret("secret/data/hadoop/creds/new.key", "value"))
        .thenReturn(null);
    doNothing().when(mockClient)
        .writeSecret("secret/data/hadoop/creds/new.key", "value", "secret_value");

    char[] credential = "secret_value".toCharArray();
    CredentialProvider.CredentialEntry entry =
        provider.createCredentialEntry("new.key", credential);

    assertNotNull(entry);
    assertEquals("new.key", entry.getAlias());
    assertArrayEquals(credential, entry.getCredential());
    verify(mockClient).writeSecret(
        "secret/data/hadoop/creds/new.key", "value", "secret_value");
  }

  @Test
  public void testCreateCredentialEntryAlreadyExists() throws Exception {
    when(mockClient.readSecret("secret/data/hadoop/creds/existing", "value"))
        .thenReturn("old_value");

    try {
      provider.createCredentialEntry("existing", "new_value".toCharArray());
      fail("should throw");
    } catch (IOException e) {
      assertEquals("Credential existing already exists in " + TEST_URI,
          e.getMessage());
    }
  }

  @Test
  public void testCreateCredentialEntryNullAlias() throws Exception {
    try {
      provider.createCredentialEntry(null, "value".toCharArray());
      fail("should throw");
    } catch (IOException e) {
      assertTrue(e.getMessage().contains("must not be null or empty"));
    }
  }

  @Test
  public void testCreateCredentialEntryEmptyAlias() throws Exception {
    try {
      provider.createCredentialEntry("", "value".toCharArray());
      fail("should throw");
    } catch (IOException e) {
      assertTrue(e.getMessage().contains("must not be null or empty"));
    }
  }

  @Test
  public void testDeleteCredentialEntry() throws Exception {
    when(mockClient.readSecret("secret/data/hadoop/creds/to.delete", "value"))
        .thenReturn("some_value");
    doNothing().when(mockClient)
        .deleteSecret("secret/metadata/hadoop/creds/to.delete");

    provider.deleteCredentialEntry("to.delete");

    verify(mockClient).deleteSecret("secret/metadata/hadoop/creds/to.delete");
  }

  @Test
  public void testDeleteCredentialEntryDoesNotExist() throws Exception {
    when(mockClient.readSecret("secret/data/hadoop/creds/nonexistent", "value"))
        .thenReturn(null);

    try {
      provider.deleteCredentialEntry("nonexistent");
      fail("should throw");
    } catch (IOException e) {
      assertEquals("Credential nonexistent does not exist in " + TEST_URI,
          e.getMessage());
    }
  }

  @Test
  public void testDeleteCredentialEntryNullAlias() throws Exception {
    try {
      provider.deleteCredentialEntry(null);
      fail("should throw");
    } catch (IOException e) {
      assertTrue(e.getMessage().contains("must not be null or empty"));
    }
  }

  @Test
  public void testIsNotTransient() {
    assertFalse(provider.isTransient());
  }

  @Test
  public void testFlushIsNoOp() throws Exception {
    provider.flush();
    // Should not throw
  }

  @Test
  public void testToString() {
    assertEquals(TEST_URI, provider.toString());
  }

  // --- Credential cache tests ---

  @Test
  public void testCacheHit() throws Exception {
    URI uri = new URI(TEST_URI);
    VaultCredentialProvider cached = new VaultCredentialProvider(
        uri, connInfo, mockClient, true, 60000);

    when(mockClient.readSecret("secret/data/hadoop/creds/cached.key", "value"))
        .thenReturn("cached_value");

    // First call - fetches from Vault
    CredentialProvider.CredentialEntry entry1 =
        cached.getCredentialEntry("cached.key");
    assertNotNull(entry1);
    assertEquals("cached_value",
        new String(entry1.getCredential()));

    // Second call - should be from cache, no extra HTTP call
    CredentialProvider.CredentialEntry entry2 =
        cached.getCredentialEntry("cached.key");
    assertNotNull(entry2);
    assertEquals("cached_value",
        new String(entry2.getCredential()));

    verify(mockClient, times(1))
        .readSecret("secret/data/hadoop/creds/cached.key", "value");
  }

  @Test
  public void testCacheExpiry() throws Exception {
    URI uri = new URI(TEST_URI);
    // TTL = 1ms
    VaultCredentialProvider cached = new VaultCredentialProvider(
        uri, connInfo, mockClient, true, 1);

    when(mockClient.readSecret("secret/data/hadoop/creds/expiring.key", "value"))
        .thenReturn("value1")
        .thenReturn("value2");

    cached.getCredentialEntry("expiring.key");

    // Wait for cache to expire
    Thread.sleep(10);

    CredentialProvider.CredentialEntry entry2 =
        cached.getCredentialEntry("expiring.key");
    assertNotNull(entry2);
    assertEquals("value2",
        new String(entry2.getCredential()));

    verify(mockClient, times(2))
        .readSecret("secret/data/hadoop/creds/expiring.key", "value");
  }

  @Test
  public void testCacheInvalidatedOnDelete() throws Exception {
    URI uri = new URI(TEST_URI);
    VaultCredentialProvider cached = new VaultCredentialProvider(
        uri, connInfo, mockClient, true, 60000);

    when(mockClient.readSecret("secret/data/hadoop/creds/del.key", "value"))
        .thenReturn("value1")
        .thenReturn(null);
    doNothing().when(mockClient)
        .deleteSecret("secret/metadata/hadoop/creds/del.key");

    // Populate cache
    cached.getCredentialEntry("del.key");
    // Delete: existence check is a cache hit, then invalidates cache
    cached.deleteCredentialEntry("del.key");
    // Next read should go to Vault (cache was cleared by delete)
    assertNull(cached.getCredentialEntry("del.key"));

    // 2 calls: initial read + post-delete read
    // (existence check in delete is served from cache)
    verify(mockClient, times(2))
        .readSecret("secret/data/hadoop/creds/del.key", "value");
  }

  @Test
  public void testCacheUpdatedOnCreate() throws Exception {
    URI uri = new URI(TEST_URI);
    VaultCredentialProvider cached = new VaultCredentialProvider(
        uri, connInfo, mockClient, true, 60000);

    when(mockClient.readSecret("secret/data/hadoop/creds/new.cached", "value"))
        .thenReturn(null);
    doNothing().when(mockClient)
        .writeSecret("secret/data/hadoop/creds/new.cached", "value", "new_val");

    // Create populates cache
    cached.createCredentialEntry("new.cached", "new_val".toCharArray());

    // Subsequent read should come from cache
    CredentialProvider.CredentialEntry entry =
        cached.getCredentialEntry("new.cached");
    assertNotNull(entry);
    assertEquals("new_val", new String(entry.getCredential()));

    // Only 1 readSecret call (the existence check in create),
    // the get after create should be cached
    verify(mockClient, times(1))
        .readSecret("secret/data/hadoop/creds/new.cached", "value");
  }

  @Test
  public void testCacheDisabled() throws Exception {
    // provider (from setUp) has cache disabled
    when(mockClient.readSecret("secret/data/hadoop/creds/no.cache", "value"))
        .thenReturn("val");

    provider.getCredentialEntry("no.cache");
    provider.getCredentialEntry("no.cache");

    verify(mockClient, times(2))
        .readSecret("secret/data/hadoop/creds/no.cache", "value");
  }

  // --- Custom secret key tests ---

  @Test
  public void testCustomSecretKeyRead() throws Exception {
    URI uri = new URI(
        "vault://https@vault.example.com:8200/secret/hadoop/creds?key=password");
    VaultConnectionInfo customConnInfo = new VaultConnectionInfo(uri);
    VaultCredentialProvider customProvider =
        new VaultCredentialProvider(uri, customConnInfo, mockClient);

    when(mockClient.readSecret(
        "secret/data/hadoop/creds/db.password", "password"))
        .thenReturn("s3cret");

    CredentialProvider.CredentialEntry entry =
        customProvider.getCredentialEntry("db.password");

    assertNotNull(entry);
    assertArrayEquals("s3cret".toCharArray(), entry.getCredential());
    verify(mockClient).readSecret(
        "secret/data/hadoop/creds/db.password", "password");
  }

  @Test
  public void testCustomSecretKeyWrite() throws Exception {
    URI uri = new URI(
        "vault://https@vault.example.com:8200/secret/hadoop/creds?key=password");
    VaultConnectionInfo customConnInfo = new VaultConnectionInfo(uri);
    VaultCredentialProvider customProvider =
        new VaultCredentialProvider(uri, customConnInfo, mockClient);

    when(mockClient.readSecret(
        "secret/data/hadoop/creds/new.key", "password"))
        .thenReturn(null);

    customProvider.createCredentialEntry(
        "new.key", "new_val".toCharArray());

    verify(mockClient).writeSecret(
        "secret/data/hadoop/creds/new.key", "password", "new_val");
  }
}
