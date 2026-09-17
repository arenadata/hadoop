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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import static org.apache.hadoop.test.LambdaTestUtils.intercept;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
    when(mockClient.readSecretFields("secret/data/hadoop/creds/new.key"))
        .thenReturn(null);

    char[] credential = "secret_value".toCharArray();
    CredentialProvider.CredentialEntry entry =
        provider.createCredentialEntry("new.key", credential);

    assertNotNull(entry);
    assertEquals("new.key", entry.getAlias());
    assertArrayEquals(credential, entry.getCredential());
    verify(mockClient).writeSecret("secret/data/hadoop/creds/new.key",
        fields("value", "secret_value"), 0);
  }

  @Test
  public void testCreateCredentialEntryAlreadyExists() throws Exception {
    when(mockClient.readSecretFields("secret/data/hadoop/creds/existing"))
        .thenReturn(secret("value", "old_value"));

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
    when(mockClient.readSecretFields("secret/data/hadoop/creds/to.delete"))
        .thenReturn(secret("value", "some_value"));
    doNothing().when(mockClient)
        .deleteSecret("secret/metadata/hadoop/creds/to.delete");

    provider.deleteCredentialEntry("to.delete");

    verify(mockClient).deleteSecret("secret/metadata/hadoop/creds/to.delete");
  }

  @Test
  public void testDeleteCredentialEntryDoesNotExist() throws Exception {
    when(mockClient.readSecretFields("secret/data/hadoop/creds/nonexistent"))
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
  public void testKeytabLoginNeedsHadoopSecurity() throws Exception {
    intercept(IOException.class,
        "requires hadoop.security.authentication=kerberos",
        () -> VaultClientIdentity.loginFromKeytab("vault/h@EXAMPLE.COM",
            "/etc/security/keytabs/vault.keytab"));
  }

  @Test
  public void testIsNotTransient() {
    assertFalse(provider.isTransient());
  }

  @Test
  public void testFlushIsNoOp() throws Exception {
    provider.flush();
  }

  @Test
  public void testToString() {
    assertEquals(TEST_URI, provider.toString());
  }

  // --- Identity isolation tests ---

  @Test
  public void testCachedSecretIsNotSharedBetweenIdentities()
      throws Exception {
    VaultCredentialProvider alice = providerAs("alice");
    VaultCredentialProvider bob = providerAs("bob");
    when(mockClient.readSecret("secret/data/hadoop/creds/shared.key", "value"))
        .thenReturn("secret_value");

    assertEquals("secret_value",
        new String(alice.getCredentialEntry("shared.key").getCredential()));
    assertEquals("secret_value",
        new String(bob.getCredentialEntry("shared.key").getCredential()));

    verify(mockClient, times(2))
        .readSecret("secret/data/hadoop/creds/shared.key", "value");
  }

  @Test
  public void testDeleteDropsTheAliasForEveryIdentity() throws Exception {
    VaultCredentialProvider alice = providerAs("alice");
    VaultCredentialProvider bob = providerAs("bob");
    when(mockClient.readSecret("secret/data/hadoop/creds/gone.key", "value"))
        .thenReturn("value1")
        .thenReturn("value1")
        .thenReturn(null);
    when(mockClient.readSecretFields("secret/data/hadoop/creds/gone.key"))
        .thenReturn(secret("value", "value1"));
    doNothing().when(mockClient)
        .deleteSecret("secret/metadata/hadoop/creds/gone.key");

    alice.getCredentialEntry("gone.key");
    bob.getCredentialEntry("gone.key");
    bob.deleteCredentialEntry("gone.key");

    assertNull(alice.getCredentialEntry("gone.key"));
  }

  @Test
  public void testWriteDropsTheAliasForEveryIdentity() throws Exception {
    VaultCredentialProvider alice = providerAs("alice");
    VaultCredentialProvider bob = providerAs("bob");
    when(mockClient.readSecret("secret/data/hadoop/creds/new.key", "value"))
        .thenReturn("old")
        .thenReturn("new");
    when(mockClient.readSecretFields("secret/data/hadoop/creds/new.key"))
        .thenReturn(null);

    alice.getCredentialEntry("new.key");
    bob.createCredentialEntry("new.key", "new".toCharArray());

    assertEquals("new",
        new String(alice.getCredentialEntry("new.key").getCredential()));
  }

  @Test
  public void testDeleteInvalidatesEvenWhenTheWriterDoesNotCache()
      throws Exception {
    VaultCredentialProvider reader = providerAs("reader");
    VaultCredentialProvider writer = new VaultCredentialProvider(
        new URI(TEST_URI), connInfo, mockClient, false, 0,
        VaultClientIdentity.forTesting("writer"));
    when(mockClient.readSecret("secret/data/hadoop/creds/rot.key", "value"))
        .thenReturn("value1")
        .thenReturn(null);
    when(mockClient.readSecretFields("secret/data/hadoop/creds/rot.key"))
        .thenReturn(secret("value", "value1"));
    doNothing().when(mockClient)
        .deleteSecret("secret/metadata/hadoop/creds/rot.key");

    reader.getCredentialEntry("rot.key");
    writer.deleteCredentialEntry("rot.key");

    assertNull(reader.getCredentialEntry("rot.key"));
  }

  @Test
  public void testFailedDeleteDoesNotLeaveTheValueCached() throws Exception {
    VaultCredentialProvider alice = providerAs("alice");
    when(mockClient.readSecret("secret/data/hadoop/creds/stuck.key", "value"))
        .thenReturn("value1");
    when(mockClient.readSecretFields("secret/data/hadoop/creds/stuck.key"))
        .thenReturn(secret("value", "value1"));
    doThrow(new IOException("vault said 403")).when(mockClient)
        .deleteSecret("secret/metadata/hadoop/creds/stuck.key");

    alice.getCredentialEntry("stuck.key");
    try {
      alice.deleteCredentialEntry("stuck.key");
      fail("should throw");
    } catch (IOException e) {
      assertEquals("vault said 403", e.getMessage());
    }
    alice.getCredentialEntry("stuck.key");

    verify(mockClient, times(2))
        .readSecret("secret/data/hadoop/creds/stuck.key", "value");
  }

  @Test
  public void testFailedWriteDropsTheCachedValue() throws Exception {
    VaultCredentialProvider alice = providerAs("alice");
    VaultCredentialProvider bob = providerAs("bob");
    when(mockClient.readSecret("secret/data/hadoop/creds/half.key", "value"))
        .thenReturn("old");
    when(mockClient.readSecretFields("secret/data/hadoop/creds/half.key"))
        .thenReturn(null);
    doThrow(new IOException("vault said 403")).when(mockClient).writeSecret(
        eq("secret/data/hadoop/creds/half.key"), anyMap(), eq(0));

    alice.getCredentialEntry("half.key");
    try {
      bob.createCredentialEntry("half.key", "new".toCharArray());
      fail("should throw");
    } catch (IOException e) {
      assertEquals("vault said 403", e.getMessage());
    }

    assertEquals("old",
        new String(alice.getCredentialEntry("half.key").getCredential()));
    verify(mockClient, times(2))
        .readSecret("secret/data/hadoop/creds/half.key", "value");
  }

  @Test
  public void testWriteKeepsTheOtherFieldsOfTheSecret() throws Exception {
    when(mockClient.readSecretFields("secret/data/hadoop/creds/db"))
        .thenReturn(secret("username", "dbuser"));

    provider.createCredentialEntry("db", "p".toCharArray());

    verify(mockClient).writeSecret("secret/data/hadoop/creds/db",
        fields("username", "dbuser", "value", "p"), 1);
  }

  @Test
  public void testWriteKeepsTheTypesOfTheOtherFields() throws Exception {
    when(mockClient.readSecretFields("secret/data/hadoop/creds/db"))
        .thenReturn(secret("port", 5432, "tls", Boolean.TRUE));

    provider.createCredentialEntry("db", "p".toCharArray());

    verify(mockClient).writeSecret("secret/data/hadoop/creds/db",
        fields("port", 5432, "tls", Boolean.TRUE, "value", "p"), 1);
  }

  @Test
  public void testGetAliasesListsNestedSecrets() throws Exception {
    when(mockClient.listSecrets("secret/metadata/hadoop/creds"))
        .thenReturn(Arrays.asList("top", "dir/"));
    when(mockClient.listSecrets("secret/metadata/hadoop/creds/dir"))
        .thenReturn(Arrays.asList("deep", "deeper/"));
    when(mockClient.listSecrets("secret/metadata/hadoop/creds/dir/deeper"))
        .thenReturn(Collections.singletonList("last"));

    assertEquals(Arrays.asList("top", "dir/deep", "dir/deeper/last"),
        provider.getAliases());
  }

  @Test
  public void testAnAliasThatIsNoVaultPathIsAbsent() throws Exception {
    assertNull(provider.getCredentialEntry("a/../b"));
    assertNull(provider.getCredentialEntry("a//b"));
    verify(mockClient, never()).readSecret(anyString(), anyString());

    intercept(IOException.class, "is not a valid Vault path",
        () -> provider.createCredentialEntry("../x", "v".toCharArray()));
    intercept(IOException.class, "is not a valid Vault path",
        () -> provider.deleteCredentialEntry("."));
  }

  @Test
  public void testAMissIsCachedUntilTheAliasIsCreated() throws Exception {
    VaultCredentialProvider cached = new VaultCredentialProvider(
        new URI(TEST_URI), connInfo, mockClient, true, 60000);
    when(mockClient.readSecret("secret/data/hadoop/creds/absent", "value"))
        .thenReturn(null);
    when(mockClient.readSecretFields("secret/data/hadoop/creds/absent"))
        .thenReturn(null);

    assertNull(cached.getCredentialEntry("absent"));
    assertNull(cached.getCredentialEntry("absent"));
    verify(mockClient, times(1))
        .readSecret("secret/data/hadoop/creds/absent", "value");

    cached.createCredentialEntry("absent", "now".toCharArray());

    assertEquals("now",
        new String(cached.getCredentialEntry("absent").getCredential()));
    verify(mockClient, times(1))
        .readSecret("secret/data/hadoop/creds/absent", "value");
  }

  @Test
  public void testACachedMissExpires() throws Exception {
    VaultCredentialProvider cached = new VaultCredentialProvider(
        new URI(TEST_URI), connInfo, mockClient, true, 1);
    when(mockClient.readSecret("secret/data/hadoop/creds/late", "value"))
        .thenReturn(null)
        .thenReturn("value2");

    assertNull(cached.getCredentialEntry("late"));
    Thread.sleep(10);

    assertEquals("value2",
        new String(cached.getCredentialEntry("late").getCredential()));
  }

  @Test
  public void testDeleteRemovesOnlyThisProvidersField() throws Exception {
    when(mockClient.readSecretFields("secret/data/hadoop/creds/db"))
        .thenReturn(secret("username", "dbuser", "value", "p"));

    provider.deleteCredentialEntry("db");

    verify(mockClient).writeSecret("secret/data/hadoop/creds/db",
        fields("username", "dbuser"), 1);
    verify(mockClient, never()).deleteSecret(anyString());
  }

  @Test
  public void testDeleteOfTheLastFieldRemovesTheSecret() throws Exception {
    when(mockClient.readSecretFields("secret/data/hadoop/creds/db"))
        .thenReturn(secret("value", "p"));

    provider.deleteCredentialEntry("db");

    verify(mockClient).deleteSecret("secret/metadata/hadoop/creds/db");
    verify(mockClient, never()).writeSecret(anyString(), anyMap(), anyInt());
  }

  @Test
  public void testWriteDropsTheAliasForEveryField() throws Exception {
    URI uri = new URI(TEST_URI + "?key=username");
    VaultConnectionInfo other = new VaultConnectionInfo(uri);
    VaultCredentialProvider reader = new VaultCredentialProvider(uri, other,
        mockClient, true, 60000, VaultClientIdentity.forTesting("reader"));
    when(mockClient.readSecret("secret/data/hadoop/creds/db", "username"))
        .thenReturn("dbuser")
        .thenReturn(null);
    when(mockClient.readSecretFields("secret/data/hadoop/creds/db"))
        .thenReturn(secret("username", "dbuser", "value", "p"));

    assertEquals("dbuser",
        new String(reader.getCredentialEntry("db").getCredential()));
    providerAs("writer").deleteCredentialEntry("db");

    assertNull(reader.getCredentialEntry("db"));
  }

  @Test
  public void testDeleteOfAGoneAliasDropsTheCachedValue() throws Exception {
    VaultCredentialProvider alice = providerAs("alice");
    when(mockClient.readSecret("secret/data/hadoop/creds/gone.now", "value"))
        .thenReturn("value1")
        .thenReturn(null);
    when(mockClient.readSecretFields("secret/data/hadoop/creds/gone.now"))
        .thenReturn(null);

    alice.getCredentialEntry("gone.now");
    try {
      alice.deleteCredentialEntry("gone.now");
      fail("should throw");
    } catch (IOException e) {
      assertTrue(e.getMessage(), e.getMessage().contains("does not exist"));
    }

    assertNull(alice.getCredentialEntry("gone.now"));
  }

  @Test
  public void testCreateOfAnExistingAliasRefreshesTheCache()
      throws Exception {
    VaultCredentialProvider alice = providerAs("alice");
    when(mockClient.readSecret("secret/data/hadoop/creds/there", "value"))
        .thenReturn("stale")
        .thenReturn("current");
    when(mockClient.readSecretFields("secret/data/hadoop/creds/there"))
        .thenReturn(secret("value", "current"));

    alice.getCredentialEntry("there");
    try {
      alice.createCredentialEntry("there", "new".toCharArray());
      fail("should throw");
    } catch (IOException e) {
      assertTrue(e.getMessage(), e.getMessage().contains("already exists"));
    }

    assertEquals("current",
        new String(alice.getCredentialEntry("there").getCredential()));
  }

  /** A secret as Vault holds it, at version 1. */
  private static VaultHttpClient.Secret secret(Object... fields) {
    return new VaultHttpClient.Secret(fields(fields), 1);
  }

  /** Fields as a write sends them. */
  private static Map<String, Object> fields(Object... fields) {
    Map<String, Object> data = new HashMap<>();
    for (int i = 0; i < fields.length; i += 2) {
      data.put((String) fields[i], fields[i + 1]);
    }
    return data;
  }

  private VaultCredentialProvider providerAs(String name) throws Exception {
    return new VaultCredentialProvider(new URI(TEST_URI), connInfo,
        mockClient, true, 60000, VaultClientIdentity.forTesting(name));
  }

  // --- Credential cache tests ---

  @Test
  public void testCacheHit() throws Exception {
    URI uri = new URI(TEST_URI);
    VaultCredentialProvider cached = new VaultCredentialProvider(
        uri, connInfo, mockClient, true, 60000);

    when(mockClient.readSecret("secret/data/hadoop/creds/cached.key", "value"))
        .thenReturn("cached_value");

    CredentialProvider.CredentialEntry entry1 =
        cached.getCredentialEntry("cached.key");
    assertNotNull(entry1);
    assertEquals("cached_value",
        new String(entry1.getCredential()));

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
    VaultCredentialProvider cached = new VaultCredentialProvider(
        uri, connInfo, mockClient, true, 1);

    when(mockClient.readSecret("secret/data/hadoop/creds/expiring.key", "value"))
        .thenReturn("value1")
        .thenReturn("value2");

    cached.getCredentialEntry("expiring.key");

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
    when(mockClient.readSecretFields("secret/data/hadoop/creds/del.key"))
        .thenReturn(secret("value", "value1"));
    doNothing().when(mockClient)
        .deleteSecret("secret/metadata/hadoop/creds/del.key");

    cached.getCredentialEntry("del.key");
    cached.deleteCredentialEntry("del.key");
    assertNull(cached.getCredentialEntry("del.key"));

    verify(mockClient, times(2))
        .readSecret("secret/data/hadoop/creds/del.key", "value");
  }

  @Test
  public void testCacheUpdatedOnCreate() throws Exception {
    URI uri = new URI(TEST_URI);
    VaultCredentialProvider cached = new VaultCredentialProvider(
        uri, connInfo, mockClient, true, 60000);

    when(mockClient.readSecretFields("secret/data/hadoop/creds/new.cached"))
        .thenReturn(null);

    cached.createCredentialEntry("new.cached", "new_val".toCharArray());

    CredentialProvider.CredentialEntry entry =
        cached.getCredentialEntry("new.cached");
    assertNotNull(entry);
    assertEquals("new_val", new String(entry.getCredential()));

    verify(mockClient, never())
        .readSecret("secret/data/hadoop/creds/new.cached", "value");
  }

  @Test
  public void testCacheDisabled() throws Exception {
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

    when(mockClient.readSecretFields("secret/data/hadoop/creds/new.key"))
        .thenReturn(null);

    customProvider.createCredentialEntry(
        "new.key", "new_val".toCharArray());

    verify(mockClient).writeSecret("secret/data/hadoop/creds/new.key",
        fields("password", "new_val"), 0);
  }
}
