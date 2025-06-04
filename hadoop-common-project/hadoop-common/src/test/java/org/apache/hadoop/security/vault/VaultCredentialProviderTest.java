package org.apache.hadoop.security.vault;

import org.apache.hadoop.security.alias.CredentialProvider.CredentialEntry;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for VaultCredentialProvider.
 */
public class VaultCredentialProviderTest {
    private VaultHttpClient mockVaultClient;
    private VaultCredentialProvider provider;

    @Before
    public void setUp() throws Exception {
        mockVaultClient = mock(VaultHttpClient.class);
        URI uri = new URI("vault://vault.example.com:8200/secret");
        provider = new VaultCredentialProvider(uri, mockVaultClient);
    }

    @Test
    public void testGetCredentialEntryFound() throws Exception {
        when(mockVaultClient.readSecret("secret", "alias1"))
                .thenReturn("mypwd".toCharArray());

        CredentialEntry entry = provider.getCredentialEntry("alias1");
        assertNotNull(entry);
        assertEquals("alias1", entry.getAlias());
        assertArrayEquals("mypwd".toCharArray(), entry.getCredential());
    }

    @Test
    public void testGetCredentialEntryNotFound() throws Exception {
        when(mockVaultClient.readSecret("secret", "missing")).thenReturn(null);
        CredentialEntry entry = provider.getCredentialEntry("missing");
        assertNull(entry);
    }

    @Test
    public void testCreateCredentialEntry() throws Exception {
        char[] pwd = "newPwd".toCharArray();
        CredentialEntry entry = provider.createCredentialEntry("newAlias", pwd);
        assertNotNull(entry);
        assertEquals("newAlias", entry.getAlias());
        assertArrayEquals(pwd, entry.getCredential());
        verify(mockVaultClient, times(1)).writeSecret("secret", "newAlias", pwd);
    }

    @Test
    public void testDeleteCredentialEntry() throws Exception {
        provider.deleteCredentialEntry("aliasToDelete");
        verify(mockVaultClient, times(1)).deleteSecret("secret", "aliasToDelete");
    }

    @Test
    public void testGetAliases() throws Exception {
        List<String> list = Arrays.asList("a", "b", "c");
        when(mockVaultClient.listSecrets("secret", "")).thenReturn(list);

        List<String> aliases = provider.getAliases();
        assertEquals(3, aliases.size());
        assertTrue(aliases.contains("a"));
        assertTrue(aliases.contains("b"));
        assertTrue(aliases.contains("c"));
    }
}
