package org.apache.hadoop.security.vault;

import org.apache.hadoop.security.alias.CredentialProvider;

import java.io.IOException;
import java.net.URI;
import java.util.List;

/**
 * VaultCredentialProvider is a Hadoop CredentialProvider that stores secrets in HashiCorp Vault (KV v2).
 * It delegates all HTTP calls to a VaultHttpClient, which uses a plain HttpClient plus a TokenManager.
 */
public class VaultCredentialProvider extends CredentialProvider {
    private final String mountPath;
    private final VaultHttpClient vaultClient;

    /**
     * @param providerName URI of the form vault://host:port/<mountPath>
     * @param vaultClient  initialized VaultHttpClient for KV v2 calls
     */
    public VaultCredentialProvider(URI providerName, VaultHttpClient vaultClient) {
        // Extract mount path from URI: remove leading "/" if present
        String path = providerName.getPath();
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        this.mountPath = path;
        this.vaultClient = vaultClient;
    }

    @Override
    public CredentialEntry getCredentialEntry(String alias) throws IOException {
        // Read the secret from Vault. In KV v2, alias == secret path
        char[] secret = vaultClient.readSecret(mountPath, alias);
        if (secret == null) {
            return null;
        }
        return new CredentialEntry(alias, secret);
    }

    @Override
    public List<String> getAliases() throws IOException {
        // List all keys under the mount path
        return vaultClient.listSecrets(mountPath, "");
    }

    @Override
    public CredentialEntry createCredentialEntry(String alias, char[] credential) throws IOException {
        // Write (create or update) the secret in Vault
        vaultClient.writeSecret(mountPath, alias, credential);
        // Hadoop expects returning a CredentialEntry for the newly created secret
        return new CredentialEntry(alias, credential);
    }

    @Override
    public void deleteCredentialEntry(String alias) throws IOException {
        // Delete the secret (all versions) from Vault
        vaultClient.deleteSecret(mountPath, alias);
    }

    @Override
    public void flush() throws IOException {
        // No local buffers: all writes to Vault are immediate
    }

    @Override
    public boolean isTransient() {
        // This provider persists secrets remotely in Vault, so it is not transient
        return false;
    }
}
