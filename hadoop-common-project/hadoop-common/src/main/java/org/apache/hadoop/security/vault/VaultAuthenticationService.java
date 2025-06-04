package org.apache.hadoop.security.vault;

import org.apache.hadoop.conf.Configuration;
import org.apache.http.impl.client.CloseableHttpClient;

import java.io.IOException;

public interface VaultAuthenticationService {

    /**
     * Factory method: based on configuration, choose either token auth or Kerberos auth.
     * Internally creates a SPNEGO-capable HttpClient if needed.
     *
     * @param conf Hadoop Configuration (reads auth method, addresses, etc.)
     * @return appropriate VaultAuthenticationService implementation
     * @throws IOException on failure to set up SPNEGO client or missing settings
     */
    static VaultAuthenticationService create(Configuration conf) throws IOException {
        String method = conf.get(VaultConfigKeys.VAULT_AUTH_METHOD, "token");

        if ("kerberos".equalsIgnoreCase(method)) {
            String vaultAddress = conf.get(VaultConfigKeys.VAULT_ADDRESS);
            if (vaultAddress == null) {
                throw new IOException("Missing configuration: " + VaultConfigKeys.VAULT_ADDRESS);
            }
            // spnego-based auth
            CloseableHttpClient spnegoClient;
            try {
                spnegoClient = VaultHttpClientFactory.createSpnegoClient(conf);
            } catch (Exception e) {
                throw new IOException("Failed to create SPNEGO HttpClient", e);
            }
            return new VaultKerberosAuthenticationService(vaultAddress, spnegoClient);
        } else {
            // token-based auth
            String token = conf.get(VaultConfigKeys.VAULT_TOKEN);
            if (token == null) {
                throw new IOException("Missing configuration: " + VaultConfigKeys.VAULT_TOKEN);
            }
            return new VaultTokenAuthenticationService(token);
        }
    }

    /**
     * Perform login to Vault and return a client token.
     *
     * @return Vault client token (string)
     * @throws IOException on I/O or authentication error
     */
    String authenticate() throws IOException;
}
