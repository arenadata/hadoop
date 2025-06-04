package org.apache.hadoop.security.vault;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.http.impl.client.CloseableHttpClient;

import java.io.IOException;
import java.net.URI;

public class VaultCredentialProviderFactory extends CredentialProviderFactory {

    public static final String SCHEME_NAME = "vault";

    @Override
    public CredentialProvider createProvider(URI providerName, Configuration conf) throws IOException {
        if (!SCHEME_NAME.equals(providerName.getScheme())) {
            return null;
        }

        boolean sslEnabled = conf.getBoolean(VaultConfigKeys.VAULT_SSL_ENABLED, false);
        String authority = providerName.getAuthority();
        String protocol = sslEnabled ? "https" : "http";
        String vaultAddress = protocol + "://" + authority;

        // Create the appropriate authentication service (Kerberos or token)
        VaultAuthenticationService authService = VaultAuthenticationService.create(conf);

        // Create TokenManager using the auth service
        TokenManager tokenManager = new TokenManager(authService);

        // Create a plain HttpClient for KV v2 calls (no SPNEGO)
        CloseableHttpClient plainClient;
        try {
            plainClient = VaultHttpClientFactory.createPlainClient(conf);
        } catch (Exception e) {
            throw new IOException("Failed to create plain HTTP client", e);
        }

        // Create VaultHttpClient with the plain client and token manager
        VaultHttpClient vaultClient = new VaultHttpClient(vaultAddress, plainClient, tokenManager);

        return new VaultCredentialProvider(providerName, vaultClient);
    }
}