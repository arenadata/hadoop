package org.apache.hadoop.security.vault;

import org.apache.hadoop.conf.Configuration;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.config.Lookup;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.auth.SPNegoSchemeFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Principal;

/**
 * Utility to create two HTTP clients:
 * 1) SPNEGO-capable client for Kerberos login.
 * 2) Plain client for token-based KV calls.
 * <p>
 * Both clients support TLS based on Hadoop Configuration (custom truststore/keystore).
 */
public final class VaultHttpClientFactory {

    private VaultHttpClientFactory() { /* utility */ }

    /**
     * Create a SPNEGO-capable HttpClient for Kerberos login to Vault.
     * If TLS settings are provided in 'conf', they will be applied.
     *
     * @param conf Hadoop Configuration
     * @return CloseableHttpClient configured for SPNEGO and TLS
     * @throws Exception on any error building SSL context
     */
    public static CloseableHttpClient createSpnegoClient(Configuration conf) throws Exception {
        // Build SSLContext from config (or default if none specified)
        SSLContext sslContext = buildSslContext(conf);

        // Register SPNEGO (Negotiate) as AuthScheme
        Lookup<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
                .register("Negotiate", new SPNegoSchemeFactory(true))
                .build();

        // CredentialsProvider using UGI Subject (null creds)
        CredentialsProvider credsProvider = new BasicCredentialsProvider();
        credsProvider.setCredentials(AuthScope.ANY, new Credentials() {
            @Override
            public Principal getUserPrincipal() {
                return null;
            }

            @Override
            public String getPassword() {
                return null;
            }
        });

        return HttpClients.custom()
                .setSSLContext(sslContext)
                .setDefaultAuthSchemeRegistry(authSchemeRegistry)
                .setDefaultCredentialsProvider(credsProvider)
                .useSystemProperties()
                .build();
    }

    /**
     * Create a plain HttpClient for token-based Vault KV v2 calls.
     * If TLS settings are provided in 'conf', they will be applied.
     *
     * @param conf Hadoop Configuration
     * @return CloseableHttpClient configured for TLS but no SPNEGO
     * @throws Exception on any error building SSL context
     */
    public static CloseableHttpClient createPlainClient(Configuration conf) throws Exception {
        SSLContext sslContext = buildSslContext(conf);
        return HttpClients.custom()
                .setSSLContext(sslContext)
                .useSystemProperties()
                .build();
    }

    /**
     * Builds an SSLContext using custom keystore/truststore if specified; otherwise defaults.
     * If no custom path is provided, returns default SSLContext (JVM truststore).
     *
     * @param conf Hadoop Configuration
     * @return initialized SSLContext
     * @throws Exception if loading keystore/truststore fails
     */
    private static SSLContext buildSslContext(Configuration conf) throws Exception {
        String truststorePath = conf.get(VaultConfigKeys.VAULT_SSL_TRUSTSTORE_PATH);
        String truststorePassword = conf.get(VaultConfigKeys.VAULT_SSL_TRUSTSTORE_PASSWORD);
        String truststoreType = conf.get(VaultConfigKeys.VAULT_SSL_TRUSTSTORE_TYPE, "JKS");


        String keystorePath = conf.get(VaultConfigKeys.VAULT_SSL_KEYSTORE_PATH);
        String keystorePassword = conf.get(VaultConfigKeys.VAULT_SSL_KEYSTORE_PASSWORD);
        String keystoreType = conf.get(VaultConfigKeys.VAULT_SSL_KEYSTORE_TYPE, "JKS");


        SSLContextBuilder builder = SSLContextBuilder.create();

        // Configure custom truststore if provided
        if (truststorePath != null && !truststorePath.isEmpty()) {
            KeyStore trustStore = KeyStore.getInstance(truststoreType);
            try (FileInputStream tsStream = new FileInputStream(new File(truststorePath))) {
                trustStore.load(tsStream,
                        (truststorePassword != null) ? truststorePassword.toCharArray() : null
                );
            }
            builder.loadTrustMaterial(trustStore, null);
        } else {
            // Use default JVM TrustStore
            builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
        }

        // Configure custom keystore (client cert) if provided
        if (keystorePath != null && !keystorePath.isEmpty()) {
            KeyStore keyStore = KeyStore.getInstance(keystoreType);
            try (FileInputStream ksStream = new FileInputStream(new File(keystorePath))) {
                keyStore.load(ksStream,
                        (keystorePassword != null) ? keystorePassword.toCharArray() : null
                );
            }
            builder.loadKeyMaterial(keyStore,
                    (keystorePassword != null) ? keystorePassword.toCharArray() : null
            );
        }

        return builder.build();
    }
}
