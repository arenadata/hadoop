package org.apache.hadoop.security.vault;

/**
 * Configuration key constants for integrating Hadoop CredentialProvider with HashiCorp Vault.
 */
public final class VaultConfigKeys {

    /**
     * Authentication method for Vault.
     * Accepted values: "token" (default) or "kerberos".
     */
    public static final String VAULT_AUTH_METHOD = "hadoop.security.credential.vault.auth.method";
    /**
     * Full URL of the Vault server, for example: "https://vault.example.com:8200".
     */
    public static final String VAULT_ADDRESS = "hadoop.security.credential.vault.address";

    /**
     * Static Vault token to use when the authentication method is "token".
     */
    public static final String VAULT_TOKEN = "hadoop.security.credential.vault.token";

    public static final String VAULT_SSL_ENABLED = "hadoop.security.credential.vault.ssl.enabled";

    /**
     * Path to a custom truststore file (JKS or PKCS12) to trust Vault's certificate.
     * If not set, the system default truststore is used.
     */
    public static final String VAULT_SSL_TRUSTSTORE_PATH = "hadoop.security.credential.vault.ssl.truststore.path";
    /**
     * Password for the custom truststore (defined by SSL_TRUSTSTORE_PATH).
     */
    public static final String VAULT_SSL_TRUSTSTORE_PASSWORD = "hadoop.security.credential.vault.ssl.truststore.password";
    /**
     * Path to a custom keystore file (JKS or PKCS12) if client-side certificates are required.
     * If not set, no client certificate is provided.
     */
    public static final String VAULT_SSL_KEYSTORE_PATH = "hadoop.security.credential.vault.ssl.keystore.path";
    /**
     * Password for the custom keystore (defined by SSL_KEYSTORE_PATH).
     */
    public static final String VAULT_SSL_KEYSTORE_PASSWORD = "hadoop.security.credential.vault.ssl.keystore.password";
    /**
     * Type of the custom truststore (e.g., "JKS" or "PKCS12"). Defaults to JKS.
     */
    public static final String VAULT_SSL_TRUSTSTORE_TYPE =
            "hadoop.security.credential.vault.ssl.truststore.type";
    /**
     * Type of the custom keystore (e.g., "JKS" or "PKCS12"). Defaults to JKS.
     */
    public static final String VAULT_SSL_KEYSTORE_TYPE =
            "hadoop.security.credential.vault.ssl.keystore.type";

    private VaultConfigKeys() {
        // Utility class; do not instantiate.
    }
}