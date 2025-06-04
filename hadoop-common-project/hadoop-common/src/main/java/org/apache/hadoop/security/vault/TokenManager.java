package org.apache.hadoop.security.vault;

import java.io.IOException;


/**
 * TokenManager handles caching and refreshing a Vault client token.
 * It uses an injected VaultAuthenticationService to perform authentication when needed.
 */
public class TokenManager {

    private final VaultAuthenticationService authService;
    private String token;
    private long expiry;

    /**
     * Construct a TokenManager with the given authentication service.
     *
     * @param authService implementation of VaultAuthenticationService (Kerberos or token-based)
     */
    public TokenManager(VaultAuthenticationService authService) {
        this.authService = authService;
        this.token = null;
        this.expiry = 0L;
    }

    /**
     * Return a valid Vault token. If the current token is null or expired, authenticate again.
     *
     * @return a non-null Vault client token
     * @throws IOException if authentication fails
     */
    public synchronized String getToken() throws IOException {
        long now = System.currentTimeMillis();
        if (token == null || now >= expiry) {
            token = authService.authenticate();
            // Set expiry ~55 minutes from now (assuming Vault token TTL is 60 minutes)
            expiry = now + 55 * 60 * 1000L;
        }
        return token;
    }

    /**
     * Invalidate the cached token so that next getToken() call forces a fresh authentication.
     */
    public synchronized void clearToken() {
        token = null;
        expiry = 0L;
    }
}