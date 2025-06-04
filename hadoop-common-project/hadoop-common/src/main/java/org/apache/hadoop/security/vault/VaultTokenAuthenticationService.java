package org.apache.hadoop.security.vault;

import java.io.IOException;

public class VaultTokenAuthenticationService implements VaultAuthenticationService {

    private final String staticToken;

    public VaultTokenAuthenticationService(String staticToken) {
        this.staticToken = staticToken;
    }

    @Override
    public String authenticate() throws IOException {
        return staticToken;
    }
}
