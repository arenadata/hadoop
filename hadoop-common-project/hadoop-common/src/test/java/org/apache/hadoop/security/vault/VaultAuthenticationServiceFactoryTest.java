package org.apache.hadoop.security.vault;

import org.apache.hadoop.conf.Configuration;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class VaultAuthenticationServiceFactoryTest {

    @Test
    public void testCreateTokenAuth() throws Exception {
        Configuration conf = new Configuration();
        conf.set(VaultConfigKeys.VAULT_AUTH_METHOD, "token");
        conf.set(VaultConfigKeys.VAULT_TOKEN, "static-token");

        VaultAuthenticationService auth = VaultAuthenticationService.create(conf);
        assertTrue(auth instanceof VaultTokenAuthenticationService);
        assertEquals("static-token", auth.authenticate());
    }

    @Test
    public void testCreateKerberosAuth() throws Exception {
        Configuration conf = new Configuration();
        conf.set(VaultConfigKeys.VAULT_AUTH_METHOD, "kerberos");
        conf.set(VaultConfigKeys.VAULT_ADDRESS, "https://vault.example.com:8200");
        VaultAuthenticationService auth = VaultAuthenticationService.create(conf);
        assertTrue(auth instanceof VaultKerberosAuthenticationService);
    }

    @Test(expected = IOException.class)
    public void testMissingTokenThrows() throws Exception {
        Configuration conf = new Configuration();
        VaultAuthenticationService.create(conf);
    }

    @Test(expected = IOException.class)
    public void testMissingAddressThrowsForKerberos() throws Exception {
        Configuration conf = new Configuration();
        conf.set(VaultConfigKeys.VAULT_AUTH_METHOD, "kerberos");
        VaultAuthenticationService.create(conf);
    }
}
