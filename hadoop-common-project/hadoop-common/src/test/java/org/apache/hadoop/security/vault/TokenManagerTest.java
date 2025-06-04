package org.apache.hadoop.security.vault;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.*;

/**
 * Unit tests for TokenManager.
 */
public class TokenManagerTest {
    private VaultAuthenticationService authService;
    private TokenManager tokenManager;

    @Before
    public void setUp() {
        authService = mock(VaultAuthenticationService.class);
        tokenManager = new TokenManager(authService);
    }

    @Test
    public void testFirstCallInvokesAuthenticate() throws Exception {
        when(authService.authenticate()).thenReturn("tok1");
        String t1 = tokenManager.getToken();
        assertEquals("tok1", t1);
        verify(authService, times(1)).authenticate();
    }

    @Test
    public void testCachedTokenIsReused() throws Exception {
        when(authService.authenticate()).thenReturn("tok1");
        String t1 = tokenManager.getToken();
        String t2 = tokenManager.getToken();
        assertSame(t1, t2);
        verify(authService, times(1)).authenticate();
    }

    @Test
    public void testClearTokenForcesReauthenticate() throws Exception {
        when(authService.authenticate()).thenReturn("tok1", "tok2");
        String t1 = tokenManager.getToken();
        tokenManager.clearToken();
        String t2 = tokenManager.getToken();
        assertEquals("tok1", t1);
        assertEquals("tok2", t2);
        verify(authService, times(2)).authenticate();
    }

    @Test
    public void testTokenExpiryForcesReauthenticate() throws Exception {
        when(authService.authenticate()).thenReturn("tok1", "tok2");

        String t1 = tokenManager.getToken();
        assertEquals("tok1", t1);
        java.lang.reflect.Field fExpiry = TokenManager.class.getDeclaredField("expiry");
        fExpiry.setAccessible(true);
        fExpiry.setLong(tokenManager, System.currentTimeMillis() - 1);

        String t2 = tokenManager.getToken();
        assertEquals("tok2", t2);
        verify(authService, times(2)).authenticate();
    }
}
