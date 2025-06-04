package org.apache.hadoop.security.vault;

import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

/**
 * Unit tests for VaultKerberosAuthenticationService.
 */
public class VaultKerberosAuthenticationServiceTest {
    @Mock
    private CloseableHttpClient mockSpnegoClient;
    @Mock
    private CloseableHttpResponse mockResponse;
    @Mock
    private StatusLine mockStatusLine;
    @Mock
    private HttpEntity mockEntity;

    private VaultKerberosAuthenticationService service;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        service = new VaultKerberosAuthenticationService(
                "https://vault.example.com:8200",
                mockSpnegoClient
        );
    }

    @Test
    public void testAuthenticateSuccess() throws Exception {
        String json = "{\"auth\":{\"client_token\":\"abc123\"}}";
        InputStream stream = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));

        when(mockStatusLine.getStatusCode()).thenReturn(200);
        when(mockEntity.getContent()).thenReturn(stream);
        when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockResponse.getEntity()).thenReturn(mockEntity);
        when(mockSpnegoClient.execute(any(HttpGet.class))).thenReturn(mockResponse);
        String token = service.authenticate();
        assertEquals("abc123", token);

        verify(mockSpnegoClient, times(1)).execute(any(HttpGet.class));
    }

    @Test(expected = IOException.class)
    public void testAuthenticateNon200Throws() throws Exception {
        when(mockStatusLine.getStatusCode()).thenReturn(401);
        when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockResponse.getEntity()).thenReturn(mockEntity);
        when(mockSpnegoClient.execute(any(HttpGet.class))).thenReturn(mockResponse);

        service.authenticate();
    }
}
