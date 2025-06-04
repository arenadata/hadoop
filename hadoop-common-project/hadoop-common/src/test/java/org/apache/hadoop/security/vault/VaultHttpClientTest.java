package org.apache.hadoop.security.vault;

import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for VaultHttpClient.
 */
public class VaultHttpClientTest {
    @Mock
    private CloseableHttpClient mockPlainClient;
    @Mock
    private CloseableHttpResponse mockResponse;
    @Mock
    private StatusLine mockStatusLine;
    @Mock
    private HttpEntity mockEntity;
    @Mock
    private TokenManager mockTokenManager;

    private VaultHttpClient client;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        client = new VaultHttpClient("https://vault.example.com:8200", mockPlainClient, mockTokenManager);
    }

    @Test
    public void testReadSecretSuccess() throws Exception {
        when(mockTokenManager.getToken()).thenReturn("t1");

        String json = "{\"data\":{\"data\":{\"value\":\"secretValue\"}}}";
        InputStream stream = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));

        when(mockStatusLine.getStatusCode()).thenReturn(200);
        when(mockEntity.getContent()).thenReturn(stream);
        when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockResponse.getEntity()).thenReturn(mockEntity);

        when(mockPlainClient.execute(any(HttpGet.class))).thenReturn(mockResponse);

        char[] result = client.readSecret("secret", "mykey");
        assertNotNull(result);
        assertEquals("secretValue", new String(result));
        verify(mockTokenManager, times(1)).getToken();
        verify(mockPlainClient, times(1)).execute(any(HttpGet.class));
    }

    @Test
    public void testReadSecretNotFoundReturnsNull() throws Exception {
        when(mockTokenManager.getToken()).thenReturn("t1");
        when(mockStatusLine.getStatusCode()).thenReturn(404);
        when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockResponse.getEntity()).thenReturn(null);
        when(mockPlainClient.execute(any(HttpGet.class))).thenReturn(mockResponse);

        char[] result = client.readSecret("secret", "missingKey");
        assertNull(result);
    }

    @Test
    public void testRetryOn401() throws Exception {
        when(mockTokenManager.getToken()).thenReturn("oldToken", "newToken");

        when(mockStatusLine.getStatusCode()).thenReturn(401)
                .thenReturn(200); // второй вызов — 200
        when(mockResponse.getEntity()).thenReturn(null);
        when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);

        String json200 = "{\"data\":{\"data\":{\"value\":\"val2\"}}}";
        HttpEntity entity200 = mock(HttpEntity.class);
        InputStream stream200 = new ByteArrayInputStream(json200.getBytes(StandardCharsets.UTF_8));
        when(entity200.getContent()).thenReturn(stream200);

        when(mockResponse.getEntity()).thenReturn(null).thenReturn(entity200);

        when(mockPlainClient.execute(any(HttpGet.class))).thenReturn(mockResponse);

        char[] result = client.readSecret("secret", "somekey");
        assertArrayEquals("val2".toCharArray(), result);
        verify(mockTokenManager, times(2)).getToken();
        verify(mockPlainClient, times(2)).execute(any(HttpGet.class));
    }

    @Test
    public void testListSecretsSuccess() throws Exception {
        when(mockTokenManager.getToken()).thenReturn("t1");
        String json = "{\"data\":{\"keys\":[\"a\",\"b/\",\"c\"]}}";
        InputStream stream = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));

        when(mockStatusLine.getStatusCode()).thenReturn(200);
        when(mockEntity.getContent()).thenReturn(stream);
        when(mockResponse.getStatusLine()).thenReturn(mockStatusLine);
        when(mockResponse.getEntity()).thenReturn(mockEntity);
        when(mockPlainClient.execute(any(HttpRequestBase.class))).thenReturn(mockResponse);

        List<String> keys = client.listSecrets("secret", "");
        assertEquals(3, keys.size());
        assertTrue(keys.contains("a"));
        assertTrue(keys.contains("b/"));
        assertTrue(keys.contains("c"));
    }
}
