package org.apache.hadoop.security.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.*;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * VaultHttpClient wraps a plain HttpClient (no SPNEGO) to call Vault KV v2 endpoints
 * using an X-Vault-Token obtained from TokenManager.
 */
public class VaultHttpClient {
    private final CloseableHttpClient plainClient;
    private final String vaultAddress;
    private final TokenManager tokenManager;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * @param vaultAddress full Vault URL without trailing slash, e.g. "https://vault.example.com:8200"
     * @param plainClient  a plain HttpClient (no SPNEGO) configured for TLS if needed
     * @param tokenManager manages the current Vault token (refreshes on expiry/401)
     */
    public VaultHttpClient(String vaultAddress,
                           CloseableHttpClient plainClient,
                           TokenManager tokenManager) {
        this.vaultAddress = vaultAddress.endsWith("/")
                ? vaultAddress.substring(0, vaultAddress.length() - 1)
                : vaultAddress;
        this.plainClient = plainClient;
        this.tokenManager = tokenManager;
    }

    /**
     * Read a secret from Vault (GET /v1/{mount}/data/{secretPath}).
     *
     * @param mount      Vault KV mount path (e.g. "secret")
     * @param secretPath path under mount (e.g. "myapp/dbpassword")
     * @return secret value as char[], or null if not found
     * @throws IOException on I/O error or non-2xx (except 404 treated as null)
     */
    public char[] readSecret(String mount, String secretPath) throws IOException {
        String url = vaultAddress + "/v1/" + mount + "/data/" + secretPath;
        HttpGet get = new HttpGet(url);
        String token = tokenManager.getToken();
        get.setHeader("X-Vault-Token", token);

        try {
            String body = executeWithRetry(get);
            JsonNode root = mapper.readTree(body);
            JsonNode val = root.path("data").path("data").path("value");
            return val.isMissingNode() ? null : val.asText().toCharArray();
        } catch (VaultNotFoundException e) {
            return null;
        }
    }

    /**
     * Write (create or update) a secret in Vault (POST /v1/{mount}/data/{secretPath}).
     *
     * @param mount      Vault KV mount path
     * @param secretPath path under mount
     * @param secret     secret value as char[]
     * @throws IOException on I/O error or non-2xx
     */
    public void writeSecret(String mount, String secretPath, char[] secret) throws IOException {
        String url = vaultAddress + "/v1/" + mount + "/data/" + secretPath;
        HttpPost post = new HttpPost(url);
        String token = tokenManager.getToken();
        post.setHeader("X-Vault-Token", token);

        // Build JSON payload: { "data": { "value": "<secret>" } }
        JsonNode rootNode = mapper.createObjectNode()
                .putObject("data")
                .put("value", new String(secret));
        StringEntity entity = new StringEntity(
                mapper.writeValueAsString(rootNode),
                "application/json"
        );
        post.setEntity(entity);

        executeWithRetry(post);
    }

    /**
     * Delete a secret from Vault (DELETE /v1/{mount}/metadata/{secretPath}),
     * which permanently removes all versions.
     *
     * @param mount      Vault KV mount path
     * @param secretPath path under mount
     * @throws IOException on I/O error or non-2xx
     */
    public void deleteSecret(String mount, String secretPath) throws IOException {
        String url = vaultAddress + "/v1/" + mount + "/metadata/" + secretPath;
        HttpDelete delete = new HttpDelete(url);
        String token = tokenManager.getToken();
        delete.setHeader("X-Vault-Token", token);

        executeWithRetry(delete);
    }

    /**
     * List all secrets under a given prefix (LIST /v1/{mount}/metadata/{pathPrefix}).
     *
     * @param mount      Vault KV mount path
     * @param pathPrefix optional prefix (empty string for root)
     * @return list of secret keys (folder names include trailing '/')
     * @throws IOException on I/O error or non-2xx
     */
    public List<String> listSecrets(String mount, String pathPrefix) throws IOException {
        String suffix = (pathPrefix == null || pathPrefix.isEmpty()) ? "" : "/" + pathPrefix;
        String url = vaultAddress + "/v1/" + mount + "/metadata" + suffix;

        // Use HTTP LIST method
        HttpRequestBase listReq = new HttpRequestBase() {
            @Override
            public String getMethod() {
                return "LIST";
            }
        };
        listReq.setURI(URI.create(url));

        String token = tokenManager.getToken();
        listReq.setHeader("X-Vault-Token", token);

        String body = executeWithRetry(listReq);
        JsonNode root = mapper.readTree(body);
        JsonNode keysNode = root.path("data").path("keys");
        List<String> keys = new ArrayList<>();
        if (keysNode.isArray()) {
            for (JsonNode key : keysNode) {
                keys.add(key.asText());
            }
        }
        return keys;
    }

    /**
     * Execute an HTTP request, retrying once if Vault returns 401 Unauthorized.
     * If 404 is returned during readSecret, throw VaultNotFoundException.
     *
     * @param request any HttpRequestBase (GET/POST/DELETE/LIST)
     * @return response body as String for 2xx
     * @throws IOException if non-2xx after retry or other I/O error
     */
    private String executeWithRetry(HttpRequestBase request) throws IOException {
        int attempts = 0;
        while (attempts < 2) {
            attempts++;
            try (CloseableHttpResponse response = plainClient.execute(request)) {
                int status = response.getStatusLine().getStatusCode();
                String body = response.getEntity() != null
                        ? EntityUtils.toString(response.getEntity(), "UTF-8")
                        : "";

                if (status == 404 && request.getMethod().equals("GET")) {
                    // Secret not found
                    throw new VaultNotFoundException("Secret not found: " + request.getURI());
                }
                if (status == 401 && attempts == 1) {
                    // Token expired or invalid: clear and retry once
                    tokenManager.clearToken();
                    String newToken = tokenManager.getToken();
                    request.setHeader("X-Vault-Token", newToken);
                    continue;
                }
                if (status >= 200 && status < 300) {
                    return body;
                }
                throw new IOException("Vault request failed (HTTP " + status + "): " + body);
            }
        }
        throw new IOException("Vault request failed after retry: " + request.getURI());
    }

    /**
     * Custom exception to indicate a 404 Not Found in readSecret.
     */
    public static class VaultNotFoundException extends IOException {
        public VaultNotFoundException(String message) {
            super(message);
        }
    }
}
