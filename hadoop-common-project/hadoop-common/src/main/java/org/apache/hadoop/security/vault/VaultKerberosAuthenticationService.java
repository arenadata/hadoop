package org.apache.hadoop.security.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.security.PrivilegedExceptionAction;

/**
 * AuthenticationService implementation that uses Kerberos/SPNEGO to log in to HashiCorp Vault.
 * Relies on Hadoop UGI for existing Kerberos credentials.
 */
public class VaultKerberosAuthenticationService implements VaultAuthenticationService {

    private final String vaultAddress;
    private final CloseableHttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * @param vaultAddress full Vault URL without trailing slash (e.g. "https://vault.example.com:8200")
     * @param spnegoClient SPNEGO-configured HttpClient from HttpClientFactory.createSpnegoClient()
     */
    public VaultKerberosAuthenticationService(String vaultAddress, CloseableHttpClient spnegoClient) {
        // Trim any trailing slash from vaultAddress
        this.vaultAddress = vaultAddress.endsWith("/")
                ? vaultAddress.substring(0, vaultAddress.length() - 1)
                : vaultAddress;
        this.httpClient = spnegoClient;
    }

    /**
     * Execute GET /v1/auth/kerberos/login under Hadoop UGI Subject.
     * Vault returns JSON with {"auth":{"client_token":"..."}}.
     */
    @Override
    public String authenticate() throws IOException {
        UserGroupInformation ugi = UserGroupInformation.getLoginUser();

        try {
            // Execute HTTP GET as the logged-in Kerberos user
            return ugi.doAs((PrivilegedExceptionAction<String>) () -> {
                String loginUrl = vaultAddress + "/v1/auth/kerberos/login";
                HttpGet get = new HttpGet(loginUrl);

                try (CloseableHttpResponse response = httpClient.execute(get)) {
                    int status = response.getStatusLine().getStatusCode();
                    String body = EntityUtils.toString(response.getEntity(), "UTF-8");

                    if (status != 200) {
                        throw new IOException("Vault Kerberos login failed, HTTP " + status + ": " + body);
                    }

                    JsonNode root = mapper.readTree(body);
                    return root.path("auth").path("client_token").asText();
                }
            });
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Error during Kerberos authentication to Vault", e);
        }
    }
}
