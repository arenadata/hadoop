/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.security.alias.vault;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Requests to the Vault Kerberos auth backend: SPNEGO-authenticated and
 * plain JSON posts, plus the shared configuration lookups.
 */
@InterfaceAudience.Private
final class VaultAuthRequests {

  private static final Logger LOG =
      LoggerFactory.getLogger(VaultAuthRequests.class);

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private VaultAuthRequests() {
  }

  /**
   * Normalise the configured auth backend mount path.
   *
   * @param mountPath the configured value, e.g. {@code auth/kerberos}
   * @return the mount path without surrounding slashes
   * @throws IOException if the mount path is empty
   */
  static String mountPath(String mountPath) throws IOException {
    String mount = VaultConnectionInfo.stripSlashes(mountPath);
    if (mount.isEmpty()) {
      throw new IOException("Vault Kerberos auth mount path is empty. Set '"
          + VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_KEY + "'.");
    }
    return mount;
  }

  static String mountPath(Configuration conf) throws IOException {
    return mountPath(conf.get(
        VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_KEY,
        VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_DEFAULT));
  }

  /**
   * Resolve the Vault service principal for SPNEGO, replacing {@code _HOST}
   * with the Vault host name.
   */
  static String resolveServicePrincipal(Configuration conf,
      String vaultHost) throws IOException {
    String configured = conf.get(
        VaultCredentialProviderConfig.KERBEROS_SERVICE_PRINCIPAL_KEY);
    if (configured != null && !configured.isEmpty()) {
      return SecurityUtil.getServerPrincipal(configured, vaultHost);
    }
    return VaultCredentialProviderConfig.KERBEROS_SERVICE_PRINCIPAL_PREFIX_DEFAULT
        + vaultHost;
  }

  /**
   * POST as {@code ugi} with a fresh SPNEGO token, relogging in from the
   * keytab first when the TGT is close to expiry.
   *
   * @return the response body
   */
  static String postWithSpnego(VaultHttpClient client,
      UserGroupInformation ugi, String servicePrincipal, String url,
      String jsonBody, String action) throws IOException {
    ugi.checkTGTAndReloginFromKeytab();
    try {
      return ugi.doAs((PrivilegedExceptionAction<String>) () -> post(client,
          url, "Negotiate " + spnegoToken(servicePrincipal), jsonBody,
          action));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException(action + " interrupted", e);
    }
  }

  /**
   * POST a JSON body and return the response body; a 204 yields an empty
   * string. Any other status becomes an IOException naming the URL.
   */
  static String post(VaultHttpClient client, String url,
      String authorization, String jsonBody, String action)
      throws IOException {
    HttpURLConnection conn = client.createConnection(url, "POST");
    if (authorization != null) {
      conn.setRequestProperty("Authorization", authorization);
    }
    conn.setRequestProperty("Content-Type", "application/json");
    conn.setDoOutput(true);
    try (OutputStream os = conn.getOutputStream()) {
      if (jsonBody != null) {
        os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
      }
    }

    int statusCode = conn.getResponseCode();
    if (statusCode == HttpURLConnection.HTTP_OK) {
      try (InputStream is = conn.getInputStream()) {
        return IOUtils.toString(is, StandardCharsets.UTF_8);
      }
    }
    if (statusCode == HttpURLConnection.HTTP_NO_CONTENT) {
      conn.disconnect();
      return "";
    }
    String errorBody = VaultHttpClient.readErrorBody(conn);
    conn.disconnect();
    throw new IOException(action + " to " + url + " failed with status "
        + statusCode + ": " + errorBody);
  }

  /**
   * Generate a base64 SPNEGO token for the service principal. Must run
   * inside the doAs of the initiating UGI.
   */
  static String spnegoToken(String servicePrincipal) throws IOException {
    try {
      GSSManager gssManager = GSSManager.getInstance();
      Oid nameType = servicePrincipal.contains("/")
          ? KerberosUtil.NT_GSS_KRB5_PRINCIPAL_OID
          : GSSName.NT_HOSTBASED_SERVICE;
      LOG.debug("Creating GSS name for '{}' with name type OID {}",
          servicePrincipal, nameType);
      GSSName serverName = gssManager.createName(
          servicePrincipal, nameType);
      GSSContext gssContext = gssManager.createContext(serverName,
          KerberosUtil.GSS_SPNEGO_MECH_OID, null,
          GSSContext.DEFAULT_LIFETIME);
      gssContext.requestMutualAuth(true);
      gssContext.requestCredDeleg(false);

      byte[] token = gssContext.initSecContext(new byte[0], 0, 0);
      gssContext.dispose();

      return Base64.getEncoder().encodeToString(token);
    } catch (GSSException e) {
      throw new IOException("Failed to generate SPNEGO token", e);
    }
  }

  /**
   * Serialise alternating keys and values into a JSON object, skipping
   * null values.
   */
  static String json(Object... keyValues) throws IOException {
    Map<String, Object> fields = new LinkedHashMap<>();
    for (int i = 0; i < keyValues.length; i += 2) {
      if (keyValues[i + 1] != null) {
        fields.put((String) keyValues[i], keyValues[i + 1]);
      }
    }
    return MAPPER.writeValueAsString(fields);
  }

  static JsonNode parse(String body, String url) throws IOException {
    try {
      return MAPPER.readTree(body);
    } catch (IOException e) {
      throw new IOException("Vault response from " + url
          + " is not JSON", e);
    }
  }

  /**
   * Extract {@code auth.client_token} from a login response.
   */
  static String clientToken(String body, String url) throws IOException {
    JsonNode token = parse(body, url).path("auth").path("client_token");
    if (!token.isTextual() || token.asText().isEmpty()) {
      throw new IOException("Vault login response from " + url
          + " has no auth.client_token");
    }
    return token.asText();
  }
}
