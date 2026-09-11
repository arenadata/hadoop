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
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedExceptionAction;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Kerberos/SPNEGO authentication for Vault.
 *
 * <p>Supports two UGI modes via
 * {@code hadoop.security.credential.vault.kerberos.ugi.mode}:
 * <ul>
 *   <li>{@code dedicated} (default) — creates a dedicated UGI from the
 *       configured principal and keytab.</li>
 *   <li>{@code current} — uses the current login UGI of the process
 *       (e.g. NameNode's or Spark driver's own Kerberos identity).
 *       No separate principal/keytab configuration needed.</li>
 * </ul>
 */
@InterfaceAudience.Private
public class KerberosVaultAuth implements VaultAuthMethod {

  private static final Logger LOG =
      LoggerFactory.getLogger(KerberosVaultAuth.class);

  private static final Oid SPNEGO_OID;
  private static final Oid KRB5_PRINCIPAL_NAME_OID;
  private static final ObjectMapper MAPPER = new ObjectMapper();


  static {
    try {
      SPNEGO_OID = new Oid("1.3.6.1.5.5.2");
      KRB5_PRINCIPAL_NAME_OID = new Oid("1.2.840.113554.1.2.2.1");
    } catch (GSSException e) {
      throw new RuntimeException("Failed to create GSS OID", e);
    }
  }

  private final UserGroupInformation vaultUgi;
  private final String loginUrl;
  private final String servicePrincipal;

  /**
   * Create a Kerberos auth method.
   *
   * @param conf the Hadoop configuration
   * @param connInfo the Vault connection info
   * @throws IOException if the keytab login fails or the auth mount path
   *     is empty
   */
  public KerberosVaultAuth(Configuration conf,
      VaultConnectionInfo connInfo) throws IOException {
    String vaultHost = connInfo.getHost();
    this.loginUrl = buildLoginUrl(connInfo.getBaseUrl(), conf.get(
        VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_KEY,
        VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_DEFAULT));

    String ugiMode = conf.get(
        VaultCredentialProviderConfig.KERBEROS_UGI_MODE_KEY,
        VaultCredentialProviderConfig.KERBEROS_UGI_MODE_DEFAULT);

    if (VaultCredentialProviderConfig.KERBEROS_UGI_MODE_CURRENT
        .equalsIgnoreCase(ugiMode)) {
      this.vaultUgi = UserGroupInformation.getCurrentUser();
      LOG.debug("Using current UGI for Vault Kerberos auth: {}",
          vaultUgi.getUserName());
    } else {
      String principal = conf.get(
          VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY);
      String keytab = conf.get(
          VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY);

      if (principal == null || principal.isEmpty()) {
        throw new IOException("Kerberos principal not configured. Set '"
            + VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY
            + "' or use ugi.mode=current.");
      }
      if (keytab == null || keytab.isEmpty()) {
        throw new IOException("Kerberos keytab not configured. Set '"
            + VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY
            + "' or use ugi.mode=current.");
      }

      // Resolve _HOST in client principal to local FQDN
      String resolvedPrincipal =
          SecurityUtil.getServerPrincipal(principal, (String) null);
      this.vaultUgi = UserGroupInformation
          .loginUserFromKeytabAndReturnUGI(resolvedPrincipal, keytab);
    }

    // Resolve _HOST in service principal to Vault server hostname
    String configuredSpn = conf.get(
        VaultCredentialProviderConfig.KERBEROS_SERVICE_PRINCIPAL_KEY);
    if (configuredSpn != null && !configuredSpn.isEmpty()) {
      this.servicePrincipal =
          SecurityUtil.getServerPrincipal(configuredSpn, vaultHost);
    } else {
      this.servicePrincipal =
          VaultCredentialProviderConfig.KERBEROS_SERVICE_PRINCIPAL_PREFIX_DEFAULT
              + vaultHost;
    }
  }

  @Override
  @SuppressWarnings("unchecked")
  public String authenticate(VaultHttpClient client) throws IOException {
    try {
      return vaultUgi.doAs(
          (PrivilegedExceptionAction<String>) () -> {
            String spnegoToken = generateSpnegoToken();
            return loginToVault(client, spnegoToken);
          });
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Kerberos authentication interrupted", e);
    }
  }

  private String generateSpnegoToken() throws IOException {
    try {
      GSSManager gssManager = GSSManager.getInstance();
      Oid nameType = servicePrincipal.contains("/")
          ? KRB5_PRINCIPAL_NAME_OID : GSSName.NT_HOSTBASED_SERVICE;
      LOG.debug("Creating GSS name for '{}' with name type OID {}",
          servicePrincipal, nameType);
      GSSName serverName = gssManager.createName(
          servicePrincipal, nameType);
      GSSContext gssContext = gssManager.createContext(
          serverName, SPNEGO_OID, null, GSSContext.DEFAULT_LIFETIME);
      gssContext.requestMutualAuth(true);
      gssContext.requestCredDeleg(false);

      byte[] token = gssContext.initSecContext(new byte[0], 0, 0);
      gssContext.dispose();

      return java.util.Base64.getEncoder().encodeToString(token);
    } catch (GSSException e) {
      throw new IOException("Failed to generate SPNEGO token", e);
    }
  }

  /**
   * Build the Kerberos login URL from the auth backend mount path.
   * The login endpoint of the Vault Kerberos auth method is
   * {@code /v1/<mount>/login}.
   *
   * @param baseUrl the Vault base URL
   * @param mountPath the auth backend mount path, e.g. {@code auth/kerberos}
   * @return the login URL
   * @throws IOException if the mount path is empty
   */
  static String buildLoginUrl(String baseUrl, String mountPath)
      throws IOException {
    String mount = StringUtils.strip(StringUtils.trimToEmpty(mountPath), "/");
    if (mount.isEmpty()) {
      throw new IOException("Vault Kerberos auth mount path is empty. Set '"
          + VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_KEY + "'.");
    }
    return baseUrl + "/v1/" + mount + "/login";
  }

  private String loginToVault(VaultHttpClient client,
      String spnegoToken) throws IOException {
    HttpURLConnection conn = client.createConnection(loginUrl, "POST");
    conn.setRequestProperty("Authorization", "Negotiate " + spnegoToken);
    conn.setDoOutput(true);
    conn.setRequestProperty("Content-Type", "application/json");
    // Empty body for kerberos login
    conn.getOutputStream().close();

    int statusCode = conn.getResponseCode();

    if (statusCode != HttpURLConnection.HTTP_OK) {
      String errorBody = "";
      InputStream es = conn.getErrorStream();
      if (es != null) {
        try {
          errorBody = IOUtils.toString(es, StandardCharsets.UTF_8);
        } finally {
          es.close();
        }
      }
      conn.disconnect();
      throw new IOException(
          "Vault Kerberos login to " + loginUrl + " failed with status "
              + statusCode + ": " + errorBody);
    }

    String responseBody;
    try (InputStream is = conn.getInputStream()) {
      responseBody = IOUtils.toString(is, StandardCharsets.UTF_8);
    }

    VaultResponse.AuthLogin response;
    try {
      response = MAPPER.readValue(responseBody, VaultResponse.AuthLogin.class);
    } catch (IOException e) {
      throw new IOException("Vault Kerberos login to " + loginUrl
          + " returned an unparseable response", e);
    }
    if (response.auth == null) {
      throw new IOException(
          "Vault Kerberos login response missing 'auth' field");
    }
    if (response.auth.clientToken == null
        || response.auth.clientToken.isEmpty()) {
      throw new IOException(
          "Vault Kerberos login response missing 'client_token'");
    }

    LOG.debug("Successfully authenticated to Vault via Kerberos");
    return response.auth.clientToken;
  }
}
