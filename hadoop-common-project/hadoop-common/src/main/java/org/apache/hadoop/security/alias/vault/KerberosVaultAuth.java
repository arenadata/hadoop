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
  private static final ObjectMapper MAPPER = new ObjectMapper();


  static {
    try {
      SPNEGO_OID = new Oid("1.3.6.1.5.5.2");
    } catch (GSSException e) {
      throw new RuntimeException("Failed to create SPNEGO OID", e);
    }
  }

  private final UserGroupInformation vaultUgi;
  private final VaultConnectionInfo connInfo;
  private final String loginPath;
  private final String servicePrincipal;

  /**
   * Create a Kerberos auth method.
   *
   * @param conf the Hadoop configuration
   * @param connInfo the Vault connection info
   * @throws IOException if the keytab login fails
   */
  public KerberosVaultAuth(Configuration conf,
      VaultConnectionInfo connInfo) throws IOException {
    this.connInfo = connInfo;
    String vaultHost = connInfo.getHost();

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

    this.loginPath = conf.get(
        VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_KEY,
        VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_DEFAULT);

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
      GSSName serverName = gssManager.createName(
          servicePrincipal, GSSName.NT_HOSTBASED_SERVICE);
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

  private String loginToVault(VaultHttpClient client,
      String spnegoToken) throws IOException {
    String url = connInfo.getBaseUrl() + "/v1/" + loginPath;

    HttpURLConnection conn = client.createConnection(url, "POST");
    conn.setRequestProperty("Authorization", "Negotiate " + spnegoToken);
    conn.setDoOutput(true);
    conn.setRequestProperty("Content-Type", "application/json");
    // Empty body for kerberos login
    try (java.io.OutputStream os = conn.getOutputStream()) {
      // no content
    }

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
          "Vault Kerberos login failed with status " + statusCode
              + ": " + errorBody);
    }

    String responseBody;
    try (InputStream is = conn.getInputStream()) {
      responseBody = IOUtils.toString(is, StandardCharsets.UTF_8);
    }

    VaultResponse.AuthLogin response = MAPPER.readValue(
        responseBody, VaultResponse.AuthLogin.class);
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
