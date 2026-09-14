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

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.apache.hadoop.security.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Kerberos/SPNEGO client of the Vault Kerberos auth backend: login, and
 * the delegation token operations of the authenticated principal.
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

  private final UserGroupInformation vaultUgi;
  private final VaultConnectionInfo connInfo;
  private final String mountPath;
  private final String loginUrl;
  private final String servicePrincipal;

  /**
   * Create a Kerberos auth method for the configured UGI mode.
   *
   * @param conf the Hadoop configuration
   * @param connInfo the Vault connection info
   * @throws IOException if the keytab login fails or the auth mount path
   *     is empty
   */
  public KerberosVaultAuth(Configuration conf,
      VaultConnectionInfo connInfo) throws IOException {
    this(conf, connInfo, VaultAuthRequests.mountPath(conf),
        resolveUgi(conf));
  }

  /**
   * Create a Kerberos auth method acting as the given UGI.
   *
   * @param conf the Hadoop configuration
   * @param connInfo the Vault connection info
   * @param mountPath the auth backend mount path
   * @param ugi the Kerberos identity to authenticate with
   * @throws IOException if the service principal cannot be resolved
   */
  KerberosVaultAuth(Configuration conf, VaultConnectionInfo connInfo,
      String mountPath, UserGroupInformation ugi) throws IOException {
    this.vaultUgi = ugi;
    this.connInfo = connInfo;
    this.mountPath = mountPath;
    this.loginUrl = connInfo.getApiUrl(mountPath + "/login");
    this.servicePrincipal = VaultAuthRequests.resolveServicePrincipal(conf,
        connInfo.getHost());
  }

  private static UserGroupInformation resolveUgi(Configuration conf)
      throws IOException {
    String ugiMode = conf.get(
        VaultCredentialProviderConfig.KERBEROS_UGI_MODE_KEY,
        VaultCredentialProviderConfig.KERBEROS_UGI_MODE_DEFAULT);
    if (VaultCredentialProviderConfig.KERBEROS_UGI_MODE_CURRENT
        .equalsIgnoreCase(ugiMode)) {
      UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
      LOG.debug("Using current UGI for Vault Kerberos auth: {}",
          ugi.getUserName());
      return ugi;
    }

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
    return UserGroupInformation
        .loginUserFromKeytabAndReturnUGI(resolvedPrincipal, keytab);
  }

  @Override
  public String authenticate(VaultHttpClient client) throws IOException {
    String body = VaultAuthRequests.postWithSpnego(client, vaultUgi,
        servicePrincipal, loginUrl, null, "Vault Kerberos login");
    String vaultToken = VaultAuthRequests.clientToken(body, loginUrl);
    LOG.debug("Authenticated to {} as {}", loginUrl, vaultUgi.getUserName());
    return vaultToken;
  }

  /**
   * Obtain a delegation token owned by the authenticated principal.
   *
   * @param client the client to send the request through
   * @param renewer the principal allowed to renew the token, or null;
   *     see {@link VaultDelegationTokens#renewerName}
   * @return the token, with the service of this server and auth mount
   * @throws IOException if Vault refuses or the response is malformed
   */
  Token<VaultDelegationTokenIdentifier> getDelegationToken(
      VaultHttpClient client, String renewer) throws IOException {
    String service = connInfo.getTokenService(mountPath);
    String url = delegationUrl("token");
    String body = VaultAuthRequests.postWithSpnego(client, vaultUgi,
        servicePrincipal, url,
        VaultAuthRequests.json("renewer",
            VaultDelegationTokens.renewerName(renewer, ownerRealm()),
            "service", service),
        "Vault delegation token request");
    return VaultDelegationTokens.decode(VaultAuthRequests.parse(body, url)
        .path("data").path("token").asText(null), service, url);
  }

  /**
   * Renew a token; the authenticated principal must be its renewer.
   *
   * @return the new expiry time in milliseconds since the epoch
   */
  long renew(VaultHttpClient client, Token<?> token) throws IOException {
    String url = delegationUrl("renew");
    String body = VaultAuthRequests.postWithSpnego(client, vaultUgi,
        servicePrincipal, url,
        VaultAuthRequests.json("token", token.encodeToUrlString()),
        "Vault delegation token renewal");
    JsonNode expiry = VaultAuthRequests.parse(body, url)
        .path("data").path("expiry");
    if (!expiry.canConvertToLong()) {
      throw new IOException("Vault response from " + url
          + " has no data.expiry");
    }
    return expiry.asLong();
  }

  /**
   * Cancel a token; the authenticated principal must be its owner or
   * renewer.
   */
  void cancel(VaultHttpClient client, Token<?> token) throws IOException {
    String url = delegationUrl("cancel");
    VaultAuthRequests.postWithSpnego(client, vaultUgi, servicePrincipal, url,
        VaultAuthRequests.json("token", token.encodeToUrlString()),
        "Vault delegation token cancellation");
  }

  private String delegationUrl(String action) {
    return connInfo.getApiUrl(mountPath + "/delegation/" + action);
  }

  private String ownerRealm() {
    String realm = new KerberosName(vaultUgi.getUserName()).getRealm();
    return realm != null ? realm : KerberosName.getDefaultRealm();
  }

  /**
   * Build the Kerberos login path from the auth backend mount path.
   * The login endpoint of the Vault Kerberos auth method is
   * {@code /v1/<mount>/login}.
   *
   * @param mountPath the auth backend mount path, e.g. {@code auth/kerberos}
   * @return the login path relative to {@code /v1/}
   * @throws IOException if the mount path is empty
   */
  static String buildLoginPath(String mountPath) throws IOException {
    return VaultAuthRequests.mountPath(mountPath) + "/login";
  }
}
