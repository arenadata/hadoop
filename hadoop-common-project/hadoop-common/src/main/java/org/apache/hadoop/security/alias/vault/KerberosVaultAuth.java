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
import java.net.HttpURLConnection;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.apache.hadoop.security.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Kerberos/SPNEGO client of the Vault Kerberos auth backend: login, and
 * the delegation token operations of the authenticated principal and of
 * the users it impersonates.
 *
 * <p>The UGI that logs in is chosen by {@link VaultClientIdentity}: the
 * configured principal and keytab with {@code ugi.mode=dedicated}, the
 * caller's own or the process login with {@code ugi.mode=current}.
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

  @Override
  public String authenticate(VaultHttpClient client) throws IOException {
    String body = VaultAuthRequests.postWithSpnego(client, vaultUgi,
        servicePrincipal, loginUrl, null, "Vault Kerberos login");
    String vaultToken = VaultAuthRequests.clientToken(body, loginUrl);
    LOG.debug("Authenticated to {} as {}", loginUrl, vaultUgi.getUserName());
    return vaultToken;
  }

  @Override
  public String toString() {
    return vaultUgi.getUserName();
  }

  /**
   * Obtain a delegation token owned by the authenticated principal or, with
   * {@code doas}, by the user it names, the authenticated principal being
   * its real user.
   *
   * @param client the client to send the request through
   * @param renewer the principal allowed to renew the token, or null for
   *     a token nobody renews; see {@link VaultDelegationTokens#renewerName}
   * @param doas the user to impersonate, or null
   * @return the token, with the service of this server and auth mount
   * @throws ImpersonationRefusedException if Vault refuses a token on
   *     behalf of {@code doas} or does not support {@code doas}
   * @throws IOException if Vault refuses, the response is malformed or the
   *     token is not owned by the user asked for
   */
  Token<VaultDelegationTokenIdentifier> getDelegationToken(
      VaultHttpClient client, String renewer, String doas)
      throws IOException {
    String service = connInfo.getTokenService(mountPath);
    String url = delegationUrl("token");
    String body;
    try {
      body = VaultAuthRequests.postWithSpnego(client, vaultUgi,
          servicePrincipal, url,
          VaultAuthRequests.json("renewer",
              VaultDelegationTokens.renewerName(renewer, loginRealm()),
              "service", service, "doas", doas),
          "Vault delegation token request");
    } catch (VaultHttpClient.RequestFailedException e) {
      if (doas == null
          || e.getStatus() != HttpURLConnection.HTTP_FORBIDDEN) {
        throw e;
      }
      throw new ImpersonationRefusedException("Vault refused the token "
          + "request of " + vaultUgi.getUserName() + ": " + e.getMessage(), e);
    }
    JsonNode data = VaultAuthRequests.parse(body, url).path("data");
    Token<VaultDelegationTokenIdentifier> token = VaultDelegationTokens.decode(
        data.path("token").asText(null), service, url);
    if (doas != null) {
      checkOwner(client, token, doas, data.has("real_user"), url);
    }
    return token;
  }

  /**
   * Cancel and refuse a token that is not owned by {@code doas}. A server
   * without {@code doas} support ignores the field, issues the token to the
   * caller itself and answers without {@code real_user}.
   */
  private void checkOwner(VaultHttpClient client,
      Token<VaultDelegationTokenIdentifier> token, String doas,
      boolean doasSupported, String url) throws IOException {
    if (!doasSupported) {
      cancelQuietly(client, token);
      throw new ImpersonationRefusedException("Vault does not support doas: "
          + "its response from " + url + " has no real_user", null);
    }
    String owner;
    try {
      owner = VaultDelegationTokens.identifier(token, url).getOwner()
          .toString();
    } catch (IOException e) {
      cancelQuietly(client, token);
      throw e;
    }
    if (!VaultDelegationTokens.namesOwner(doas, owner)) {
      cancelQuietly(client, token);
      throw new IOException("Vault response from " + url + " has a token "
          + "owned by " + owner + ", expected " + doas);
    }
  }

  private void cancelQuietly(VaultHttpClient client, Token<?> token) {
    try {
      cancel(client, token);
    } catch (IOException e) {
      LOG.warn("Failed to cancel Vault delegation token {}: {}", token,
          e.getMessage());
    }
  }

  /** Vault issues no token on behalf of the user asked for. */
  static final class ImpersonationRefusedException extends IOException {
    private static final long serialVersionUID = 1L;

    ImpersonationRefusedException(String message, Throwable cause) {
      super(message, cause);
    }
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
   * Cancel a token; the authenticated principal must be its owner, its
   * renewer, or allowed to impersonate its owner.
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

  private String loginRealm() {
    String realm = new KerberosName(vaultUgi.getUserName()).getRealm();
    return realm != null ? realm : KerberosName.getDefaultRealm();
  }
}
