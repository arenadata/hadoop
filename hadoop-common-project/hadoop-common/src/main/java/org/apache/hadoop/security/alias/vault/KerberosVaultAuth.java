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
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.apache.hadoop.security.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Kerberos/SPNEGO client of the Vault Kerberos auth backend: login, and
 * the delegation token operations of the authenticated principal.
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

  /**
   * Obtain a delegation token owned by the authenticated principal.
   *
   * @param client the client to send the request through
   * @param renewer the principal allowed to renew the token, or null for
   *     a token nobody renews; see {@link VaultDelegationTokens#renewerName}
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
}
