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

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Vault login with a delegation token issued by the Kerberos auth backend:
 * {@code POST /v1/<mount>/login} with {@code {"delegation_token": ...}} and
 * no SPNEGO. Used by processes that hold a token but no Kerberos
 * credentials, such as YARN containers. The token is taken from the user's
 * credentials at every login, so a replaced token is picked up.
 */
@InterfaceAudience.Private
public class VaultDelegationTokenAuth implements VaultAuthMethod {

  private static final Logger LOG =
      LoggerFactory.getLogger(VaultDelegationTokenAuth.class);

  private final VaultConnectionInfo connInfo;
  private final String preferredMountPath;

  /**
   * @param connInfo the Vault server
   * @param preferredMountPath the configured auth mount path; a token for
   *     another mount of the same server is used when none matches it
   */
  public VaultDelegationTokenAuth(VaultConnectionInfo connInfo,
      String preferredMountPath) {
    this.connInfo = connInfo;
    this.preferredMountPath = preferredMountPath;
  }

  @Override
  public String authenticate(VaultHttpClient client) throws IOException {
    UserGroupInformation ugi = VaultDelegationTokens.actualUser();
    Token<?> token = VaultDelegationTokens.selectToken(ugi.getCredentials(),
        connInfo, preferredMountPath);
    if (token == null) {
      throw new IOException("User " + ugi.getUserName()
          + " has no Vault delegation token for "
          + connInfo.getServerService());
    }
    String loginUrl = connInfo.getApiUrl(VaultDelegationTokens.authMountPath(
        token.getService().toString()) + "/login");
    String body = VaultAuthRequests.post(client, loginUrl, null,
        VaultAuthRequests.json("delegation_token", token.encodeToUrlString()),
        "Vault delegation token login");
    String vaultToken = VaultAuthRequests.clientToken(body, loginUrl);
    LOG.debug("Authenticated to {} with the delegation token of {}",
        loginUrl, ugi.getUserName());
    return vaultToken;
  }
}
