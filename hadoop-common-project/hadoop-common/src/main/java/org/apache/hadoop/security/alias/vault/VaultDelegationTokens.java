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
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.apache.hadoop.security.token.Token;

/**
 * Delegation tokens of the Vault/OpenBao Kerberos auth backend: selection
 * from Hadoop credentials and the token service format
 * {@code vault://<protocol>@<host>:<port>/<auth mount path>}.
 */
@InterfaceAudience.Private
public final class VaultDelegationTokens {

  private VaultDelegationTokens() {
  }

  /**
   * Select the delegation token for a Vault server from credentials: the
   * token recorded for the given auth mount, else any token of this kind
   * for the same server.
   *
   * @param credentials the credentials to search
   * @param connInfo the Vault server
   * @param authMountPath the auth mount path to prefer
   * @return the token, or null when there is none
   */
  public static Token<?> selectToken(Credentials credentials,
      VaultConnectionInfo connInfo, String authMountPath) {
    Token<?> token = credentials.getToken(
        new Text(connInfo.getTokenService(authMountPath)));
    if (isVaultToken(token)) {
      return token;
    }
    String server = connInfo.getServerService() + "/";
    for (Token<?> candidate : credentials.getAllTokens()) {
      if (isVaultToken(candidate)
          && candidate.getService().toString().startsWith(server)) {
        return candidate;
      }
    }
    return null;
  }

  private static boolean isVaultToken(Token<?> token) {
    return token != null
        && VaultDelegationTokenIdentifier.KIND_NAME.equals(token.getKind());
  }

  /**
   * The auth mount path recorded in a token service.
   *
   * @throws IOException if the service carries no mount path
   */
  static String authMountPath(String tokenService) throws IOException {
    int slash = tokenService.indexOf('/', tokenService.indexOf('@') + 1);
    String mount = slash < 0 ? ""
        : VaultConnectionInfo.stripSlashes(tokenService.substring(slash));
    if (mount.isEmpty()) {
      throw new IOException("Vault token service " + tokenService
          + " has no auth mount path");
    }
    return mount;
  }

  /**
   * The user whose credentials authenticate to Vault: the current user, or
   * the real user behind a proxy user.
   */
  static UserGroupInformation actualUser() throws IOException {
    UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
    return ugi.getRealUser() != null ? ugi.getRealUser() : ugi;
  }

  /**
   * The renewer name to record in a token. Vault matches a renewer by its
   * full principal, or by the primary alone for callers from the owner's
   * realm, so a same-realm renewer is recorded by its primary and any
   * ResourceManager of an HA pair or a federation can renew.
   *
   * @param renewer the renewer principal, or null
   * @param ownerRealm the realm of the token owner
   * @return the name to record, or null
   */
  static String renewerName(String renewer, String ownerRealm) {
    if (renewer == null || renewer.isEmpty()) {
      return null;
    }
    KerberosName name;
    try {
      name = new KerberosName(renewer);
    } catch (IllegalArgumentException e) {
      return renewer;
    }
    String realm = name.getRealm();
    if (realm == null || realm.isEmpty() || realm.equals(ownerRealm)) {
      return name.getServiceName();
    }
    return renewer;
  }

  /**
   * Decode a token issued by {@code delegation/token}.
   */
  static Token<VaultDelegationTokenIdentifier> decode(String encoded,
      String service, String url) throws IOException {
    if (encoded == null || encoded.isEmpty()) {
      throw new IOException("Vault response from " + url
          + " has no data.token");
    }
    Token<VaultDelegationTokenIdentifier> token = new Token<>();
    try {
      token.decodeFromUrlString(encoded);
    } catch (RuntimeException e) {
      throw new IOException("Vault response from " + url
          + " has a malformed data.token", e);
    }
    if (!VaultDelegationTokenIdentifier.KIND_NAME.equals(token.getKind())) {
      throw new IOException("Vault issued a delegation token of kind "
          + token.getKind() + ", expected "
          + VaultDelegationTokenIdentifier.KIND_NAME);
    }
    token.setService(new Text(service));
    return token;
  }
}
