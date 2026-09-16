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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenRenewer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Renews and cancels Vault delegation tokens as the current user over
 * SPNEGO. The Vault server and auth mount come from the token service; the
 * service principal and TLS settings come from the configuration. A token
 * names the server the renewer authenticates to, so the server is checked
 * against the ones this host is configured for.
 */
@InterfaceAudience.Private
public class VaultDelegationTokenRenewer extends TokenRenewer {

  private static final Logger LOG =
      LoggerFactory.getLogger(VaultDelegationTokenRenewer.class);

  private static final Set<String> UNCONFIGURED_SERVERS =
      ConcurrentHashMap.newKeySet();

  @Override
  public boolean handleKind(Text kind) {
    return VaultDelegationTokenIdentifier.KIND_NAME.equals(kind);
  }

  @Override
  public boolean isManaged(Token<?> token) {
    return true;
  }

  @Override
  public long renew(Token<?> token, Configuration conf) throws IOException {
    LOG.debug("Renewing Vault delegation token {}", token);
    return withClient(token, conf, (auth, client) -> auth.renew(client, token));
  }

  @Override
  public void cancel(Token<?> token, Configuration conf) throws IOException {
    LOG.debug("Cancelling Vault delegation token {}", token);
    withClient(token, conf, (auth, client) -> {
      auth.cancel(client, token);
      return null;
    });
  }

  private interface Call<T> {
    T apply(KerberosVaultAuth auth, VaultHttpClient client)
        throws IOException;
  }

  private static <T> T withClient(Token<?> token, Configuration conf,
      Call<T> call) throws IOException {
    String service = token.getService().toString();
    VaultConnectionInfo connInfo = VaultConnectionInfo.fromTokenService(
        service);
    checkServer(conf, connInfo.getServerService());
    KerberosVaultAuth auth = new KerberosVaultAuth(conf, connInfo,
        VaultDelegationTokens.authMountPath(service),
        UserGroupInformation.getCurrentUser());
    VaultHttpClient client = VaultHttpClient.unauthenticated(conf, connInfo);
    try {
      return call.apply(auth, client);
    } finally {
      client.close();
    }
  }

  /**
   * Refuse a server this host is not configured for. The servers are
   * those listed for renewal, else those of the credential provider path;
   * a host that names none accepts every server and says so once each.
   */
  static void checkServer(Configuration conf, String server)
      throws IOException {
    Set<String> known = knownServers(conf);
    if (known.isEmpty()) {
      if (UNCONFIGURED_SERVERS.add(server)) {
        LOG.warn("Renewing Vault delegation tokens of {}, a server no "
            + "configuration on this host names; set {} to restrict the "
            + "servers renewal authenticates to", server,
            VaultCredentialProviderConfig.DELEGATION_TOKEN_SERVERS_KEY);
      }
      return;
    }
    if (!known.contains(server)) {
      throw new IOException("Vault server " + server
          + " is not one this host is configured for; see "
          + VaultCredentialProviderConfig.DELEGATION_TOKEN_SERVERS_KEY);
    }
  }

  static Set<String> knownServers(Configuration conf) throws IOException {
    Set<String> servers = new HashSet<>();
    for (String entry : conf.getTrimmedStringCollection(
        VaultCredentialProviderConfig.DELEGATION_TOKEN_SERVERS_KEY)) {
      String prefix = VaultCredentialProvider.SCHEME_NAME + "://";
      servers.add(VaultConnectionInfo.fromTokenService(
          entry.startsWith(prefix) ? entry : prefix + entry)
          .getServerService());
    }
    if (!servers.isEmpty()) {
      return servers;
    }
    for (String path : conf.getTrimmedStringCollection(
        CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH)) {
      URI uri;
      try {
        uri = new URI(path);
      } catch (URISyntaxException e) {
        continue;
      }
      if (VaultCredentialProvider.SCHEME_NAME.equals(uri.getScheme())) {
        servers.add(new VaultConnectionInfo(uri).getServerService());
      }
    }
    return servers;
  }
}
