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
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenRenewer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Renews and cancels Vault delegation tokens as the current user over
 * SPNEGO. The Vault server and auth mount come from the token service; the
 * service principal and TLS settings come from the configuration.
 */
@InterfaceAudience.Private
public class VaultDelegationTokenRenewer extends TokenRenewer {

  private static final Logger LOG =
      LoggerFactory.getLogger(VaultDelegationTokenRenewer.class);

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
}
