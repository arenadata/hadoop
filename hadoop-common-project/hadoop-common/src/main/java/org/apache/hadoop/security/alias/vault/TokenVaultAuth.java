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

/**
 * Token-based authentication for Vault.
 * Reads the token from Hadoop configuration, systemd credentials
 * ({@code $CREDENTIALS_DIRECTORY/vault-token}), or the VAULT_TOKEN
 * environment variable.
 */
@InterfaceAudience.Private
public class TokenVaultAuth implements VaultAuthMethod {

  private final Configuration conf;

  public TokenVaultAuth(Configuration conf) {
    this.conf = conf;
  }

  @Override
  public String authenticate(VaultHttpClient client) throws IOException {
    String token = VaultCredentialProviderConfig.resolveToken(conf);
    if (token == null || token.isEmpty()) {
      throw new IOException("Vault token not found. Set '"
          + VaultCredentialProviderConfig.TOKEN_KEY
          + "' in configuration, provide a systemd credential '"
          + VaultCredentialProviderConfig.SYSTEMD_CREDENTIAL_NAME_DEFAULT
          + "' in $" + VaultCredentialProviderConfig.CREDENTIALS_DIRECTORY_ENV
          + ", or set '" + VaultCredentialProviderConfig.VAULT_TOKEN_ENV
          + "' environment variable.");
    }
    return token;
  }
}
