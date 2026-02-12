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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configuration constants for the Vault credential provider.
 */
@InterfaceAudience.Private
public final class VaultCredentialProviderConfig {

  private static final Logger LOG =
      LoggerFactory.getLogger(VaultCredentialProviderConfig.class);

  public static final String CONFIG_PREFIX =
      "hadoop.security.credential.vault.";

  public static final String AUTH_METHOD_KEY =
      CONFIG_PREFIX + "auth.method";
  public static final String AUTH_METHOD_DEFAULT = "token";

  public static final String TOKEN_KEY =
      CONFIG_PREFIX + "token";
  public static final String VAULT_TOKEN_ENV = "VAULT_TOKEN";

  public static final String CREDENTIALS_DIRECTORY_ENV =
      "CREDENTIALS_DIRECTORY";
  public static final String SYSTEMD_CREDENTIAL_NAME_KEY =
      CONFIG_PREFIX + "systemd.credential.name";
  public static final String SYSTEMD_CREDENTIAL_NAME_DEFAULT =
      "vault-token";

  public static final String CONNECTION_TIMEOUT_MS_KEY =
      CONFIG_PREFIX + "connection.timeout.ms";
  public static final int CONNECTION_TIMEOUT_MS_DEFAULT = 30000;

  public static final String READ_TIMEOUT_MS_KEY =
      CONFIG_PREFIX + "read.timeout.ms";
  public static final int READ_TIMEOUT_MS_DEFAULT = 30000;

  public static final String RETRY_COUNT_KEY =
      CONFIG_PREFIX + "retry.count";
  public static final int RETRY_COUNT_DEFAULT = 3;

  public static final String RETRY_INTERVAL_MS_KEY =
      CONFIG_PREFIX + "retry.interval.ms";
  public static final int RETRY_INTERVAL_MS_DEFAULT = 1000;

  public static final String KERBEROS_PRINCIPAL_KEY =
      CONFIG_PREFIX + "kerberos.principal";
  public static final String KERBEROS_KEYTAB_KEY =
      CONFIG_PREFIX + "kerberos.keytab";
  public static final String KERBEROS_LOGIN_PATH_KEY =
      CONFIG_PREFIX + "kerberos.login.path";
  public static final String KERBEROS_LOGIN_PATH_DEFAULT =
      "auth/kerberos";

  public static final String KERBEROS_SERVICE_PRINCIPAL_KEY =
      CONFIG_PREFIX + "kerberos.service.principal";
  public static final String KERBEROS_SERVICE_PRINCIPAL_PREFIX_DEFAULT =
      "HTTP@";

  public static final String KERBEROS_UGI_MODE_KEY =
      CONFIG_PREFIX + "kerberos.ugi.mode";
  public static final String KERBEROS_UGI_MODE_DEFAULT = "dedicated";
  public static final String KERBEROS_UGI_MODE_CURRENT = "current";

  public static final String CACHE_ENABLED_KEY =
      CONFIG_PREFIX + "cache.enabled";
  public static final boolean CACHE_ENABLED_DEFAULT = true;

  public static final String CLIENT_CACHE_MAX_SIZE_KEY =
      CONFIG_PREFIX + "client.cache.max.size";
  public static final int CLIENT_CACHE_MAX_SIZE_DEFAULT = 16;

  public static final String CACHE_TTL_MS_KEY =
      CONFIG_PREFIX + "cache.ttl.ms";
  public static final long CACHE_TTL_MS_DEFAULT = 600000;

  private VaultCredentialProviderConfig() {
  }

  /**
   * Resolves the Vault token from configuration, systemd credentials,
   * or environment variable (in that priority order).
   *
   * <p>Resolution order:
   * <ol>
   *   <li>Hadoop configuration property {@code hadoop.security.credential.vault.token}</li>
   *   <li>systemd credential file at {@code $CREDENTIALS_DIRECTORY/<name>}</li>
   *   <li>Environment variable {@code VAULT_TOKEN}</li>
   * </ol>
   *
   * @param conf the Hadoop configuration
   * @return the Vault token, or null if not found
   */
  public static String resolveToken(Configuration conf) {
    String token = conf.get(TOKEN_KEY);
    if (token != null && !token.isEmpty()) {
      return token;
    }

    token = readSystemdCredential(conf);
    if (token != null && !token.isEmpty()) {
      return token;
    }

    return System.getenv(VAULT_TOKEN_ENV);
  }

  /**
   * Read the Vault token from a systemd credential file.
   *
   * @param conf the Hadoop configuration
   * @return the token string, or null if not available
   */
  static String readSystemdCredential(Configuration conf) {
    return readSystemdCredential(conf,
        System.getenv(CREDENTIALS_DIRECTORY_ENV));
  }

  /**
   * Read the Vault token from a systemd credential file at the given
   * directory path. Package-private for testability.
   *
   * @param conf the Hadoop configuration
   * @param credDir the credentials directory path, or null if not set
   * @return the token string, or null if not available
   */
  static String readSystemdCredential(Configuration conf, String credDir) {
    if (credDir == null || credDir.isEmpty()) {
      return null;
    }

    String credName = conf.get(SYSTEMD_CREDENTIAL_NAME_KEY,
        SYSTEMD_CREDENTIAL_NAME_DEFAULT);
    File credFile = new File(credDir, credName);
    if (!credFile.isFile()) {
      LOG.debug("systemd credential file not found: {}", credFile);
      return null;
    }

    try (FileInputStream fis = new FileInputStream(credFile)) {
      String token = IOUtils.toString(fis, StandardCharsets.UTF_8).trim();
      if (!token.isEmpty()) {
        LOG.debug("Vault token read from systemd credential: {}", credFile);
        return token;
      }
    } catch (IOException e) {
      LOG.warn("Failed to read systemd credential file {}: {}",
          credFile, e.getMessage());
    }
    return null;
  }
}
