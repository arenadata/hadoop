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
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.hadoop.security.token.DelegationTokenIssuer;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.thirdparty.com.google.common.cache.Cache;
import org.apache.hadoop.thirdparty.com.google.common.cache.CacheBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A credential provider backed by HashiCorp Vault or OpenBao KV v2 engine.
 *
 * URI format: {@code vault://[protocol@]host:port/mount/path}
 *
 * Each alias is stored as a separate secret in Vault at
 * {@code {mount}/data/{path}/{alias}} with content
 * {@code {"value": "credential_string"}}.
 *
 * <p>The provider maintains two levels of caching within the JVM:
 * <ul>
 *   <li><b>Client cache</b> — a static map of {@link VaultHttpClient}
 *       instances keyed by {@link VaultClientIdentity}, so that provider
 *       re-creation (e.g. repeated {@code Configuration.getPassword()}
 *       calls) reuses the already-authenticated client, and only for the
 *       identity that authenticated it.</li>
 *   <li><b>Credential cache</b> — a Guava {@link Cache} with
 *       {@code expireAfterWrite} TTL, to avoid repeated HTTP round-trips
 *       for the same alias within the same JVM. Entries belong to the
 *       identity that read them; writes and deletes drop the alias for
 *       every identity.</li>
 * </ul>
 *
 * {@link #flush()} is a no-op. Writes and deletes update the cache
 * immediately.
 */
@InterfaceAudience.Private
public class VaultCredentialProvider extends CredentialProvider
    implements DelegationTokenIssuer {

  public static final String SCHEME_NAME = "vault";

  private static final Logger LOG =
      LoggerFactory.getLogger(VaultCredentialProvider.class);

  /** Static client cache, lazily initialized on first use. */
  private static volatile Cache<VaultClientIdentity, VaultHttpClient>
      clientCache;

  /**
   * Static credential cache, lazily initialized on first use. A value is
   * held per identity that read it, so it is never served to an identity
   * Vault has not granted it to; a write or a delete drops the alias for
   * all of them.
   */
  private static volatile Cache<CredentialKey, String> credentialCache;

  private final URI uri;
  private final VaultConnectionInfo connInfo;
  private final VaultHttpClient httpClient;
  private final boolean cacheEnabled;
  private final Configuration conf;
  private final VaultClientIdentity identity;

  /**
   * Create a Vault credential provider.
   *
   * @param uri the provider URI
   * @param conf the Hadoop configuration
   * @throws IOException if the provider cannot be initialized
   */
  public VaultCredentialProvider(URI uri, Configuration conf)
      throws IOException {
    this.uri = uri;
    this.conf = conf;
    this.connInfo = new VaultConnectionInfo(uri);
    this.cacheEnabled = conf.getBoolean(
        VaultCredentialProviderConfig.CACHE_ENABLED_KEY,
        VaultCredentialProviderConfig.CACHE_ENABLED_DEFAULT);

    initClientCache(conf);
    if (cacheEnabled) {
      initCredentialCache(conf);
    }

    try {
      this.identity = VaultClientIdentity.of(conf, connInfo);
    } catch (IOException e) {
      throw new IOException("Failed to create VaultHttpClient for "
          + connInfo.getBaseUrl(), e);
    }
    try {
      this.httpClient = clientCache.get(identity, () ->
          new VaultHttpClient(conf, connInfo,
              identity.createAuthMethod(conf, connInfo)));
    } catch (ExecutionException e) {
      throw new IOException("Failed to create VaultHttpClient for "
          + connInfo.getBaseUrl(), e.getCause());
    }

    LOG.debug("Created VaultCredentialProvider for {}", uri);
  }

  /**
   * Package-private constructor for testing (no caching).
   */
  VaultCredentialProvider(URI uri, VaultConnectionInfo connInfo,
      VaultHttpClient httpClient) {
    this(uri, connInfo, httpClient, false, 0,
        VaultClientIdentity.forTesting("test"));
  }

  /**
   * Package-private constructor for testing with cache control.
   */
  VaultCredentialProvider(URI uri, VaultConnectionInfo connInfo,
      VaultHttpClient httpClient, boolean cacheEnabled, long cacheTtlMs) {
    this(uri, connInfo, httpClient, cacheEnabled, cacheTtlMs,
        VaultClientIdentity.forTesting("test"));
  }

  /**
   * Package-private constructor for testing a given identity.
   */
  VaultCredentialProvider(URI uri, VaultConnectionInfo connInfo,
      VaultHttpClient httpClient, boolean cacheEnabled, long cacheTtlMs,
      VaultClientIdentity identity) {
    this.uri = uri;
    this.conf = new Configuration(false);
    this.connInfo = connInfo;
    this.httpClient = httpClient;
    this.cacheEnabled = cacheEnabled;
    this.identity = identity;
    if (cacheEnabled && credentialCache == null) {
      credentialCache = CacheBuilder.newBuilder()
          .expireAfterWrite(cacheTtlMs, TimeUnit.MILLISECONDS)
          .maximumSize(VaultCredentialProviderConfig.CACHE_MAX_SIZE_DEFAULT)
          .build();
    }
  }

  /**
   * The token service of this provider, or null when the configured auth
   * mount path is invalid.
   */
  @Override
  public String getCanonicalServiceName() {
    try {
      return connInfo.getTokenService(VaultAuthRequests.mountPath(conf));
    } catch (IOException e) {
      return null;
    }
  }

  /**
   * Obtain a delegation token owned by the current user, who must hold
   * Kerberos credentials of their own. Returns null when this provider
   * does not use Kerberos auth, when the current user is a proxy user or
   * when they have no Kerberos credentials: tokens are never issued in the
   * name of the dedicated keytab principal.
   */
  @Override
  public Token<?> getDelegationToken(String renewer) throws IOException {
    if (!VaultCredentialProviderConfig.AUTH_METHOD_KERBEROS
        .equalsIgnoreCase(VaultCredentialProviderConfig.authMethod(conf))) {
      LOG.debug("Not issuing a Vault delegation token for {}: auth method is "
          + "not kerberos", connInfo.getServerService());
      return null;
    }
    UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
    if (ugi.getRealUser() != null || !ugi.hasKerberosCredentials()) {
      LOG.debug("Not issuing a Vault delegation token for {}: user {} is a "
          + "proxy user or has no Kerberos credentials",
          connInfo.getServerService(), ugi.getUserName());
      return null;
    }
    Token<?> token = new KerberosVaultAuth(conf, connInfo,
        VaultAuthRequests.mountPath(conf), ugi)
        .getDelegationToken(httpClient, renewer);
    LOG.info("Obtained Vault delegation token {} with renewer {}", token,
        renewer);
    return token;
  }

  private static void initClientCache(Configuration conf) {
    if (clientCache == null) {
      synchronized (VaultCredentialProvider.class) {
        if (clientCache == null) {
          int maxSize = conf.getInt(
              VaultCredentialProviderConfig.CLIENT_CACHE_MAX_SIZE_KEY,
              VaultCredentialProviderConfig.CLIENT_CACHE_MAX_SIZE_DEFAULT);
          clientCache = CacheBuilder.newBuilder()
              .maximumSize(maxSize)
              .removalListener(notification -> {
                VaultHttpClient c =
                    (VaultHttpClient) notification.getValue();
                if (c != null) {
                  c.close();
                }
              })
              .build();
        }
      }
    }
  }

  private static void initCredentialCache(Configuration conf) {
    if (credentialCache == null) {
      synchronized (VaultCredentialProvider.class) {
        if (credentialCache == null) {
          long ttlMs = conf.getLong(
              VaultCredentialProviderConfig.CACHE_TTL_MS_KEY,
              VaultCredentialProviderConfig.CACHE_TTL_MS_DEFAULT);
          int maxSize = conf.getInt(
              VaultCredentialProviderConfig.CACHE_MAX_SIZE_KEY,
              VaultCredentialProviderConfig.CACHE_MAX_SIZE_DEFAULT);
          credentialCache = CacheBuilder.newBuilder()
              .expireAfterWrite(ttlMs, TimeUnit.MILLISECONDS)
              .maximumSize(maxSize)
              .build();
        }
      }
    }
  }

  @Override
  public CredentialEntry getCredentialEntry(String alias) throws IOException {
    if (alias == null || alias.isEmpty()) {
      return null;
    }
    String dataPath = connInfo.buildDataPath(alias);

    if (cacheEnabled) {
      String cached = credentialCache.getIfPresent(cacheKey(dataPath));
      if (cached != null) {
        LOG.debug("Credential cache hit for {}", alias);
        return newCredentialEntry(alias, cached.toCharArray());
      }
    }

    String value = httpClient.readSecret(dataPath, connInfo.getSecretKey());
    if (value == null) {
      return null;
    }

    if (cacheEnabled) {
      credentialCache.put(cacheKey(dataPath), value);
    }
    return newCredentialEntry(alias, value.toCharArray());
  }

  @Override
  public List<String> getAliases() throws IOException {
    String metadataPath = connInfo.buildMetadataPath();
    return httpClient.listSecrets(metadataPath);
  }

  @Override
  public CredentialEntry createCredentialEntry(String name, char[] credential)
      throws IOException {
    if (name == null || name.isEmpty()) {
      throw new IOException("Credential alias must not be null or empty");
    }
    // Check if already exists
    CredentialEntry existing = getCredentialEntry(name);
    if (existing != null) {
      throw new IOException("Credential " + name
          + " already exists in " + this);
    }

    String dataPath = connInfo.buildDataPath(name);
    String value = new String(credential);
    httpClient.writeSecret(dataPath, connInfo.getSecretKey(), value);

    invalidateForAllIdentities(dataPath);
    if (cacheEnabled) {
      credentialCache.put(cacheKey(dataPath), value);
    }
    return newCredentialEntry(name, credential);
  }

  @Override
  public void deleteCredentialEntry(String name) throws IOException {
    if (name == null || name.isEmpty()) {
      throw new IOException("Credential alias must not be null or empty");
    }
    // Check if exists
    CredentialEntry existing = getCredentialEntry(name);
    if (existing == null) {
      throw new IOException("Credential " + name
          + " does not exist in " + this);
    }

    String metadataPath = connInfo.buildMetadataPath(name);
    httpClient.deleteSecret(metadataPath);

    invalidateForAllIdentities(connInfo.buildDataPath(name));
  }

  @Override
  public void flush() throws IOException {
    // All operations are immediate; nothing to flush.
  }

  @Override
  public boolean isTransient() {
    return false;
  }

  @Override
  public String toString() {
    return uri.toString();
  }

  private CredentialKey cacheKey(String path) {
    return new CredentialKey(identity, connInfo.getBaseUrl(), path,
        connInfo.getSecretKey());
  }

  /**
   * A write or a delete changes what Vault serves to every identity, not
   * just to this caller, so all of their entries go. Runs whether or not
   * this provider caches: the entries belong to the JVM.
   */
  private void invalidateForAllIdentities(String path) {
    Cache<CredentialKey, String> cache = credentialCache;
    if (cache != null) {
      cache.asMap().keySet().removeIf(key -> key.isAlias(
          connInfo.getBaseUrl(), path, connInfo.getSecretKey()));
    }
  }

  /** One alias, as read by one identity. */
  private static final class CredentialKey {
    private final VaultClientIdentity identity;
    private final String baseUrl;
    private final String path;
    private final String secretKey;

    CredentialKey(VaultClientIdentity identity, String baseUrl, String path,
        String secretKey) {
      this.identity = identity;
      this.baseUrl = baseUrl;
      this.path = path;
      this.secretKey = secretKey;
    }

    boolean isAlias(String otherBaseUrl, String otherPath,
        String otherSecretKey) {
      return baseUrl.equals(otherBaseUrl) && path.equals(otherPath)
          && secretKey.equals(otherSecretKey);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof CredentialKey)) {
        return false;
      }
      CredentialKey that = (CredentialKey) o;
      return identity.equals(that.identity)
          && isAlias(that.baseUrl, that.path, that.secretKey);
    }

    @Override
    public int hashCode() {
      return Objects.hash(identity, baseUrl, path, secretKey);
    }
  }

  /**
   * Clear all static caches. Package-private, for testing only.
   */
  static void clearCaches() {
    if (clientCache != null) {
      clientCache.invalidateAll();
      clientCache = null;
    }
    if (credentialCache != null) {
      credentialCache.invalidateAll();
      credentialCache = null;
    }
  }

  /**
   * Factory for creating VaultCredentialProvider instances.
   */
  public static class Factory extends CredentialProviderFactory {

    @Override
    public CredentialProvider createProvider(URI providerName,
        Configuration conf) throws IOException {
      if (SCHEME_NAME.equals(providerName.getScheme())) {
        return new VaultCredentialProvider(providerName, conf);
      }
      return null;
    }
  }
}
