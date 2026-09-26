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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.hadoop.security.token.DelegationTokenIssuer;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.thirdparty.com.google.common.base.Ticker;
import org.apache.hadoop.thirdparty.com.google.common.cache.Cache;
import org.apache.hadoop.thirdparty.com.google.common.cache.CacheBuilder;
import org.apache.hadoop.thirdparty.com.google.common.util.concurrent.ExecutionError;
import org.apache.hadoop.thirdparty.com.google.common.util.concurrent.UncheckedExecutionException;
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
 *       identity that authenticated it. A client is built on first use
 *       and dropped once its identity has gone idle.</li>
 *   <li><b>Credential cache</b> — a Guava {@link Cache} with
 *       {@code expireAfterWrite} TTL, to avoid repeated HTTP round-trips
 *       for the same alias within the same JVM. Entries belong to the
 *       identity that read them; an alias found absent or denied by the
 *       policy is remembered for a shorter TTL; writes and deletes drop
 *       the alias for every identity.</li>
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

  /** Aliases an identity found absent or denied, held for the negative TTL. */
  private static volatile Cache<CredentialKey, Boolean> missCache;

  /** Settings the JVM-wide caches were built with, by property. */
  private static final Map<String, Long> CACHE_SETTINGS =
      new ConcurrentHashMap<>();
  private static final Set<String> WARNED_CACHE_SETTINGS =
      ConcurrentHashMap.newKeySet();

  /** The clock the client cache ages entries by. For testing. */
  private static volatile Ticker clientCacheTicker = Ticker.systemTicker();

  /** Identities whose client this thread is building. */
  private static final ThreadLocal<Set<VaultClientIdentity>> BUILDING =
      ThreadLocal.withInitial(HashSet::new);

  private final URI uri;
  private final VaultConnectionInfo connInfo;
  /** Set by the test constructors only; otherwise the client cache. */
  private final VaultHttpClient suppliedClient;
  private final boolean cacheEnabled;
  private final Configuration conf;
  /** Resolved on first use: only then are the caller's credentials needed. */
  private volatile VaultClientIdentity identity;

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
    warnOnIgnoredCacheSettings(conf);
    this.suppliedClient = null;

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
   * Package-private constructor for testing a given identity. The
   * negative cache shares the TTL of the credential cache.
   */
  VaultCredentialProvider(URI uri, VaultConnectionInfo connInfo,
      VaultHttpClient httpClient, boolean cacheEnabled, long cacheTtlMs,
      VaultClientIdentity identity) {
    this.uri = uri;
    this.conf = new Configuration(false);
    this.connInfo = connInfo;
    this.suppliedClient = httpClient;
    this.cacheEnabled = cacheEnabled;
    this.identity = identity;
    if (cacheEnabled && credentialCache == null) {
      buildCredentialCaches(cacheTtlMs, cacheTtlMs,
          VaultCredentialProviderConfig.CACHE_MAX_SIZE_DEFAULT);
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
   * Obtain a delegation token owned by the current user, who must hold a
   * Kerberos login of their own. Returns null when this provider uses
   * token auth, when delegation tokens are disabled, when the current
   * user is a proxy user or when they have no Kerberos login: tokens are
   * never issued in the name of the dedicated keytab principal.
   */
  @Override
  public Token<?> getDelegationToken(String renewer) throws IOException {
    String service = connInfo.getServerService();
    if (!conf.getBoolean(
        VaultCredentialProviderConfig.DELEGATION_TOKEN_ENABLED_KEY,
        VaultCredentialProviderConfig.DELEGATION_TOKEN_ENABLED_DEFAULT)) {
      LOG.debug("Not issuing a Vault delegation token for {}: disabled",
          service);
      return null;
    }
    if (VaultCredentialProviderConfig.AUTH_METHOD_TOKEN
        .equalsIgnoreCase(VaultCredentialProviderConfig.authMethod(conf))) {
      LOG.debug("Not issuing a Vault delegation token for {}: auth method is "
          + "token", service);
      return null;
    }
    UserGroupInformation ugi = UserGroupInformation.getCurrentUser();
    if (ugi.getRealUser() != null) {
      LOG.info("Not issuing a Vault delegation token for {} to {}: a proxy "
          + "user cannot own one", service, ugi.getUserName());
      return null;
    }
    if (!ugi.shouldRelogin()) {
      LOG.info("Not issuing a Vault delegation token for {} to {}: the user "
          + "has no Kerberos login", service, ugi.getUserName());
      return null;
    }
    String recordedRenewer = conf.getBoolean(
        VaultCredentialProviderConfig.DELEGATION_TOKEN_RENEWABLE_KEY,
        VaultCredentialProviderConfig.DELEGATION_TOKEN_RENEWABLE_DEFAULT)
        ? renewer : null;
    // The request authenticates itself over SPNEGO.
    Token<?> token;
    VaultHttpClient client =
        VaultHttpClient.unauthenticated(conf, connInfo);
    try {
      token = new KerberosVaultAuth(conf, connInfo,
          VaultAuthRequests.mountPath(conf), ugi)
          .getDelegationToken(client, recordedRenewer);
    } finally {
      client.close();
    }
    LOG.info("Obtained Vault delegation token {} with renewer {}", token,
        recordedRenewer);
    return token;
  }

  private VaultClientIdentity identity() throws IOException {
    VaultClientIdentity resolved = identity;
    if (resolved == null) {
      synchronized (this) {
        resolved = identity;
        if (resolved == null) {
          try {
            resolved = VaultClientIdentity.of(conf, connInfo);
          } catch (IOException e) {
            throw new IOException("Failed to resolve the Vault identity for "
                + connInfo.getBaseUrl(), e);
          }
          identity = resolved;
        }
      }
    }
    return resolved;
  }

  /**
   * The client authenticated for this provider's identity, built on first
   * use. Providers are constructed under the global serviceLoader lock of
   * CredentialProviderFactory, which the Kerberos and the Vault login must
   * not hold.
   */
  private VaultHttpClient client() throws IOException {
    if (suppliedClient != null) {
      return suppliedClient;
    }
    VaultClientIdentity self = identity();
    Set<VaultClientIdentity> building = BUILDING.get();
    if (!building.add(self)) {
      throw new IOException("Building the Vault client for " + self
          + " needs a credential this same provider would serve");
    }
    try {
      return clientCache.get(self, () ->
          new VaultHttpClient(conf, connInfo,
              self.createAuthMethod(conf, connInfo)));
    } catch (ExecutionException | UncheckedExecutionException
        | ExecutionError e) {
      throw new IOException("Failed to create VaultHttpClient for "
          + connInfo.getBaseUrl(), e.getCause());
    } finally {
      building.remove(self);
      if (building.isEmpty()) {
        BUILDING.remove();
      }
    }
  }

  private static void initClientCache(Configuration conf)
      throws IOException {
    if (clientCache == null) {
      synchronized (VaultCredentialProvider.class) {
        if (clientCache == null) {
          long maxSize = VaultCredentialProviderConfig.positiveNumber(conf,
              VaultCredentialProviderConfig.CLIENT_CACHE_MAX_SIZE_KEY,
              VaultCredentialProviderConfig.CLIENT_CACHE_MAX_SIZE_DEFAULT);
          long idleMs = VaultCredentialProviderConfig.nonNegativeNumber(conf,
              VaultCredentialProviderConfig.CLIENT_CACHE_IDLE_MS_KEY,
              VaultCredentialProviderConfig.CLIENT_CACHE_IDLE_MS_DEFAULT);
          recordCacheSetting(
              VaultCredentialProviderConfig.CLIENT_CACHE_MAX_SIZE_KEY, maxSize);
          recordCacheSetting(
              VaultCredentialProviderConfig.CLIENT_CACHE_IDLE_MS_KEY, idleMs);
          CacheBuilder<Object, Object> builder = CacheBuilder.newBuilder()
              .ticker(clientCacheTicker)
              .maximumSize(maxSize)
              .removalListener(notification -> {
                VaultHttpClient c =
                    (VaultHttpClient) notification.getValue();
                if (c != null) {
                  c.close();
                }
              });
          if (idleMs > 0) {
            builder.expireAfterAccess(idleMs, TimeUnit.MILLISECONDS);
          }
          clientCache = builder.build();
        }
      }
    }
  }

  private static void initCredentialCache(Configuration conf)
      throws IOException {
    if (credentialCache == null) {
      synchronized (VaultCredentialProvider.class) {
        if (credentialCache == null) {
          long ttlMs = VaultCredentialProviderConfig.positiveNumber(conf,
              VaultCredentialProviderConfig.CACHE_TTL_MS_KEY,
              VaultCredentialProviderConfig.CACHE_TTL_MS_DEFAULT);
          long negativeTtlMs = VaultCredentialProviderConfig.nonNegativeNumber(
              conf, VaultCredentialProviderConfig.CACHE_NEGATIVE_TTL_MS_KEY,
              VaultCredentialProviderConfig.CACHE_NEGATIVE_TTL_MS_DEFAULT);
          long maxSize = VaultCredentialProviderConfig.positiveNumber(conf,
              VaultCredentialProviderConfig.CACHE_MAX_SIZE_KEY,
              VaultCredentialProviderConfig.CACHE_MAX_SIZE_DEFAULT);
          buildCredentialCaches(ttlMs, negativeTtlMs, maxSize);
        }
      }
    }
  }

  private static void buildCredentialCaches(long ttlMs, long negativeTtlMs,
      long maxSize) {
    recordCacheSetting(VaultCredentialProviderConfig.CACHE_TTL_MS_KEY, ttlMs);
    recordCacheSetting(VaultCredentialProviderConfig.CACHE_NEGATIVE_TTL_MS_KEY,
        negativeTtlMs);
    recordCacheSetting(VaultCredentialProviderConfig.CACHE_MAX_SIZE_KEY,
        maxSize);
    missCache = negativeTtlMs > 0 ? CacheBuilder.newBuilder()
        .expireAfterWrite(negativeTtlMs, TimeUnit.MILLISECONDS)
        .maximumSize(maxSize)
        .build() : null;
    credentialCache = CacheBuilder.newBuilder()
        .expireAfterWrite(ttlMs, TimeUnit.MILLISECONDS)
        .maximumSize(maxSize)
        .build();
  }

  private static void recordCacheSetting(String key, long value) {
    CACHE_SETTINGS.put(key, value);
  }

  /**
   * The caches are JVM-wide and keep the settings of the configuration
   * that built them, so a later one asking for different values gets the
   * values already in force. Report each such property once, and only
   * where this configuration sets it itself: the defaults it inherits
   * from core-default.xml are nobody's request.
   */
  private static void warnOnIgnoredCacheSettings(Configuration conf) {
    CACHE_SETTINGS.forEach((key, inForce) -> {
      if (!VaultCredentialProviderConfig.isSetByUser(conf, key)) {
        return;
      }
      long asked;
      try {
        asked = VaultCredentialProviderConfig.number(conf, key, inForce);
      } catch (IOException e) {
        if (WARNED_CACHE_SETTINGS.add(key)) {
          LOG.warn("{} is ignored: {}", key, e.getMessage());
        }
        return;
      }
      if (asked != inForce && WARNED_CACHE_SETTINGS.add(key)) {
        LOG.warn("{}={} is ignored: the JVM-wide Vault cache it configures "
            + "was built with {}", key, asked, inForce);
      }
    });
  }

  @Override
  public CredentialEntry getCredentialEntry(String alias) throws IOException {
    if (!VaultConnectionInfo.isValidAlias(alias)) {
      return null;
    }
    String dataPath = connInfo.buildDataPath(alias);

    if (cacheEnabled) {
      CredentialKey key = cacheKey(dataPath);
      String cached = credentialCache.getIfPresent(key);
      if (cached != null) {
        LOG.debug("Credential cache hit for {}", alias);
        return newCredentialEntry(alias, cached.toCharArray());
      }
      Cache<CredentialKey, Boolean> misses = missCache;
      if (misses != null && misses.getIfPresent(key) != null) {
        LOG.debug("Credential cache hit for absent {}", alias);
        return null;
      }
    }

    String value = readSecret(dataPath);
    if (value == null) {
      Cache<CredentialKey, Boolean> misses = missCache;
      if (cacheEnabled && misses != null) {
        misses.put(cacheKey(dataPath), Boolean.TRUE);
      }
      return null;
    }

    if (cacheEnabled) {
      credentialCache.put(cacheKey(dataPath), value);
    }
    return newCredentialEntry(alias, value.toCharArray());
  }

  @Override
  public List<String> getAliases() throws IOException {
    List<String> aliases = new ArrayList<>();
    collectAliases(connInfo.buildMetadataPath(), "", aliases);
    return aliases;
  }

  /** A KV v2 list is one level deep; aliases may hold slashes. */
  private void collectAliases(String metadataPath, String prefix,
      List<String> aliases) throws IOException {
    for (String key : client().listSecrets(metadataPath)) {
      if (key.endsWith("/")) {
        String dir = key.substring(0, key.length() - 1);
        collectAliases(metadataPath + "/" + dir, prefix + key, aliases);
      } else {
        aliases.add(prefix + key);
      }
    }
  }

  @Override
  public CredentialEntry createCredentialEntry(String name, char[] credential)
      throws IOException {
    VaultConnectionInfo.checkAlias(name);
    String dataPath = connInfo.buildDataPath(name);
    VaultHttpClient.Secret current = client().readSecretFields(dataPath);
    if (current != null
        && current.getFields().get(connInfo.getSecretKey()) != null) {
      invalidateForAllIdentities(dataPath);
      throw new IOException("Credential " + name
          + " already exists in " + this);
    }

    String value = new String(credential);
    Map<String, Object> fields = current == null
        ? new HashMap<>() : new HashMap<>(current.getFields());
    fields.put(connInfo.getSecretKey(), value);
    try {
      client().writeSecret(dataPath, fields,
          current == null ? 0 : current.getVersion());
    } finally {
      invalidateForAllIdentities(dataPath);
    }
    if (cacheEnabled) {
      credentialCache.put(cacheKey(dataPath), value);
    }
    return newCredentialEntry(name, credential);
  }

  @Override
  public void deleteCredentialEntry(String name) throws IOException {
    VaultConnectionInfo.checkAlias(name);
    String dataPath = connInfo.buildDataPath(name);
    VaultHttpClient.Secret current = client().readSecretFields(dataPath);
    if (current == null
        || current.getFields().get(connInfo.getSecretKey()) == null) {
      invalidateForAllIdentities(dataPath);
      throw new IOException("Credential " + name
          + " does not exist in " + this);
    }

    Map<String, Object> fields = new HashMap<>(current.getFields());
    fields.remove(connInfo.getSecretKey());
    try {
      if (fields.isEmpty()) {
        client().deleteSecret(connInfo.buildMetadataPath(name));
      } else {
        client().writeSecret(dataPath, fields, current.getVersion());
      }
    } finally {
      invalidateForAllIdentities(dataPath);
    }
  }

  /** Read the alias from Vault, bypassing the credential cache. */
  private String readSecret(String dataPath) throws IOException {
    return client().readSecret(dataPath, connInfo.getSecretKey());
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

  private CredentialKey cacheKey(String path) throws IOException {
    return new CredentialKey(identity(), connInfo.getBaseUrl(), path,
        connInfo.getSecretKey());
  }

  /**
   * A write or a delete changes what Vault serves to every identity, not
   * just to this caller, and a KV v2 write replaces the whole secret, so
   * the entries of every field of the alias go. Runs whether or not this
   * provider caches: the entries belong to the JVM.
   */
  private void invalidateForAllIdentities(String path) {
    Cache<CredentialKey, String> cache = credentialCache;
    if (cache != null) {
      cache.asMap().keySet().removeIf(
          key -> key.isAlias(connInfo.getBaseUrl(), path));
    }
    Cache<CredentialKey, Boolean> misses = missCache;
    if (misses != null) {
      misses.asMap().keySet().removeIf(
          key -> key.isAlias(connInfo.getBaseUrl(), path));
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

    boolean isAlias(String otherBaseUrl, String otherPath) {
      return baseUrl.equals(otherBaseUrl) && path.equals(otherPath);
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
          && isAlias(that.baseUrl, that.path)
          && secretKey.equals(that.secretKey);
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
    if (missCache != null) {
      missCache.invalidateAll();
      missCache = null;
    }
    CACHE_SETTINGS.clear();
    WARNED_CACHE_SETTINGS.clear();
    clientCacheTicker = Ticker.systemTicker();
  }

  /**
   * Set the clock the client cache ages entries by. Package-private, for
   * testing only; takes effect when the cache is next built.
   */
  static void setClientCacheTicker(Ticker ticker) {
    clientCacheTicker = ticker;
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
