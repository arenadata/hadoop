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

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.ssl.SSLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP client of the Vault/OpenBao KV v2 API over {@link HttpURLConnection}.
 * Transport failures and 5xx or 429 responses are retried at a fixed
 * interval, except for a request Vault may already have applied; a 401 or
 * 403 gets one re-authentication.
 */
@InterfaceAudience.Private
public class VaultHttpClient implements Closeable {

  private static final Logger LOG =
      LoggerFactory.getLogger(VaultHttpClient.class);

  private static final String VAULT_TOKEN_HEADER = "X-Vault-Token";
  private static final String CONTENT_TYPE_JSON = "application/json";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final VaultAuthMethod authMethod;
  private final VaultConnectionInfo connInfo;
  private final int connectTimeoutMs;
  private final int readTimeoutMs;
  private final int retryCount;
  private final int retryIntervalMs;
  private final SSLFactory sslFactory;
  private final SSLSocketFactory sslSocketFactory;
  private final AtomicInteger requestsInFlight = new AtomicInteger();
  private final AtomicBoolean destroyed = new AtomicBoolean();
  private final Object loginLock = new Object();
  private volatile boolean closeRequested;
  private volatile String clientToken;

  /**
   * Create a new VaultHttpClient.
   *
   * @param conf the Hadoop configuration
   * @param connInfo the Vault connection info
   * @param authMethod the authentication method
   * @throws IOException if initialization fails
   */
  public VaultHttpClient(Configuration conf, VaultConnectionInfo connInfo,
      VaultAuthMethod authMethod) throws IOException {
    this(conf, connInfo, authMethod, true);
  }

  /**
   * Client for requests that carry their own credentials, such as the
   * SPNEGO delegation token calls. It cannot read or write secrets.
   */
  static VaultHttpClient unauthenticated(Configuration conf,
      VaultConnectionInfo connInfo) throws IOException {
    return new VaultHttpClient(conf, connInfo, null, false);
  }

  private VaultHttpClient(Configuration conf, VaultConnectionInfo connInfo,
      VaultAuthMethod authMethod, boolean authenticate) throws IOException {
    this.connInfo = connInfo;
    this.authMethod = authMethod;
    this.connectTimeoutMs = setting(conf,
        VaultCredentialProviderConfig.CONNECTION_TIMEOUT_MS_KEY,
        VaultCredentialProviderConfig.CONNECTION_TIMEOUT_MS_DEFAULT);
    this.readTimeoutMs = setting(conf,
        VaultCredentialProviderConfig.READ_TIMEOUT_MS_KEY,
        VaultCredentialProviderConfig.READ_TIMEOUT_MS_DEFAULT);
    this.retryCount = setting(conf,
        VaultCredentialProviderConfig.RETRY_COUNT_KEY,
        VaultCredentialProviderConfig.RETRY_COUNT_DEFAULT);
    this.retryIntervalMs = setting(conf,
        VaultCredentialProviderConfig.RETRY_INTERVAL_MS_KEY,
        VaultCredentialProviderConfig.RETRY_INTERVAL_MS_DEFAULT);

    if ("https".equalsIgnoreCase(connInfo.getProtocol())) {
      this.sslFactory = createSslFactory(conf);
      this.sslSocketFactory = createSslSocketFactory(conf, sslFactory);
    } else {
      this.sslFactory = null;
      this.sslSocketFactory = null;
    }

    try {
      this.clientToken = authenticate ? authMethod.authenticate(this) : null;
    } catch (IOException | RuntimeException e) {
      close();
      throw e;
    }
  }

  VaultHttpClient(VaultConnectionInfo connInfo, VaultAuthMethod authMethod,
      int connectTimeoutMs, int readTimeoutMs,
      int retryCount, int retryIntervalMs) throws IOException {
    this.connInfo = connInfo;
    this.authMethod = authMethod;
    this.connectTimeoutMs = connectTimeoutMs;
    this.readTimeoutMs = readTimeoutMs;
    this.retryCount = retryCount;
    this.retryIntervalMs = retryIntervalMs;
    this.sslFactory = null;
    this.sslSocketFactory = null;
    this.clientToken = authMethod.authenticate(this);
  }

  private static int setting(Configuration conf, String key,
      int defaultValue) throws IOException {
    long value = VaultCredentialProviderConfig.nonNegativeNumber(conf, key,
        defaultValue);
    if (value > Integer.MAX_VALUE) {
      throw new IOException(key + " is too large: " + value);
    }
    return (int) value;
  }

  private static SSLFactory createSslFactory(Configuration conf)
      throws IOException {
    if (!conf.getTrimmed(
        VaultCredentialProviderConfig.SSL_TRUSTSTORE_LOCATION_KEY, "")
        .isEmpty()) {
      return null;
    }
    SSLFactory factory = new SSLFactory(SSLFactory.Mode.CLIENT, conf);
    try {
      factory.init();
      LOG.debug("Using Hadoop SSLFactory for Vault connection");
      return factory;
    } catch (GeneralSecurityException | IOException e) {
      factory.destroy();
      throw new IOException("Failed to initialize SSL for Vault", e);
    }
  }

  private static SSLSocketFactory createSslSocketFactory(
      Configuration conf, SSLFactory factory) throws IOException {
    if (factory != null) {
      try {
        return factory.createSSLSocketFactory();
      } catch (GeneralSecurityException e) {
        factory.destroy();
        throw new IOException(
            "Failed to create SSLSocketFactory for Vault", e);
      }
    }
    LOG.debug("Using dedicated vault SSL configuration");
    try {
      return buildSslContext(conf).getSocketFactory();
    } catch (GeneralSecurityException e) {
      throw new IOException(
          "Failed to build SSLContext from vault.ssl.* config", e);
    }
  }

  private static SSLContext buildSslContext(Configuration conf)
      throws IOException, GeneralSecurityException {
    String truststoreLocation = conf.getTrimmed(
        VaultCredentialProviderConfig.SSL_TRUSTSTORE_LOCATION_KEY);
    String truststorePassword = conf.getTrimmed(
        VaultCredentialProviderConfig.SSL_TRUSTSTORE_PASSWORD_KEY, "");
    String truststoreType = conf.getTrimmed(
        VaultCredentialProviderConfig.SSL_TRUSTSTORE_TYPE_KEY,
        VaultCredentialProviderConfig.SSL_TRUSTSTORE_TYPE_DEFAULT);

    KeyStore truststore = KeyStore.getInstance(truststoreType);
    try (FileInputStream fis = new FileInputStream(truststoreLocation)) {
      // A truststore password is only an integrity check; none skips it.
      truststore.load(fis, truststorePassword.isEmpty() ? null
          : truststorePassword.toCharArray());
    }
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(truststore);

    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, tmf.getTrustManagers(), null);
    return sslContext;
  }

  /**
   * Read one field of a secret as text.
   *
   * @param dataPath the KV v2 data path
   * @param secretKey the key within the secret's data map
   * @return the field, or null if the secret or the field does not exist
   * @throws IOException if the request fails or the field is not a scalar
   */
  public String readSecret(String dataPath, String secretKey)
      throws IOException {
    Secret secret = readSecretFields(dataPath);
    Object value = secret == null ? null : secret.getFields().get(secretKey);
    if (value == null) {
      return null;
    }
    if (value instanceof String) {
      return (String) value;
    }
    if (value instanceof Number || value instanceof Boolean) {
      return value.toString();
    }
    throw new IOException("Field " + secretKey + " of " + dataPath
        + " is not a string");
  }

  /**
   * Read every field of a secret and the version they belong to.
   *
   * @param dataPath the KV v2 data path
   * @return the secret, or null if it does not exist; a secret whose
   *     current version is deleted has no fields but keeps its version
   * @throws IOException if the request fails
   */
  Secret readSecretFields(String dataPath) throws IOException {
    Response response = executeWithRetry("GET",
        connInfo.getApiUrl(dataPath), null, true, true);
    if (response.getStatus() == HttpURLConnection.HTTP_NOT_FOUND) {
      return notFound(response.getBody());
    }

    VaultResponse.KvRead read = MAPPER.readValue(response.getBody(),
        VaultResponse.KvRead.class);
    if (read.data == null || read.data.data == null) {
      return null;
    }
    return new Secret(read.data.data,
        read.data.metadata == null ? 0 : read.data.metadata.version);
  }

  /**
   * A KV v2 404 is one of three things: a secret that does not exist
   * (no errors), a secret whose current version is deleted or destroyed
   * (metadata without data; a write must name that version), or a path no
   * engine serves (errors).
   */
  private static Secret notFound(String body) throws IOException {
    if (body == null || body.trim().isEmpty()) {
      return null;
    }
    JsonNode tree;
    try {
      tree = MAPPER.readTree(body);
    } catch (IOException e) {
      throw new RequestFailedException(HttpURLConnection.HTTP_NOT_FOUND,
          "Vault request failed with status 404: " + body);
    }
    JsonNode errors = tree.path("errors");
    if (errors.isArray() && errors.size() > 0) {
      throw new RequestFailedException(HttpURLConnection.HTTP_NOT_FOUND,
          "Vault request failed with status 404: " + body);
    }
    JsonNode version = tree.path("data").path("metadata").path("version");
    return version.canConvertToInt()
        ? new Secret(Collections.emptyMap(), version.asInt()) : null;
  }

  /** The fields of one KV v2 secret, as of one version. */
  static final class Secret {
    private final Map<String, Object> fields;
    private final int version;

    Secret(Map<String, Object> fields, int version) {
      this.fields = Collections.unmodifiableMap(new HashMap<>(fields));
      this.version = version;
    }

    Map<String, Object> getFields() {
      return fields;
    }

    int getVersion() {
      return version;
    }
  }

  /**
   * List the keys directly under a metadata path; a key ending in a slash
   * is a directory.
   *
   * @param metadataPath the KV v2 metadata path
   * @return the keys, empty if the path does not exist
   * @throws IOException if the request fails
   */
  public List<String> listSecrets(String metadataPath) throws IOException {
    Response response = executeWithRetry("GET",
        connInfo.getApiUrl(metadataPath) + "?list=true", null, true, true);
    if (response.getStatus() == HttpURLConnection.HTTP_NOT_FOUND) {
      notFound(response.getBody());
      return Collections.emptyList();
    }

    VaultResponse.KvList list = MAPPER.readValue(response.getBody(),
        VaultResponse.KvList.class);
    if (list.data == null || list.data.keys == null) {
      return Collections.emptyList();
    }
    return list.data.keys;
  }

  /**
   * Replace every field of a secret. A KV v2 write replaces the whole
   * secret, so the caller passes the fields it wants to keep; the version
   * it read them from is sent as a check-and-set, so a write that raced
   * another writer fails instead of dropping their fields.
   *
   * @param dataPath the KV v2 data path
   * @param fields the fields the new version holds
   * @param version the version the fields were read from, 0 to create
   * @throws IOException if the request fails
   */
  void writeSecret(String dataPath, Map<String, Object> fields, int version)
      throws IOException {
    Map<String, Object> options = new HashMap<>();
    options.put("cas", version);
    Map<String, Object> body = new HashMap<>();
    body.put("data", fields);
    body.put("options", options);

    executeWithRetry("POST", connInfo.getApiUrl(dataPath),
        MAPPER.writeValueAsString(body), false, false);
  }

  /**
   * Delete a secret from Vault, every version of it.
   *
   * @param metadataPath the KV v2 metadata path for the alias
   * @throws IOException if the request fails
   */
  public void deleteSecret(String metadataPath) throws IOException {
    executeWithRetry("DELETE", connInfo.getApiUrl(metadataPath), null, true,
        false);
  }

  private Response executeWithRetry(String method, String url,
      String jsonBody, boolean idempotent, boolean allowNotFound)
      throws IOException {
    if (authMethod == null) {
      throw new IOException("Vault client for " + connInfo.getBaseUrl()
          + " has no auth method");
    }
    requestsInFlight.incrementAndGet();
    try {
      return execute(method, url, jsonBody, idempotent, allowNotFound);
    } finally {
      requestsInFlight.decrementAndGet();
      destroyIfIdle();
    }
  }

  private Response execute(String method, String url, String jsonBody,
      boolean idempotent, boolean allowNotFound) throws IOException {
    String action = "Vault request " + method + " " + url;
    boolean reauthenticated = false;
    IOException lastFailure = null;
    int attempt = 0;
    while (true) {
      String token = clientToken;
      Response response;
      try {
        response = send(method, url, token, jsonBody, idempotent);
      } catch (IOException e) {
        if (!isTransient(e)) {
          throw e;
        }
        response = null;
        lastFailure = e;
        LOG.warn("{} failed (attempt {}/{}): {}", action, attempt + 1,
            retryCount + 1, e.getMessage());
      }

      if (response != null) {
        int status = response.getStatus();
        if (status == HttpURLConnection.HTTP_OK
            || status == HttpURLConnection.HTTP_NO_CONTENT
            || (status == HttpURLConnection.HTTP_NOT_FOUND && allowNotFound)) {
          return response;
        }
        if (status == HttpURLConnection.HTTP_UNAUTHORIZED
            || status == HttpURLConnection.HTTP_FORBIDDEN) {
          if (reauthenticated) {
            throw response.failure();
          }
          reauthenticated = true;
          LOG.debug("{} answered {}, re-authenticating", action, status);
          reauthenticate(token);
          continue;
        }
        RequestFailedException failure = response.failure();
        if (!failure.isTransient()) {
          throw failure;
        }
        lastFailure = failure;
        LOG.warn("{} failed (attempt {}/{}): {}", action, attempt + 1,
            retryCount + 1, failure.getMessage());
      }

      if (attempt >= retryCount) {
        throw new IOException(action + " failed after " + (attempt + 1)
            + " attempts", lastFailure);
      }
      attempt++;
      sleep(retryIntervalMs);
    }
  }

  /**
   * Log in again, unless another thread already replaced the token that
   * was refused.
   */
  private void reauthenticate(String refusedToken) throws IOException {
    synchronized (loginLock) {
      if (clientToken == refusedToken) {
        clientToken = authMethod.authenticate(this);
      }
    }
  }

  /**
   * Run a request that is safe to repeat, retrying transient failures on
   * this client's budget.
   */
  <T> T retrying(String action, RetriableCall<T> call) throws IOException {
    IOException lastFailure = null;
    for (int attempt = 0; ; attempt++) {
      if (attempt > 0) {
        sleep(retryIntervalMs);
      }
      try {
        return call.call();
      } catch (IOException e) {
        if (!isTransient(e)) {
          throw e;
        }
        lastFailure = e;
        LOG.warn("{} failed (attempt {}/{}): {}", action, attempt + 1,
            retryCount + 1, e.getMessage());
        if (attempt >= retryCount) {
          throw new IOException(action + " failed after " + (attempt + 1)
              + " attempts", lastFailure);
        }
      }
    }
  }

  /** A request that may be repeated. */
  interface RetriableCall<T> {
    T call() throws IOException;
  }

  private static boolean isTransient(IOException e) {
    return e instanceof SocketException
        || e instanceof SocketTimeoutException
        || e instanceof UnknownHostException
        || (e instanceof RequestFailedException
            && ((RequestFailedException) e).isTransient());
  }

  private static void sleep(long ms) throws IOException {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Retry interrupted", e);
    }
  }

  /**
   * One request. A failure after the request was handed to the connection
   * is not retriable for a request that is not idempotent: Vault may have
   * applied it.
   */
  private Response send(String method, String url, String token,
      String jsonBody, boolean idempotent) throws IOException {
    HttpURLConnection conn = createConnection(url, method);
    conn.setRequestProperty(VAULT_TOKEN_HEADER, token);
    if (jsonBody != null) {
      conn.setDoOutput(true);
      conn.setRequestProperty("Content-Type", CONTENT_TYPE_JSON);
    }
    conn.connect();
    try {
      if (jsonBody != null) {
        try (OutputStream os = conn.getOutputStream()) {
          os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }
      }
      int status = conn.getResponseCode();
      String body = status >= HttpURLConnection.HTTP_BAD_REQUEST
          ? readErrorBody(conn) : readResponseBody(conn);
      return new Response(status, body);
    } catch (IOException e) {
      conn.disconnect();
      if (idempotent) {
        throw e;
      }
      throw new IOException(method + " " + url
          + " was sent but got no response; not repeated", e);
    }
  }

  /**
   * Open an HTTP(S) connection to Vault with configured timeouts and SSL.
   */
  HttpURLConnection createConnection(String urlString, String method)
      throws IOException {
    URL url = new URL(urlString);
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();

    conn.setRequestMethod(method);
    conn.setConnectTimeout(connectTimeoutMs);
    conn.setReadTimeout(readTimeoutMs);
    conn.setUseCaches(false);

    if (sslSocketFactory != null && conn instanceof HttpsURLConnection) {
      HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
      httpsConn.setSSLSocketFactory(sslSocketFactory);
      if (sslFactory != null) {
        httpsConn.setHostnameVerifier(sslFactory.getHostnameVerifier());
      }
    }

    return conn;
  }

  private static String readResponseBody(HttpURLConnection conn)
      throws IOException {
    InputStream is = conn.getInputStream();
    if (is == null) {
      return "";
    }
    try {
      return IOUtils.toString(is, StandardCharsets.UTF_8);
    } finally {
      is.close();
    }
  }

  static String readErrorBody(HttpURLConnection conn) {
    try {
      InputStream es = conn.getErrorStream();
      if (es == null) {
        return "";
      }
      try {
        return IOUtils.toString(es, StandardCharsets.UTF_8);
      } finally {
        es.close();
      }
    } catch (IOException e) {
      return "";
    }
  }

  /** A response Vault sent: status and body. */
  private static final class Response {
    private final int status;
    private final String body;

    Response(int status, String body) {
      this.status = status;
      this.body = body;
    }

    int getStatus() {
      return status;
    }

    String getBody() {
      return body;
    }

    RequestFailedException failure() {
      return new RequestFailedException(status,
          "Vault request failed with status " + status + ": " + body);
    }
  }

  /** A response with a status the caller cannot use. */
  static final class RequestFailedException extends IOException {
    private static final long serialVersionUID = 1L;
    private final int status;

    RequestFailedException(int status, String message) {
      super(message);
      this.status = status;
    }

    int getStatus() {
      return status;
    }

    /** Whether a later attempt may succeed: the server is busy or down. */
    boolean isTransient() {
      return status >= HttpURLConnection.HTTP_INTERNAL_ERROR || status == 429;
    }
  }

  /**
   * Release the SSL machinery once no request is using it. The client is
   * closed when the cache evicts it, which can happen while another
   * thread is mid-request with the instance it was handed.
   */
  @Override
  public void close() {
    closeRequested = true;
    destroyIfIdle();
  }

  private void destroyIfIdle() {
    if (closeRequested && requestsInFlight.get() == 0
        && destroyed.compareAndSet(false, true)) {
      if (sslFactory != null) {
        sslFactory.destroy();
      }
    }
  }
}
