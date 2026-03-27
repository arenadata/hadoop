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
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.ssl.SSLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP client for communicating with Vault/OpenBao KV v2 API.
 * Uses {@link HttpURLConnection} (lightweight, no connection pool)
 * with configurable timeouts, SSL, retry logic, and automatic
 * re-authentication on 401/403.
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
    this.connInfo = connInfo;
    this.authMethod = authMethod;
    this.connectTimeoutMs = conf.getInt(
        VaultCredentialProviderConfig.CONNECTION_TIMEOUT_MS_KEY,
        VaultCredentialProviderConfig.CONNECTION_TIMEOUT_MS_DEFAULT);
    this.readTimeoutMs = conf.getInt(
        VaultCredentialProviderConfig.READ_TIMEOUT_MS_KEY,
        VaultCredentialProviderConfig.READ_TIMEOUT_MS_DEFAULT);
    this.retryCount = conf.getInt(
        VaultCredentialProviderConfig.RETRY_COUNT_KEY,
        VaultCredentialProviderConfig.RETRY_COUNT_DEFAULT);
    this.retryIntervalMs = conf.getInt(
        VaultCredentialProviderConfig.RETRY_INTERVAL_MS_KEY,
        VaultCredentialProviderConfig.RETRY_INTERVAL_MS_DEFAULT);

    if ("https".equalsIgnoreCase(connInfo.getProtocol())) {
      this.sslFactory = createSslFactory(conf);
      this.sslSocketFactory = createSslSocketFactory(conf, sslFactory);
    } else {
      this.sslFactory = null;
      this.sslSocketFactory = null;
    }

    this.clientToken = authMethod.authenticate(this);
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

  private static SSLFactory createSslFactory(Configuration conf)
      throws IOException {
    if (conf.get(VaultCredentialProviderConfig.SSL_TRUSTSTORE_LOCATION_KEY)
        != null) {
      return null;
    }
    SSLFactory factory = new SSLFactory(SSLFactory.Mode.CLIENT, conf);
    try {
      factory.init();
      LOG.debug("Using Hadoop SSLFactory for Vault connection");
      return factory;
    } catch (GeneralSecurityException e) {
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
    String truststoreLocation = conf.get(
        VaultCredentialProviderConfig.SSL_TRUSTSTORE_LOCATION_KEY);
    String truststorePassword = conf.get(
        VaultCredentialProviderConfig.SSL_TRUSTSTORE_PASSWORD_KEY, "");
    String truststoreType = conf.get(
        VaultCredentialProviderConfig.SSL_TRUSTSTORE_TYPE_KEY,
        VaultCredentialProviderConfig.SSL_TRUSTSTORE_TYPE_DEFAULT);

    KeyStore truststore = KeyStore.getInstance(truststoreType);
    try (FileInputStream fis = new FileInputStream(truststoreLocation)) {
      truststore.load(fis, truststorePassword.toCharArray());
    }
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(truststore);

    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, tmf.getTrustManagers(), null);
    return sslContext;
  }

  /**
   * Read a secret value from Vault using the default key {@code "value"}.
   */
  public String readSecret(String dataPath) throws IOException {
    return readSecret(dataPath, VaultConnectionInfo.DEFAULT_SECRET_KEY);
  }

  /**
   * Read a secret value from Vault.
   *
   * @param dataPath the KV v2 data path
   * @param secretKey the key within the secret's data map
   * @return the secret value, or null if not found
   * @throws IOException if the request fails
   */
  public String readSecret(String dataPath, String secretKey)
      throws IOException {
    String url = connInfo.getBaseUrl() + "/v1/" + dataPath;

    String responseBody = executeWithRetry("GET", url, null, false);
    if (responseBody == null) {
      return null;
    }

    VaultResponse.KvRead response =
        MAPPER.readValue(responseBody, VaultResponse.KvRead.class);
    if (response.data == null || response.data.data == null) {
      return null;
    }
    return response.data.data.get(secretKey);
  }

  /**
   * List secrets at the given metadata path.
   *
   * @param metadataPath the KV v2 metadata path
   * @return list of secret names
   * @throws IOException if the request fails
   */
  public List<String> listSecrets(String metadataPath) throws IOException {
    String url = connInfo.getBaseUrl() + "/v1/" + metadataPath
        + "?list=true";

    String responseBody = executeWithRetry("GET", url, null, false);
    if (responseBody == null) {
      return Collections.emptyList();
    }

    VaultResponse.KvList response =
        MAPPER.readValue(responseBody, VaultResponse.KvList.class);
    if (response.data == null || response.data.keys == null) {
      return Collections.emptyList();
    }

    // Filter out directory entries (trailing /)
    List<String> result = new ArrayList<>();
    for (String key : response.data.keys) {
      if (!key.endsWith("/")) {
        result.add(key);
      }
    }
    return result;
  }

  /**
   * Write a secret value to Vault using the default key {@code "value"}.
   */
  public void writeSecret(String dataPath, String value) throws IOException {
    writeSecret(dataPath, VaultConnectionInfo.DEFAULT_SECRET_KEY, value);
  }

  /**
   * Write a secret value to Vault.
   *
   * @param dataPath the KV v2 data path
   * @param secretKey the key within the secret's data map
   * @param value the secret value
   * @throws IOException if the request fails
   */
  public void writeSecret(String dataPath, String secretKey, String value)
      throws IOException {
    String url = connInfo.getBaseUrl() + "/v1/" + dataPath;

    Map<String, Object> data = new HashMap<>();
    Map<String, String> innerData = new HashMap<>();
    innerData.put(secretKey, value);
    data.put("data", innerData);

    String jsonBody = MAPPER.writeValueAsString(data);
    executeWithRetry("POST", url, jsonBody, true);
  }

  /**
   * Delete a secret from Vault.
   *
   * @param metadataPath the KV v2 metadata path for the alias
   * @throws IOException if the request fails
   */
  public void deleteSecret(String metadataPath) throws IOException {
    String url = connInfo.getBaseUrl() + "/v1/" + metadataPath;
    executeWithRetry("DELETE", url, null, true);
  }

  /**
   * Execute an HTTP request with retry and re-authentication logic.
   */
  private String executeWithRetry(String method, String url,
      String jsonBody, boolean failOnNotFound) throws IOException {
    IOException lastException = null;

    for (int attempt = 0; attempt <= retryCount; attempt++) {
      if (attempt > 0) {
        try {
          Thread.sleep(retryIntervalMs);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new IOException("Retry interrupted", e);
        }
      }

      try {
        HttpURLConnection conn = createConnection(url, method);
        conn.setRequestProperty(VAULT_TOKEN_HEADER, clientToken);

        if (jsonBody != null) {
          conn.setDoOutput(true);
          conn.setRequestProperty("Content-Type", CONTENT_TYPE_JSON);
          byte[] bodyBytes = jsonBody.getBytes(StandardCharsets.UTF_8);
          try (OutputStream os = conn.getOutputStream()) {
            os.write(bodyBytes);
          }
        }

        int statusCode = conn.getResponseCode();

        if (statusCode == HttpURLConnection.HTTP_OK
            || statusCode == HttpURLConnection.HTTP_NO_CONTENT) {
          return readResponseBody(conn);
        }

        if (statusCode == HttpURLConnection.HTTP_NOT_FOUND
            && !failOnNotFound) {
          conn.disconnect();
          return null;
        }

        if (statusCode == HttpURLConnection.HTTP_UNAUTHORIZED
            || statusCode == HttpURLConnection.HTTP_FORBIDDEN) {
          conn.disconnect();
          LOG.debug("Received {} from Vault, re-authenticating "
              + "(attempt {}/{})", statusCode, attempt + 1, retryCount + 1);
          clientToken = authMethod.authenticate(this);
          continue;
        }

        String body = readErrorBody(conn);
        conn.disconnect();
        throw new IOException("Vault request failed with status "
            + statusCode + ": " + body);

      } catch (ConnectException | SocketTimeoutException e) {
        LOG.warn("Vault connection failed (attempt {}/{}): {}",
            attempt + 1, retryCount + 1, e.getMessage());
        lastException = e;
      }
    }

    throw new IOException(
        "Vault request failed after " + (retryCount + 1) + " attempts",
        lastException);
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
      return null;
    }
    try {
      return IOUtils.toString(is, StandardCharsets.UTF_8);
    } finally {
      is.close();
    }
  }

  private static String readErrorBody(HttpURLConnection conn) {
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

  @Override
  public void close() {
    if (sslFactory != null) {
      sslFactory.destroy();
    }
  }

  VaultConnectionInfo getConnInfo() {
    return connInfo;
  }
}
