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
import java.nio.charset.StandardCharsets;

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.security.ProviderUtils;

/**
 * Parses a Vault credential provider URI and provides methods to build
 * Vault API paths.
 *
 * URI format: {@code vault://[protocol@]host:port/mount/path}
 *
 * Examples:
 * <ul>
 *   <li>{@code vault://https@vault.example.com:8200/secret/hadoop/creds}</li>
 *   <li>{@code vault://http@vault.internal:8200/secret/data-platform}</li>
 *   <li>{@code vault://vault.example.com:8200/secret/hadoop}</li>
 * </ul>
 */
@InterfaceAudience.Private
public class VaultConnectionInfo {

  public static final int DEFAULT_PORT = 8200;
  public static final String DEFAULT_PROTOCOL = "https";
  public static final String DEFAULT_SECRET_KEY = "value";

  private final String protocol;
  private final String host;
  private final int port;
  private final String mount;
  private final String basePath;
  private final String secretKey;

  /**
   * Parse a Vault URI into connection info.
   *
   * @param uri the Vault URI
   * @throws IOException if the URI is invalid
   */
  public VaultConnectionInfo(URI uri) throws IOException {
    String authority = uri.getAuthority();
    if (authority == null || authority.isEmpty()) {
      throw new IOException("Invalid Vault URI: missing host in " + uri);
    }

    if (authority.contains("@")) {
      // Format: vault://protocol@host:port/...
      Path unnested = ProviderUtils.unnestUri(uri);
      URI innerUri = unnested.toUri();

      String scheme = innerUri.getScheme();
      this.protocol = (scheme != null && !scheme.isEmpty())
          ? scheme : DEFAULT_PROTOCOL;

      String innerHost = innerUri.getHost();
      if (innerHost != null && !innerHost.isEmpty()) {
        this.host = innerHost;
        this.port = innerUri.getPort() > 0
            ? innerUri.getPort() : DEFAULT_PORT;
      } else {
        String afterAt = authority.split("@", 2)[1];
        this.host = parseHost(afterAt);
        this.port = parsePort(afterAt);
      }
    } else {
      // Format: vault://host:port/...
      this.protocol = DEFAULT_PROTOCOL;
      this.host = parseHost(authority);
      this.port = parsePort(authority);
    }

    if (this.host == null || this.host.isEmpty()) {
      throw new IOException("Invalid Vault URI: missing host in " + uri);
    }

    String path = uri.getPath();
    if (path == null || path.isEmpty()) {
      throw new IOException("Invalid Vault URI: missing path in " + uri);
    }

    path = stripSlashes(path);

    if (path.isEmpty()) {
      throw new IOException(
          "Invalid Vault URI: path must contain at least a mount point in "
              + uri);
    }

    int slashIdx = path.indexOf('/');
    if (slashIdx < 0) {
      this.mount = path;
      this.basePath = null;
    } else {
      this.mount = path.substring(0, slashIdx);
      this.basePath = path.substring(slashIdx + 1);
    }

    // Parse ?key= query parameter
    String query = uri.getQuery();
    if (query != null) {
      String parsedKey = null;
      for (String param : query.split("&")) {
        if (param.startsWith("key=")) {
          parsedKey = param.substring(4);
          break;
        }
      }
      this.secretKey = (parsedKey != null && !parsedKey.isEmpty())
          ? parsedKey : DEFAULT_SECRET_KEY;
    } else {
      this.secretKey = DEFAULT_SECRET_KEY;
    }
  }

  private VaultConnectionInfo(String protocol, String host, int port) {
    this.protocol = protocol;
    this.host = host;
    this.port = port;
    this.mount = null;
    this.basePath = null;
    this.secretKey = DEFAULT_SECRET_KEY;
  }

  /**
   * Connection info for the server named by a delegation token service,
   * see {@link #getTokenService(String)}. It carries no secret path.
   *
   * @param service the token service
   * @return the connection info
   * @throws IOException if the service is not a Vault token service
   */
  public static VaultConnectionInfo fromTokenService(String service)
      throws IOException {
    String prefix = VaultCredentialProvider.SCHEME_NAME + "://";
    int at = service == null ? -1 : service.indexOf('@');
    if (at < 0 || !service.startsWith(prefix)) {
      throw new IOException("Invalid Vault token service: " + service);
    }
    String protocol = service.substring(prefix.length(), at);
    int slash = service.indexOf('/', at);
    String hostPort = slash < 0 ? service.substring(at + 1)
        : service.substring(at + 1, slash);
    String host = parseHost(hostPort);
    if (protocol.isEmpty() || host.isEmpty()) {
      throw new IOException("Invalid Vault token service: " + service);
    }
    return new VaultConnectionInfo(protocol, host, parsePort(hostPort));
  }

  private static String parseHost(String hostPort) {
    int colonIdx = portSeparator(hostPort);
    if (colonIdx >= 0) {
      return hostPort.substring(0, colonIdx);
    }
    return hostPort;
  }

  private static int parsePort(String hostPort) throws IOException {
    int colonIdx = portSeparator(hostPort);
    if (colonIdx < 0) {
      return DEFAULT_PORT;
    }
    String port = hostPort.substring(colonIdx + 1);
    try {
      return Integer.parseInt(port);
    } catch (NumberFormatException e) {
      throw new IOException("Invalid Vault port: " + port);
    }
  }

  /** Index of the colon before the port, -1 if none; IPv6 literals are bracketed. */
  private static int portSeparator(String hostPort) {
    int from = hostPort.startsWith("[") ? hostPort.indexOf(']') : 0;
    return hostPort.indexOf(':', from < 0 ? 0 : from);
  }

  /**
   * Reject an alias that cannot name one secret under the base path: empty,
   * with control characters, or with an empty, {@code .} or {@code ..} path
   * segment.
   *
   * @param alias the credential alias
   * @throws IOException if the alias is not a Vault path
   */
  static void checkAlias(String alias) throws IOException {
    if (alias == null || alias.isEmpty()) {
      throw new IOException("Credential alias must not be null or empty");
    }
    for (int i = 0; i < alias.length(); i++) {
      char c = alias.charAt(i);
      if (c < ' ' || c == 0x7f) {
        throw new IOException("Credential alias contains control characters");
      }
    }
    for (String segment : alias.split("/", -1)) {
      if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
        throw new IOException("Credential alias '" + alias
            + "' is not a valid Vault path");
      }
    }
  }

  static boolean isValidAlias(String alias) {
    try {
      checkAlias(alias);
      return true;
    } catch (IOException e) {
      return false;
    }
  }

  /**
   * Build the data path for a specific alias.
   * Format: {mount}/data/{basePath}/{alias}
   *
   * @param alias the credential alias
   * @return the Vault data path
   */
  public String buildDataPath(String alias) {
    StringBuilder sb = new StringBuilder();
    sb.append(mount).append("/data");
    if (basePath != null && !basePath.isEmpty()) {
      sb.append('/').append(basePath);
    }
    sb.append('/').append(alias);
    return sb.toString();
  }

  /**
   * Build the metadata path for listing.
   * Format: {mount}/metadata/{basePath}
   *
   * @return the Vault metadata path
   */
  public String buildMetadataPath() {
    StringBuilder sb = new StringBuilder();
    sb.append(mount).append("/metadata");
    if (basePath != null && !basePath.isEmpty()) {
      sb.append('/').append(basePath);
    }
    return sb.toString();
  }

  /**
   * Build the metadata path for a specific alias.
   * Format: {mount}/metadata/{basePath}/{alias}
   *
   * @param alias the credential alias
   * @return the Vault metadata path for the alias
   */
  public String buildMetadataPath(String alias) {
    StringBuilder sb = new StringBuilder();
    sb.append(mount).append("/metadata");
    if (basePath != null && !basePath.isEmpty()) {
      sb.append('/').append(basePath);
    }
    sb.append('/').append(alias);
    return sb.toString();
  }

  /**
   * Get the base URL for the Vault server.
   * Format: {protocol}://{host}:{port}
   *
   * @return the base URL
   */
  public String getBaseUrl() {
    return protocol + "://" + host + ":" + port;
  }

  /**
   * Build the URL of a Vault API path, each segment percent-encoded.
   * Format: {protocol}://{host}:{port}/v1/{path}
   *
   * @param path the API path relative to {@code /v1/}
   * @return the full URL
   */
  public String getApiUrl(String path) {
    return getBaseUrl() + "/v1/" + encodePath(path);
  }

  private static final char[] HEX = "0123456789ABCDEF".toCharArray();

  static String encodePath(String path) {
    StringBuilder sb = new StringBuilder(path.length());
    for (String segment : path.split("/", -1)) {
      if (sb.length() > 0) {
        sb.append('/');
      }
      encodeSegment(segment, sb);
    }
    return sb.toString();
  }

  /** Percent-encode everything but the unreserved characters of RFC 3986. */
  private static void encodeSegment(String segment, StringBuilder sb) {
    for (byte b : segment.getBytes(StandardCharsets.UTF_8)) {
      int c = b & 0xff;
      if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
          || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'
          || c == '~') {
        sb.append((char) c);
      } else {
        sb.append('%').append(HEX[c >> 4]).append(HEX[c & 0xf]);
      }
    }
  }

  /**
   * Server part of a delegation token service.
   * Format: vault://{protocol}@{host}:{port}
   *
   * @return the server service
   */
  public String getServerService() {
    return VaultCredentialProvider.SCHEME_NAME + "://" + protocol + "@"
        + host + ":" + port;
  }

  /**
   * Service recorded in delegation tokens issued by an auth mount of this
   * server. Format: vault://{protocol}@{host}:{port}/{auth mount path}
   *
   * @param authMountPath the Kerberos auth backend mount path
   * @return the token service
   */
  public String getTokenService(String authMountPath) {
    return getServerService() + "/" + authMountPath;
  }

  /**
   * Strip surrounding whitespace and slashes from a path.
   */
  static String stripSlashes(String path) {
    return StringUtils.strip(StringUtils.trimToEmpty(path), "/");
  }

  public String getProtocol() {
    return protocol;
  }

  public String getHost() {
    return host;
  }

  public int getPort() {
    return port;
  }

  public String getMount() {
    return mount;
  }

  public String getBasePath() {
    return basePath;
  }

  /**
   * Get the key name used to read/write the secret value within a
   * Vault KV v2 secret. Defaults to {@code "value"}, configurable
   * via {@code ?key=} query parameter in the provider URI.
   *
   * @return the secret field key name
   */
  public String getSecretKey() {
    return secretKey;
  }
}
