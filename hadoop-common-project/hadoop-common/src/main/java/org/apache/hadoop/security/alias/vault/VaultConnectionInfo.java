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

  private final String protocol;
  private final String host;
  private final int port;
  private final String mount;
  private final String basePath;

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
      // Use ProviderUtils.unnestUri to extract protocol from authority
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

    // Parse path
    String path = uri.getPath();
    if (path == null || path.isEmpty()) {
      throw new IOException("Invalid Vault URI: missing path in " + uri);
    }

    // Remove leading slash
    if (path.startsWith("/")) {
      path = path.substring(1);
    }
    // Remove trailing slash
    if (path.endsWith("/")) {
      path = path.substring(0, path.length() - 1);
    }

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
  }

  private static String parseHost(String hostPort) {
    int colonIdx = hostPort.indexOf(':');
    if (colonIdx >= 0) {
      return hostPort.substring(0, colonIdx);
    }
    return hostPort;
  }

  private static int parsePort(String hostPort) {
    int colonIdx = hostPort.indexOf(':');
    if (colonIdx >= 0) {
      try {
        return Integer.parseInt(hostPort.substring(colonIdx + 1));
      } catch (NumberFormatException e) {
        return DEFAULT_PORT;
      }
    }
    return DEFAULT_PORT;
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
}
