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

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.io.IOUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Integration tests for VaultCredentialProvider using a mock Vault HTTP server.
 * Tests the full stack including discovery via CredentialProviderFactory.
 */
public class TestVaultCredentialProviderIntegration {

  private static final String TEST_TOKEN = "s.integrationtest";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private HttpServer server;
  private int port;
  private Configuration conf;

  /** In-memory store simulating Vault KV v2. */
  private final ConcurrentHashMap<String, String> store =
      new ConcurrentHashMap<>();

  @Before
  public void setUp() throws Exception {
    server = HttpServer.create(new InetSocketAddress(0), 0);
    port = server.getAddress().getPort();

    // Handle all requests under /v1/secret/
    server.createContext("/v1/secret/", this::handleVaultRequest);
    server.start();

    VaultCredentialProvider.clearCaches();

    conf = new Configuration();
    String providerUri =
        "vault://http@localhost:" + port + "/secret/hadoop/creds";
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH, providerUri);
    conf.set(VaultCredentialProviderConfig.TOKEN_KEY, TEST_TOKEN);
    conf.setInt(VaultCredentialProviderConfig.RETRY_COUNT_KEY, 0);
    // Disable credential cache so integration tests see fresh Vault state
    conf.setBoolean(VaultCredentialProviderConfig.CACHE_ENABLED_KEY, false);

    store.clear();
  }

  @After
  public void tearDown() {
    if (server != null) {
      server.stop(0);
    }
    VaultCredentialProvider.clearCaches();
  }

  @Test
  public void testDiscoveryViaFactory() throws Exception {
    List<CredentialProvider> providers =
        CredentialProviderFactory.getProviders(conf);

    assertEquals(1, providers.size());
    assertTrue(providers.get(0) instanceof VaultCredentialProvider);
  }

  @Test
  public void testCrudLifecycle() throws Exception {
    List<CredentialProvider> providers =
        CredentialProviderFactory.getProviders(conf);
    CredentialProvider provider = providers.get(0);

    // Initially no entry
    assertNull(provider.getCredentialEntry("test.key"));

    // Create
    char[] password = "mySecret123".toCharArray();
    CredentialProvider.CredentialEntry entry =
        provider.createCredentialEntry("test.key", password);
    assertNotNull(entry);
    assertArrayEquals(password, entry.getCredential());

    // Read back
    entry = provider.getCredentialEntry("test.key");
    assertNotNull(entry);
    assertArrayEquals(password, entry.getCredential());

    // List
    List<String> aliases = provider.getAliases();
    assertTrue(aliases.contains("test.key"));

    // Duplicate create should fail
    try {
      provider.createCredentialEntry("test.key", "other".toCharArray());
      fail("should throw");
    } catch (Exception e) {
      assertTrue(e.getMessage().contains("already exists"));
    }

    // Delete
    provider.deleteCredentialEntry("test.key");
    assertNull(provider.getCredentialEntry("test.key"));

    // Delete non-existent should fail
    try {
      provider.deleteCredentialEntry("test.key");
      fail("should throw");
    } catch (Exception e) {
      assertTrue(e.getMessage().contains("does not exist"));
    }
  }

  @Test
  public void testConfigurationGetPassword() throws Exception {
    // Pre-populate the store
    store.put("hadoop/creds/ssl.password", "keystorePass");

    char[] password = conf.getPassword("ssl.password");
    assertNotNull(password);
    assertArrayEquals("keystorePass".toCharArray(), password);
  }

  @Test
  public void testMultipleCredentials() throws Exception {
    List<CredentialProvider> providers =
        CredentialProviderFactory.getProviders(conf);
    CredentialProvider provider = providers.get(0);

    provider.createCredentialEntry("key1", "value1".toCharArray());
    provider.createCredentialEntry("key2", "value2".toCharArray());
    provider.createCredentialEntry("key3", "value3".toCharArray());

    List<String> aliases = provider.getAliases();
    assertEquals(3, aliases.size());
    assertTrue(aliases.contains("key1"));
    assertTrue(aliases.contains("key2"));
    assertTrue(aliases.contains("key3"));

    assertArrayEquals("value1".toCharArray(),
        provider.getCredentialEntry("key1").getCredential());
    assertArrayEquals("value2".toCharArray(),
        provider.getCredentialEntry("key2").getCredential());
    assertArrayEquals("value3".toCharArray(),
        provider.getCredentialEntry("key3").getCredential());
  }

  @SuppressWarnings("unchecked")
  private void handleVaultRequest(HttpExchange exchange) {
    try {
      String path = exchange.getRequestURI().getPath();
      String method = exchange.getRequestMethod();
      String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");

      if (!TEST_TOKEN.equals(token)) {
        sendResponse(exchange, 403,
            "{\"errors\":[\"permission denied\"]}");
        return;
      }

      // Strip /v1/secret/ prefix
      String subPath = path.substring("/v1/secret/".length());

      if (subPath.startsWith("data/")) {
        String key = subPath.substring("data/".length());
        handleDataRequest(exchange, method, key);
      } else if (subPath.startsWith("metadata/")) {
        String key = subPath.substring("metadata/".length());
        handleMetadataRequest(exchange, method, key);
      } else {
        sendResponse(exchange, 404, "{\"errors\":[\"not found\"]}");
      }
    } catch (Exception e) {
      try {
        sendResponse(exchange, 500,
            "{\"errors\":[\"" + e.getMessage() + "\"]}");
      } catch (Exception ignored) {
      }
    }
  }

  @SuppressWarnings("unchecked")
  private void handleDataRequest(HttpExchange exchange, String method,
      String key) throws Exception {
    if ("GET".equals(method)) {
      String value = store.get(key);
      if (value == null) {
        sendResponse(exchange, 404, "{\"errors\":[\"not found\"]}");
      } else {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> data = new HashMap<>();
        Map<String, String> innerData = new HashMap<>();
        innerData.put("value", value);
        data.put("data", innerData);
        response.put("data", data);
        sendResponse(exchange, 200, MAPPER.writeValueAsString(response));
      }
    } else if ("POST".equals(method)) {
      String body = new String(
          IOUtils.toByteArray(exchange.getRequestBody()),
              StandardCharsets.UTF_8);
      Map<String, Object> request = MAPPER.readValue(body, Map.class);
      Map<String, String> data = (Map<String, String>) request.get("data");
      String value = data.get("value");
      store.put(key, value);
      sendResponse(exchange, 200, "{\"data\":{\"version\":1}}");
    } else {
      sendResponse(exchange, 405, "{\"errors\":[\"method not allowed\"]}");
    }
  }

  private void handleMetadataRequest(HttpExchange exchange, String method,
      String key) throws Exception {
    if ("DELETE".equals(method)) {
      store.remove(key);
      sendResponse(exchange, 204, "");
    } else if ("GET".equals(method)) {
      // LIST operation (with ?list=true query parameter)
      String query = exchange.getRequestURI().getQuery();
      if (query != null && query.contains("list=true")) {
        // List all keys under the prefix
        String prefix = key.endsWith("/") ? key : key + "/";
        // Handle case where key might not have trailing / yet
        java.util.List<String> keys = new java.util.ArrayList<>();
        for (String storedKey : store.keySet()) {
          if (storedKey.startsWith(prefix)) {
            String remainder = storedKey.substring(prefix.length());
            // Only return the first segment
            int slashIdx = remainder.indexOf('/');
            String entry = slashIdx >= 0
                ? remainder.substring(0, slashIdx + 1) : remainder;
            if (!keys.contains(entry)) {
              keys.add(entry);
            }
          }
        }
        if (keys.isEmpty()) {
          // Also check without trailing slash prefix
          String altPrefix = key;
          for (String storedKey : store.keySet()) {
            if (storedKey.startsWith(altPrefix + "/")
                || storedKey.equals(altPrefix)) {
              String remainder = storedKey.equals(altPrefix)
                  ? storedKey
                  : storedKey.substring(altPrefix.length() + 1);
              int slashIdx = remainder.indexOf('/');
              String entry = slashIdx >= 0
                  ? remainder.substring(0, slashIdx + 1) : remainder;
              if (!keys.contains(entry) && !entry.isEmpty()) {
                keys.add(entry);
              }
            }
          }
        }
        if (keys.isEmpty()) {
          sendResponse(exchange, 404, "{\"errors\":[\"not found\"]}");
        } else {
          Map<String, Object> response = new HashMap<>();
          Map<String, Object> data = new HashMap<>();
          data.put("keys", keys);
          response.put("data", data);
          sendResponse(exchange, 200, MAPPER.writeValueAsString(response));
        }
      } else {
        sendResponse(exchange, 404, "{\"errors\":[\"not found\"]}");
      }
    } else {
      sendResponse(exchange, 405, "{\"errors\":[\"method not allowed\"]}");
    }
  }

  private void sendResponse(HttpExchange exchange, int statusCode,
      String body) throws Exception {
    byte[] responseBytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(statusCode,
        responseBytes.length > 0 ? responseBytes.length : -1);
    if (responseBytes.length > 0) {
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(responseBytes);
      }
    }
    exchange.close();
  }
}
