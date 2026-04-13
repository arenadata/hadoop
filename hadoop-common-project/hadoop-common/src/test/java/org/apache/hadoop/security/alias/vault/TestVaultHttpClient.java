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
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.io.IOUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for {@link VaultHttpClient} using an embedded HTTP server.
 */
public class TestVaultHttpClient {

  private static final String TEST_TOKEN = "s.testtoken12345";

  private HttpServer server;
  private int port;
  private VaultHttpClient client;
  private VaultConnectionInfo connInfo;

  @Before
  public void setUp() throws Exception {
    server = HttpServer.create(new InetSocketAddress(0), 0);
    port = server.getAddress().getPort();

    URI uri = new URI("vault://http@localhost:" + port + "/secret/hadoop");
    connInfo = new VaultConnectionInfo(uri);

    VaultAuthMethod auth = c -> TEST_TOKEN;

    server.start();
    client = new VaultHttpClient(connInfo, auth, 5000, 5000, 1, 100);
  }

  @After
  public void tearDown() throws Exception {
    if (server != null) {
      server.stop(0);
    }
  }

  @Test
  public void testReadSecret() throws Exception {
    server.createContext("/v1/secret/data/hadoop/db.password",
        exchange -> {
          assertTokenHeader(exchange);
          String response =
              "{\"data\":{\"data\":{\"value\":\"p@ssw0rd\"}}}";
          sendResponse(exchange, 200, response);
        });

    String value = client.readSecret("secret/data/hadoop/db.password");
    assertEquals("p@ssw0rd", value);
  }

  @Test
  public void testReadSecretNotFound() throws Exception {
    server.createContext("/v1/secret/data/hadoop/missing",
        exchange -> {
          assertTokenHeader(exchange);
          sendResponse(exchange, 404, "");
        });

    String value = client.readSecret("secret/data/hadoop/missing");
    assertNull(value);
  }

  @Test
  public void testWriteSecret() throws Exception {
    final boolean[] called = {false};
    server.createContext("/v1/secret/data/hadoop/new.key",
        exchange -> {
          assertTokenHeader(exchange);
          assertEquals("POST", exchange.getRequestMethod());
          String body = new String(
              IOUtils.toByteArray(exchange.getRequestBody()),
              StandardCharsets.UTF_8);
          assertTrue(body.contains("\"value\":\"secret123\""));
          called[0] = true;
          sendResponse(exchange, 200,
              "{\"data\":{\"version\":1}}");
        });

    client.writeSecret("secret/data/hadoop/new.key", "secret123");
    assertTrue("Write handler should have been called", called[0]);
  }

  @Test
  public void testListSecrets() throws Exception {
    server.createContext("/v1/secret/metadata/hadoop",
        exchange -> {
          assertTokenHeader(exchange);
          String query = exchange.getRequestURI().getQuery();
          assertTrue(query != null && query.contains("list=true"));
          String response =
              "{\"data\":{\"keys\":[\"key1\",\"key2\",\"subdir/\"]}}";
          sendResponse(exchange, 200, response);
        });

    List<String> keys = client.listSecrets("secret/metadata/hadoop");
    assertEquals(2, keys.size());
    assertTrue(keys.contains("key1"));
    assertTrue(keys.contains("key2"));
  }

  @Test
  public void testListSecretsNotFound() throws Exception {
    server.createContext("/v1/secret/metadata/hadoop",
        exchange -> {
          sendResponse(exchange, 404, "");
        });

    List<String> keys = client.listSecrets("secret/metadata/hadoop");
    assertTrue(keys.isEmpty());
  }

  @Test
  public void testDeleteSecret() throws Exception {
    final boolean[] called = {false};
    server.createContext("/v1/secret/metadata/hadoop/old.key",
        exchange -> {
          assertTokenHeader(exchange);
          assertEquals("DELETE", exchange.getRequestMethod());
          called[0] = true;
          sendResponse(exchange, 204, "");
        });

    client.deleteSecret("secret/metadata/hadoop/old.key");
    assertTrue("Delete handler should have been called", called[0]);
  }

  @Test
  public void testReauthOn403() throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    String newToken = "s.newtoken";

    VaultAuthMethod auth = new VaultAuthMethod() {
      private int authCount = 0;
      @Override
      public String authenticate(VaultHttpClient c) {
        return authCount++ == 0 ? TEST_TOKEN : newToken;
      }
    };

    server.createContext("/v1/secret/data/hadoop/auth.test",
        exchange -> {
          int count = callCount.incrementAndGet();
          if (count == 1) {
            sendResponse(exchange, 403, "{\"errors\":[\"permission denied\"]}");
          } else {
            assertEquals(newToken,
                exchange.getRequestHeaders().getFirst("X-Vault-Token"));
            sendResponse(exchange, 200,
                "{\"data\":{\"data\":{\"value\":\"secret\"}}}");
          }
        });

    VaultHttpClient reauthClient =
        new VaultHttpClient(connInfo, auth, 5000, 5000, 2, 100);
    String value = reauthClient.readSecret("secret/data/hadoop/auth.test");
    assertEquals("secret", value);
    assertTrue("Should have retried after 403", callCount.get() >= 2);
  }

  @Test
  public void testTokenHeader() throws Exception {
    server.createContext("/v1/secret/data/hadoop/check.token",
        exchange -> {
          String token = exchange.getRequestHeaders()
              .getFirst("X-Vault-Token");
          assertEquals(TEST_TOKEN, token);
          sendResponse(exchange, 200,
              "{\"data\":{\"data\":{\"value\":\"ok\"}}}");
        });

    String value = client.readSecret("secret/data/hadoop/check.token");
    assertEquals("ok", value);
  }

  @Test
  public void testServerError() throws Exception {
    server.createContext("/v1/secret/data/hadoop/error.key",
        exchange -> {
          sendResponse(exchange, 500, "{\"errors\":[\"internal error\"]}");
        });

    try {
      client.readSecret("secret/data/hadoop/error.key");
      fail("should throw IOException");
    } catch (IOException e) {
      assertTrue(e.getMessage().contains("500"));
    }
  }

  private void assertTokenHeader(HttpExchange exchange) {
    String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");
    assertNotNull("X-Vault-Token header must be present", token);
  }

  private void sendResponse(HttpExchange exchange, int statusCode,
      String body) throws IOException {
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
