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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.io.IOUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.ssl.KeyStoreTestUtil;
import org.apache.hadoop.test.GenericTestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.apache.hadoop.test.LambdaTestUtils.intercept;
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
  private static final String NOT_FOUND = "{\"errors\":[]}";

  @Rule
  public TemporaryFolder tempDir = new TemporaryFolder();

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

    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    client = new VaultHttpClient(connInfo, auth, 5000, 5000, 1, 100);
  }

  @After
  public void tearDown() throws Exception {
    if (server != null) {
      server.stop(0);
    }
  }

  /**
   * The SSL machinery is built before the Vault login, so a login that
   * fails must not leave the truststore reload timer running.
   */
  @Test
  public void testFailedLoginReleasesTheSslMachinery() throws Exception {
    File trustStore = new File(tempDir.getRoot(), "truststore.jks");
    KeyStoreTestUtil.createTrustStore(trustStore.getPath(), "changeit",
        new HashMap<String, Certificate>());
    Configuration sslConf = new Configuration();
    sslConf.set("ssl.client.truststore.location", trustStore.getPath());
    sslConf.set("ssl.client.truststore.password", "changeit");
    VaultConnectionInfo https = new VaultConnectionInfo(
        new URI("vault://https@localhost:" + port + "/secret/hadoop"));
    long before = sslMonitorThreads();

    try {
      new VaultHttpClient(sslConf, https, c -> {
        throw new IOException("vault said 403");
      });
      fail("should throw");
    } catch (IOException e) {
      assertEquals("vault said 403", e.getMessage());
    }

    GenericTestUtils.waitFor(() -> sslMonitorThreads() <= before, 20, 5000);
  }

  private static long sslMonitorThreads() {
    return Thread.getAllStackTraces().keySet().stream()
        .filter(t -> t.getName().contains("SSL Certificates Store Monitor"))
        .count();
  }

  @Test
  public void testDedicatedTruststoreLoadsWithoutAPassword()
      throws Exception {
    File trustStore = new File(tempDir.getRoot(), "vault-truststore.jks");
    KeyStoreTestUtil.createTrustStore(trustStore.getPath(), "changeit",
        new HashMap<String, Certificate>());
    Configuration sslConf = new Configuration(false);
    sslConf.set(VaultCredentialProviderConfig.SSL_TRUSTSTORE_LOCATION_KEY,
        trustStore.getPath());
    VaultConnectionInfo https = new VaultConnectionInfo(
        new URI("vault://https@localhost:" + port + "/secret/hadoop"));

    new VaultHttpClient(sslConf, https, c -> TEST_TOKEN).close();
  }

  @Test
  public void testHttpSettingsAreValidated() throws Exception {
    Configuration conf = new Configuration(false);
    conf.set(VaultCredentialProviderConfig.CONNECTION_TIMEOUT_MS_KEY, "-1");
    intercept(IOException.class,
        VaultCredentialProviderConfig.CONNECTION_TIMEOUT_MS_KEY
            + " must not be negative",
        () -> new VaultHttpClient(conf, connInfo, c -> TEST_TOKEN));

    conf.unset(VaultCredentialProviderConfig.CONNECTION_TIMEOUT_MS_KEY);
    conf.set(VaultCredentialProviderConfig.RETRY_COUNT_KEY, "three");
    intercept(IOException.class,
        VaultCredentialProviderConfig.RETRY_COUNT_KEY + " is not a number",
        () -> new VaultHttpClient(conf, connInfo, c -> TEST_TOKEN));
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

    String value = client.readSecret("secret/data/hadoop/db.password", "value");
    assertEquals("p@ssw0rd", value);
  }

  @Test
  public void testRequestsCarryTheVaultRequestHeader() throws Exception {
    List<String> headers = new CopyOnWriteArrayList<>();
    server.createContext("/v1/secret/data/hadoop/db.password",
        exchange -> {
          headers.add(exchange.getRequestHeaders().getFirst("X-Vault-Request"));
          sendResponse(exchange, 200,
              "{\"data\":{\"data\":{\"value\":\"p@ssw0rd\"}}}");
        });
    server.createContext("/v1/auth/test/login",
        exchange -> {
          headers.add(exchange.getRequestHeaders().getFirst("X-Vault-Request"));
          sendResponse(exchange, 200, "{}");
        });

    client.readSecret("secret/data/hadoop/db.password", "value");
    VaultAuthRequests.post(client,
        "http://localhost:" + port + "/v1/auth/test/login", null, "{}",
        "Vault test login");
    assertEquals(Arrays.asList("true", "true"), headers);
  }

  @Test
  public void testReadSecretNotFound() throws Exception {
    server.createContext("/v1/secret/data/hadoop/missing",
        exchange -> {
          assertTokenHeader(exchange);
          sendResponse(exchange, 404, NOT_FOUND);
        });
    server.createContext("/v1/secret/data/hadoop/silent",
        exchange -> sendResponse(exchange, 404, ""));

    assertNull(client.readSecret("secret/data/hadoop/missing", "value"));
    assertNull(client.readSecret("secret/data/hadoop/silent", "value"));
  }

  @Test
  public void testNotFoundWithErrorsIsAnError() throws Exception {
    server.createContext("/v1/secrt/data/hadoop/x",
        exchange -> sendResponse(exchange, 404, "{\"errors\":[\"no handler "
            + "for route 'secrt/data/hadoop/x'. route entry not found.\"]}"));

    intercept(IOException.class, "no handler for route",
        () -> client.readSecret("secrt/data/hadoop/x", "value"));
  }

  @Test
  public void testDeletedSecretKeepsItsVersion() throws Exception {
    server.createContext("/v1/secret/data/hadoop/deleted",
        exchange -> sendResponse(exchange, 404, "{\"data\":{\"data\":null,"
            + "\"metadata\":{\"version\":4,\"destroyed\":false,"
            + "\"deletion_time\":\"2026-09-16T10:00:00Z\"}}}"));

    VaultHttpClient.Secret secret =
        client.readSecretFields("secret/data/hadoop/deleted");
    assertTrue(secret.getFields().isEmpty());
    assertEquals(4, secret.getVersion());
    assertNull(client.readSecret("secret/data/hadoop/deleted", "value"));
  }

  @Test
  public void testFieldsKeepTheirJsonTypes() throws Exception {
    server.createContext("/v1/secret/data/hadoop/typed",
        exchange -> sendResponse(exchange, 200, "{\"data\":{\"data\":"
            + "{\"value\":\"pw\",\"port\":5432,\"tls\":{\"verify\":true}},"
            + "\"metadata\":{\"version\":2}}}"));

    assertEquals("pw", client.readSecret("secret/data/hadoop/typed", "value"));
    assertEquals("5432",
        client.readSecret("secret/data/hadoop/typed", "port"));
    intercept(IOException.class, "Field tls of secret/data/hadoop/typed is "
        + "not a string",
        () -> client.readSecret("secret/data/hadoop/typed", "tls"));

    VaultHttpClient.Secret secret =
        client.readSecretFields("secret/data/hadoop/typed");
    assertEquals(5432, secret.getFields().get("port"));
    assertTrue(secret.getFields().get("tls") instanceof Map);
  }

  @Test
  public void testWriteSecret() throws Exception {
    final String[] body = {null};
    server.createContext("/v1/secret/data/hadoop/new.key",
        exchange -> {
          assertTokenHeader(exchange);
          assertEquals("POST", exchange.getRequestMethod());
          body[0] = new String(
              IOUtils.toByteArray(exchange.getRequestBody()),
              StandardCharsets.UTF_8);
          sendResponse(exchange, 200, "{\"data\":{\"version\":4}}");
        });

    Map<String, Object> fields = new HashMap<>();
    fields.put("username", "dbuser");
    fields.put("port", 5432);
    fields.put("value", "secret123");
    client.writeSecret("secret/data/hadoop/new.key", fields, 3);

    assertNotNull("Write handler should have been called", body[0]);
    assertTrue(body[0], body[0].contains("\"value\":\"secret123\""));
    assertTrue(body[0], body[0].contains("\"username\":\"dbuser\""));
    assertTrue(body[0], body[0].contains("\"port\":5432"));
    assertTrue(body[0], body[0].contains("\"cas\":3"));
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
    assertEquals(3, keys.size());
    assertTrue(keys.contains("key1"));
    assertTrue(keys.contains("key2"));
    assertTrue(keys.contains("subdir/"));
  }

  @Test
  public void testListSecretsNotFound() throws Exception {
    server.createContext("/v1/secret/metadata/hadoop",
        exchange -> {
          sendResponse(exchange, 404, NOT_FOUND);
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
    AtomicInteger lookups = serveTokenLookup(newToken);

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
        new VaultHttpClient(connInfo, auth, 5000, 5000, 0, 100);
    String value = reauthClient.readSecret("secret/data/hadoop/auth.test", "value");
    assertEquals("secret", value);
    assertEquals("re-authentication needs no retry budget", 2,
        callCount.get());
    assertEquals(1, lookups.get());
  }

  /** A token Vault refuses even after a fresh login is a failure. */
  @Test
  public void testPersistentForbiddenReportsTheStatusAndBody()
      throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    AtomicInteger authCount = new AtomicInteger(0);
    AtomicInteger lookups = serveTokenLookup();
    server.createContext("/v1/secret/data/hadoop/denied", exchange -> {
      callCount.incrementAndGet();
      sendResponse(exchange, 403, "{\"errors\":[\"permission denied\"]}");
    });
    VaultHttpClient denied = new VaultHttpClient(connInfo,
        c -> "s.login-" + authCount.incrementAndGet(), 5000, 5000, 3, 100);

    IOException e = intercept(IOException.class, "permission denied",
        () -> denied.readSecret("secret/data/hadoop/denied", "value"));

    assertTrue(e.getMessage(), e.getMessage().contains("status 403"));
    assertEquals("one request, one re-authentication, one more request", 2,
        callCount.get());
    assertEquals(2, authCount.get());
    assertEquals(2, lookups.get());
  }

  @Test
  public void testARefusedStaticTokenIsNotSentAgain() throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    AtomicInteger authCount = new AtomicInteger(0);
    AtomicInteger lookups = serveTokenLookup();
    server.createContext("/v1/secret/data/hadoop/denied", exchange -> {
      callCount.incrementAndGet();
      sendResponse(exchange, 403, MockVault.PERMISSION_DENIED);
    });
    VaultHttpClient denied = new VaultHttpClient(connInfo, c -> {
      authCount.incrementAndGet();
      return TEST_TOKEN;
    }, 5000, 5000, 3, 100);

    intercept(IOException.class, "status 403",
        () -> denied.readSecret("secret/data/hadoop/denied", "value"));
    intercept(IOException.class, "status 403",
        () -> denied.writeSecret("secret/data/hadoop/denied",
            new HashMap<>(), 0));

    assertEquals(2, callCount.get());
    assertEquals(3, authCount.get());
    assertEquals(1, lookups.get());
  }

  @Test
  public void testAReadThePolicyDeniesIsAbsent() throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    AtomicInteger authCount = new AtomicInteger(0);
    AtomicInteger lookups = serveTokenLookup(TEST_TOKEN);
    server.createContext("/v1/secret/data/hadoop/denied", exchange -> {
      callCount.incrementAndGet();
      sendResponse(exchange, 403, MockVault.PERMISSION_DENIED);
    });
    VaultHttpClient denied = new VaultHttpClient(connInfo, c -> {
      authCount.incrementAndGet();
      return TEST_TOKEN;
    }, 5000, 5000, 3, 100);

    assertNull(denied.readSecret("secret/data/hadoop/denied", "value"));

    assertEquals(1, callCount.get());
    assertEquals("no re-authentication", 1, authCount.get());
    assertEquals(1, lookups.get());
  }

  @Test
  public void testADenialOfTheNewTokenIsAbsent() throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    AtomicInteger authCount = new AtomicInteger(0);
    String newToken = "s.newtoken";
    AtomicInteger lookups = serveTokenLookup(newToken);
    server.createContext("/v1/secret/data/hadoop/denied", exchange -> {
      callCount.incrementAndGet();
      sendResponse(exchange, 403, MockVault.PERMISSION_DENIED);
    });
    VaultHttpClient denied = new VaultHttpClient(connInfo,
        c -> authCount.getAndIncrement() == 0 ? TEST_TOKEN : newToken,
        5000, 5000, 3, 100);

    assertNull(denied.readSecret("secret/data/hadoop/denied", "value"));

    assertEquals(2, callCount.get());
    assertEquals(2, authCount.get());
    assertEquals(2, lookups.get());
  }

  /**
   * Policies bound at login change only with a new token, so a token older
   * than the negative cache TTL gets a fresh login before a denial counts.
   */
  @Test
  public void testAnOldTokenIsRenewedBeforeADenialCounts() throws Exception {
    AtomicInteger authCount = new AtomicInteger(0);
    AtomicInteger lookups = serveTokenLookup("s.login-1", "s.login-2");
    server.createContext("/v1/secret/data/hadoop/granted", exchange ->
        MockVault.handleSecret(exchange, "s.login-2"::equals));
    Configuration conf = new Configuration(false);
    conf.setLong(VaultCredentialProviderConfig.CACHE_NEGATIVE_TTL_MS_KEY, 0);
    VaultHttpClient old = new VaultHttpClient(conf, connInfo,
        c -> "s.login-" + authCount.incrementAndGet());

    assertEquals(MockVault.SECRET_VALUE,
        old.readSecret("secret/data/hadoop/granted", "value"));

    assertEquals(2, authCount.get());
    assertEquals(1, lookups.get());
  }

  @Test
  public void testAnOldStaticTokenDeniedByPolicyIsAbsent() throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    AtomicInteger authCount = new AtomicInteger(0);
    serveTokenLookup(TEST_TOKEN);
    server.createContext("/v1/secret/data/hadoop/denied", exchange -> {
      callCount.incrementAndGet();
      sendResponse(exchange, 403, MockVault.PERMISSION_DENIED);
    });
    Configuration conf = new Configuration(false);
    conf.setLong(VaultCredentialProviderConfig.CACHE_NEGATIVE_TTL_MS_KEY, 0);
    VaultHttpClient old = new VaultHttpClient(conf, connInfo, c -> {
      authCount.incrementAndGet();
      return TEST_TOKEN;
    });

    assertNull(old.readSecret("secret/data/hadoop/denied", "value"));

    assertEquals(1, callCount.get());
    assertEquals(2, authCount.get());
  }

  @Test
  public void testADenialWithoutABodyIsAbsent() throws Exception {
    serveTokenLookup(TEST_TOKEN);
    server.createContext("/v1/secret/data/hadoop/proxied",
        exchange -> sendResponse(exchange, 403, ""));

    assertNull(client.readSecret("secret/data/hadoop/proxied", "value"));
  }

  @Test
  public void testATransientLookupFailureIsRetried() throws Exception {
    AtomicInteger authCount = new AtomicInteger(0);
    AtomicInteger lookups = new AtomicInteger(0);
    server.createContext(MockVault.TOKEN_LOOKUP_PATH, exchange -> {
      if (lookups.incrementAndGet() == 1) {
        sendResponse(exchange, 429, "{\"errors\":[\"rate limit quota\"]}");
      } else {
        MockVault.handleTokenLookup(exchange, TEST_TOKEN::equals);
      }
    });
    server.createContext("/v1/secret/data/hadoop/denied",
        exchange -> sendResponse(exchange, 403, MockVault.PERMISSION_DENIED));
    VaultHttpClient denied = new VaultHttpClient(connInfo, c -> {
      authCount.incrementAndGet();
      return TEST_TOKEN;
    }, 5000, 5000, 1, 10);

    assertNull(denied.readSecret("secret/data/hadoop/denied", "value"));

    assertEquals(2, lookups.get());
    assertEquals("no re-authentication", 1, authCount.get());
  }

  @Test
  public void testALookupThatKeepsFailingIsReportedAsSuch()
      throws Exception {
    AtomicInteger authCount = new AtomicInteger(0);
    server.createContext(MockVault.TOKEN_LOOKUP_PATH,
        exchange -> sendResponse(exchange, 503,
            "{\"errors\":[\"Vault is sealed\"]}"));
    server.createContext("/v1/secret/data/hadoop/denied",
        exchange -> sendResponse(exchange, 403, MockVault.PERMISSION_DENIED));
    VaultHttpClient denied = new VaultHttpClient(connInfo, c -> {
      authCount.incrementAndGet();
      return TEST_TOKEN;
    }, 5000, 5000, 1, 10);

    IOException e = intercept(IOException.class,
        "Vault token lookup failed after 2 attempts",
        () -> denied.readSecret("secret/data/hadoop/denied", "value"));

    assertTrue(e.getCause().getMessage(),
        e.getCause().getMessage().contains("status 503"));
    assertEquals("no re-authentication", 1, authCount.get());
  }

  /**
   * Writes, lists and the read that precedes a write or a delete fail on
   * a denial even to a token Vault accepts.
   */
  @Test
  public void testADenialFailsAllButASecretRead() throws Exception {
    serveTokenLookup(TEST_TOKEN);
    server.createContext("/v1/secret/",
        exchange -> sendResponse(exchange, 403, MockVault.PERMISSION_DENIED));

    assertNull(client.readSecret("secret/data/hadoop/denied", "value"));
    intercept(IOException.class, "status 403",
        () -> client.readSecretFields("secret/data/hadoop/denied"));
    intercept(IOException.class, "status 403", () -> client.writeSecret(
        "secret/data/hadoop/denied", new HashMap<>(), 0));
    intercept(IOException.class, "status 403",
        () -> client.listSecrets("secret/metadata/hadoop"));
    intercept(IOException.class, "status 403",
        () -> client.deleteSecret("secret/metadata/hadoop/denied"));
  }

  /**
   * Answer {@code auth/token/lookup-self}: 200 to the accepted tokens, 403
   * to any other.
   *
   * @return the number of lookups
   */
  private AtomicInteger serveTokenLookup(String... accepted) {
    List<String> tokens = Arrays.asList(accepted);
    AtomicInteger lookups = new AtomicInteger();
    server.createContext(MockVault.TOKEN_LOOKUP_PATH, exchange -> {
      lookups.incrementAndGet();
      MockVault.handleTokenLookup(exchange, tokens::contains);
    });
    return lookups;
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

    String value = client.readSecret("secret/data/hadoop/check.token", "value");
    assertEquals("ok", value);
  }

  @Test
  public void testServerErrorIsRetriedThenReported() throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    server.createContext("/v1/secret/data/hadoop/error.key",
        exchange -> {
          callCount.incrementAndGet();
          sendResponse(exchange, 500, "{\"errors\":[\"internal error\"]}");
        });

    IOException e = intercept(IOException.class, "failed after 2 attempts",
        () -> client.readSecret("secret/data/hadoop/error.key", "value"));

    assertEquals(2, callCount.get());
    assertTrue(e.getCause().getMessage(),
        e.getCause().getMessage().contains("status 500"));
  }

  @Test
  public void testTransientStatusIsRetriedUntilItClears() throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    server.createContext("/v1/secret/data/hadoop/sealed",
        exchange -> {
          if (callCount.incrementAndGet() == 1) {
            sendResponse(exchange, 503, "{\"errors\":[\"Vault is sealed\"]}");
          } else {
            sendResponse(exchange, 200,
                "{\"data\":{\"data\":{\"value\":\"ok\"}}}");
          }
        });

    assertEquals("ok", client.readSecret("secret/data/hadoop/sealed", "value"));
    assertEquals(2, callCount.get());
  }

  @Test
  public void testBadRequestIsNotRetried() throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    server.createContext("/v1/secret/data/hadoop/cas",
        exchange -> {
          callCount.incrementAndGet();
          sendResponse(exchange, 400, "{\"errors\":[\"check-and-set "
              + "parameter did not match the current version\"]}");
        });

    intercept(IOException.class, "status 400", () -> client.writeSecret(
        "secret/data/hadoop/cas", new HashMap<>(), 1));
    assertEquals(1, callCount.get());
  }

  /**
   * The JDK client itself reconnects once when a kept-alive connection
   * turns out closed, so the server has to drop two connections before
   * the failure reaches the retry loop.
   */
  @Test
  public void testConnectionResetIsRetried() throws Exception {
    ServerSocket sockets = new ServerSocket(0, 50,
        InetAddress.getLoopbackAddress());
    String body = "{\"data\":{\"data\":{\"value\":\"ok\"}}}";
    Thread flaky = new Thread(() -> {
      try {
        sockets.accept().close();
        sockets.accept().close();
        try (Socket second = sockets.accept()) {
          InputStream in = second.getInputStream();
          StringBuilder request = new StringBuilder();
          int c;
          while ((c = in.read()) >= 0) {
            request.append((char) c);
            if (request.toString().endsWith("\r\n\r\n")) {
              break;
            }
          }
          OutputStream out = second.getOutputStream();
          out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
              + "Content-Length: " + body.length()
              + "\r\nConnection: close\r\n\r\n" + body)
              .getBytes(StandardCharsets.UTF_8));
          out.flush();
        }
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
    flaky.start();
    try {
      VaultConnectionInfo flakyInfo = new VaultConnectionInfo(new URI(
          "vault://http@localhost:" + sockets.getLocalPort()
              + "/secret/hadoop"));
      VaultHttpClient flakyClient =
          new VaultHttpClient(flakyInfo, c -> TEST_TOKEN, 5000, 5000, 1, 10);

      assertEquals("ok",
          flakyClient.readSecret("secret/data/hadoop/reset", "value"));
    } finally {
      sockets.close();
      flaky.join(5000);
    }
  }

  @Test
  public void testAWriteIsNotRepeatedAfterItWasSent() throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    server.createContext("/v1/secret/data/hadoop/slow", exchange -> {
      callCount.incrementAndGet();
      IOUtils.toByteArray(exchange.getRequestBody());
      try {
        Thread.sleep(1500);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      sendResponse(exchange, 200, "{\"data\":{\"version\":1}}");
    });
    VaultHttpClient impatient =
        new VaultHttpClient(connInfo, c -> TEST_TOKEN, 5000, 300, 2, 10);

    intercept(IOException.class, "not repeated", () -> impatient.writeSecret(
        "secret/data/hadoop/slow", new HashMap<>(), 0));

    assertEquals(1, callCount.get());
  }

  @Test
  public void testADeleteIsRepeatedAfterATimeout() throws Exception {
    AtomicInteger callCount = new AtomicInteger(0);
    server.createContext("/v1/secret/metadata/hadoop/slow", exchange -> {
      if (callCount.incrementAndGet() == 1) {
        try {
          Thread.sleep(1500);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      sendResponse(exchange, 204, "");
    });
    VaultHttpClient impatient =
        new VaultHttpClient(connInfo, c -> TEST_TOKEN, 5000, 300, 2, 10);

    impatient.deleteSecret("secret/metadata/hadoop/slow");

    assertEquals(2, callCount.get());
  }

  @Test
  public void testAliasIsPercentEncodedOnTheWire() throws Exception {
    final String[] paths = {null, null};
    server.createContext("/v1/secret/data/hadoop/", exchange -> {
      paths[0] = exchange.getRequestURI().getRawPath();
      paths[1] = exchange.getRequestURI().getPath();
      sendResponse(exchange, 200, "{\"data\":{\"data\":{\"value\":\"ok\"}}}");
    });

    assertEquals("ok", client.readSecret(
        connInfo.buildDataPath("my key#1?x"), "value"));

    assertEquals("/v1/secret/data/hadoop/my%20key%231%3Fx", paths[0]);
    assertEquals("/v1/secret/data/hadoop/my key#1?x", paths[1]);
  }

  private void assertTokenHeader(HttpExchange exchange) {
    String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");
    assertNotNull("X-Vault-Token header must be present", token);
  }

  @Test
  public void testReadMultipleKeysFromSamePath() throws Exception {
    server.createContext("/v1/secret/data/hadoop/db",
        exchange -> {
          assertTokenHeader(exchange);
          String response =
              "{\"data\":{\"data\":"
              + "{\"password\":\"s3cret\",\"username\":\"admin\"}}}";
          sendResponse(exchange, 200, response);
        });

    assertEquals("s3cret",
        client.readSecret("secret/data/hadoop/db", "password"));
    assertEquals("admin",
        client.readSecret("secret/data/hadoop/db", "username"));
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
