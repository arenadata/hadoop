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
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.apache.hadoop.security.alias.vault.VaultKerberosTestFixture.CLIENT_PRINCIPAL;
import static org.apache.hadoop.test.LambdaTestUtils.intercept;
import static org.junit.Assert.assertEquals;

/**
 * Tests for {@link KerberosVaultAuth}: login path construction and the
 * SPNEGO login round trip against a mock Vault server backed by MiniKdc.
 */
public class TestKerberosVaultAuth {

  private static final String DEFAULT_LOGIN_PATH = "/v1/auth/kerberos/login";

  @ClassRule
  public static final TemporaryFolder FOLDER = new TemporaryFolder();

  private static final VaultKerberosTestFixture KRB =
      new VaultKerberosTestFixture();

  private HttpServer server;
  private int port;
  private VaultConnectionInfo connInfo;
  private Configuration conf;
  /** The only login endpoint the mock treats as mounted. */
  private volatile String mountedLoginPath = DEFAULT_LOGIN_PATH;
  /** Token the next login issues; the secret handler accepts only it. */
  private volatile String issuedToken = "s.login-1";
  private final List<String> loginRequests =
      Collections.synchronizedList(new ArrayList<>());
  private final List<String> authenticatedPrincipals =
      Collections.synchronizedList(new ArrayList<>());

  @BeforeClass
  public static void startKdc() throws Exception {
    KRB.start(FOLDER.getRoot());
  }

  @AfterClass
  public static void stopKdc() {
    KRB.stop();
  }

  @Before
  public void setUp() throws Exception {
    server = HttpServer.create(new InetSocketAddress(0), 0);
    port = server.getAddress().getPort();
    server.createContext("/v1/auth/", this::handleLogin);
    server.createContext(MockVault.SECRET_PATH,
        exchange -> MockVault.handleSecret(exchange, issuedToken::equals));
    server.start();

    connInfo = new VaultConnectionInfo(new URI(
        "vault://http@localhost:" + port + "/secret/hadoop/creds"));
    conf = KRB.kerberosConf();
    VaultCredentialProvider.clearCaches();
  }

  @After
  public void tearDown() {
    if (server != null) {
      server.stop(0);
    }
    VaultCredentialProvider.clearCaches();
  }

  @Test
  public void testBuildLoginPath() throws Exception {
    assertEquals("auth/kerberos/login", KerberosVaultAuth.buildLoginPath(
        VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_DEFAULT));
    assertEquals("auth/krb-prod/login",
        KerberosVaultAuth.buildLoginPath("auth/krb-prod"));
    assertEquals("auth/krb-prod/login",
        KerberosVaultAuth.buildLoginPath(" /auth/krb-prod// "));
  }

  @Test
  public void testBuildLoginPathRejectsEmptyMount() throws Exception {
    intercept(IOException.class, "mount path is empty",
        () -> KerberosVaultAuth.buildLoginPath(""));
    intercept(IOException.class, "mount path is empty",
        () -> KerberosVaultAuth.buildLoginPath("/"));
  }

  @Test
  public void testLoginPostsToDefaultMountLoginPath() throws Exception {
    VaultHttpClient client = newClient(0);

    assertEquals(Collections.singletonList("POST " + DEFAULT_LOGIN_PATH),
        loginRequests);
    assertEquals(
        Collections.singletonList(KRB.principal(CLIENT_PRINCIPAL)),
        authenticatedPrincipals);
    assertEquals(MockVault.SECRET_VALUE, client.readSecret(
        "secret/data/hadoop/creds/db.password", "value"));
  }

  @Test
  public void testLoginPostsToCustomMountLoginPath() throws Exception {
    conf.set(VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_KEY,
        "/auth/krb-prod/");
    mountedLoginPath = "/v1/auth/krb-prod/login";

    newClient(0);

    assertEquals(Collections.singletonList("POST /v1/auth/krb-prod/login"),
        loginRequests);
  }

  @Test
  public void testLoginFailureReportsUrlAndStatus() throws Exception {
    conf.set(VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_KEY,
        "auth/unmounted");

    intercept(IOException.class,
        "Vault Kerberos login to " + connInfo.getBaseUrl()
            + "/v1/auth/unmounted/login failed with status 403: "
            + MockVault.PERMISSION_DENIED,
        () -> newClient(0));
  }

  @Test
  public void testReauthenticatesOnForbidden() throws Exception {
    VaultHttpClient client = newClient(1);
    issuedToken = "s.login-2";

    assertEquals(MockVault.SECRET_VALUE, client.readSecret(
        "secret/data/hadoop/creds/db.password", "value"));
    assertEquals(Arrays.asList(
        "POST " + DEFAULT_LOGIN_PATH, "POST " + DEFAULT_LOGIN_PATH),
        loginRequests);
  }

  @Test
  public void testProviderWithKerberosAuthMethod() throws Exception {
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
        "vault://http@localhost:" + port + "/secret/hadoop/creds");
    conf.setInt(VaultCredentialProviderConfig.RETRY_COUNT_KEY, 0);

    assertEquals(MockVault.SECRET_VALUE, new String(conf.getPassword("db.password")));
    assertEquals(Collections.singletonList("POST " + DEFAULT_LOGIN_PATH),
        loginRequests);
  }

  private VaultHttpClient newClient(int retryCount) throws IOException {
    return new VaultHttpClient(connInfo, new KerberosVaultAuth(conf, connInfo),
        5000, 5000, retryCount, 100);
  }

  /**
   * Mimics Vault core: only the {@code login} endpoint of a mounted auth
   * backend is reachable without a token, and the backend accepts the
   * SPNEGO token before issuing one.
   */
  private void handleLogin(HttpExchange exchange) throws IOException {
    String path = exchange.getRequestURI().getPath();
    loginRequests.add(exchange.getRequestMethod() + " " + path);
    if (!path.equals(mountedLoginPath)) {
      MockVault.sendResponse(exchange, 403, MockVault.PERMISSION_DENIED);
      return;
    }
    try {
      String principal = KRB.acceptSpnego(
          exchange.getRequestHeaders().getFirst("Authorization"));
      authenticatedPrincipals.add(principal);
      MockVault.sendResponse(exchange, 200,
          "{\"auth\":{\"client_token\":\"" + issuedToken + "\"}}");
    } catch (Exception e) {
      MockVault.sendResponse(exchange, 403,
          "{\"errors\":[\"spnego rejected: " + e + "\"]}");
    }
  }
}
