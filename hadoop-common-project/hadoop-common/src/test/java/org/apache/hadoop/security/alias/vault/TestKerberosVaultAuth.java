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
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.minikdc.MiniKdc;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.apache.hadoop.test.LambdaTestUtils.intercept;
import static org.junit.Assert.assertEquals;

/**
 * Tests for {@link KerberosVaultAuth}: login URL construction and the
 * SPNEGO login round trip against a mock Vault server backed by MiniKdc.
 * The mock accepts the SPNEGO token with the {@code HTTP/localhost} key
 * from the same keytab, so a token a real acceptor would reject fails here.
 * UGI relogin is forced on every authentication so the keytab relogin path
 * runs on each login.
 */
public class TestKerberosVaultAuth {

  private static final String BASE_URL = "http://localhost:8200";
  private static final String CLIENT_PRINCIPAL = "vault-client";
  private static final String SERVER_PRINCIPAL = "HTTP/localhost";
  private static final String DEFAULT_LOGIN_PATH = "/v1/auth/kerberos/login";
  private static final String SECRET_PATH =
      "/v1/secret/data/hadoop/creds/db.password";
  private static final String NEGOTIATE = "Negotiate ";
  private static final String PERMISSION_DENIED =
      "{\"errors\":[\"permission denied\"]}";

  @ClassRule
  public static final TemporaryFolder FOLDER = new TemporaryFolder();

  private static MiniKdc kdc;
  private static File keytab;
  private static UserGroupInformation serverUgi;

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
    kdc = new MiniKdc(MiniKdc.createConf(), FOLDER.getRoot());
    kdc.start();
    keytab = new File(FOLDER.getRoot(), "vault.keytab");
    kdc.createPrincipal(keytab, CLIENT_PRINCIPAL, SERVER_PRINCIPAL);

    Configuration conf = new Configuration();
    conf.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTHENTICATION,
        "kerberos");
    UserGroupInformation.setConfiguration(conf);
    UserGroupInformation.setShouldRenewImmediatelyForTests(true);
    serverUgi = UserGroupInformation.loginUserFromKeytabAndReturnUGI(
        SERVER_PRINCIPAL + "@" + kdc.getRealm(), keytab.getAbsolutePath());
  }

  @AfterClass
  public static void stopKdc() {
    if (kdc != null) {
      kdc.stop();
    }
    UserGroupInformation.setShouldRenewImmediatelyForTests(false);
    UserGroupInformation.reset();
  }

  @Before
  public void setUp() throws Exception {
    server = HttpServer.create(new InetSocketAddress(0), 0);
    port = server.getAddress().getPort();
    server.createContext("/v1/auth/", this::handleLogin);
    server.createContext(SECRET_PATH, this::handleSecret);
    server.start();

    connInfo = new VaultConnectionInfo(new URI(
        "vault://http@localhost:" + port + "/secret/hadoop/creds"));

    conf = new Configuration();
    conf.set(VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY,
        CLIENT_PRINCIPAL + "@" + kdc.getRealm());
    conf.set(VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY,
        keytab.getAbsolutePath());
    conf.set(VaultCredentialProviderConfig.KERBEROS_SERVICE_PRINCIPAL_KEY,
        "HTTP/_HOST@" + kdc.getRealm());
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
  public void testBuildLoginUrl() throws Exception {
    assertEquals(BASE_URL + DEFAULT_LOGIN_PATH,
        KerberosVaultAuth.buildLoginUrl(BASE_URL,
            VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_DEFAULT));
    assertEquals(BASE_URL + "/v1/auth/krb-prod/login",
        KerberosVaultAuth.buildLoginUrl(BASE_URL, "auth/krb-prod"));
    assertEquals(BASE_URL + "/v1/auth/krb-prod/login",
        KerberosVaultAuth.buildLoginUrl(BASE_URL, " /auth/krb-prod// "));
  }

  @Test
  public void testBuildLoginUrlRejectsEmptyMount() throws Exception {
    intercept(IOException.class, "mount path is empty",
        () -> KerberosVaultAuth.buildLoginUrl(BASE_URL, ""));
    intercept(IOException.class, "mount path is empty",
        () -> KerberosVaultAuth.buildLoginUrl(BASE_URL, "/"));
  }

  @Test
  public void testLoginPostsToDefaultMountLoginPath() throws Exception {
    VaultHttpClient client = newClient(0);

    assertEquals(Collections.singletonList("POST " + DEFAULT_LOGIN_PATH),
        loginRequests);
    assertEquals(
        Collections.singletonList(CLIENT_PRINCIPAL + "@" + kdc.getRealm()),
        authenticatedPrincipals);
    assertEquals("s3cret", client.readSecret(
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
            + PERMISSION_DENIED,
        () -> newClient(0));
  }

  @Test
  public void testReauthenticatesOnForbidden() throws Exception {
    VaultHttpClient client = newClient(1);
    issuedToken = "s.login-2";

    assertEquals("s3cret", client.readSecret(
        "secret/data/hadoop/creds/db.password", "value"));
    assertEquals(Arrays.asList(
        "POST " + DEFAULT_LOGIN_PATH, "POST " + DEFAULT_LOGIN_PATH),
        loginRequests);
  }

  @Test
  public void testProviderWithKerberosAuthMethod() throws Exception {
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
        "vault://http@localhost:" + port + "/secret/hadoop/creds");
    conf.set(VaultCredentialProviderConfig.AUTH_METHOD_KEY, "kerberos");
    conf.setInt(VaultCredentialProviderConfig.RETRY_COUNT_KEY, 0);

    assertEquals("s3cret", new String(conf.getPassword("db.password")));
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
      sendResponse(exchange, 403, PERMISSION_DENIED);
      return;
    }
    try {
      String principal = acceptSpnego(
          exchange.getRequestHeaders().getFirst("Authorization"));
      authenticatedPrincipals.add(principal);
      sendResponse(exchange, 200,
          "{\"auth\":{\"client_token\":\"" + issuedToken + "\"}}");
    } catch (Exception e) {
      sendResponse(exchange, 403,
          "{\"errors\":[\"spnego rejected: " + e + "\"]}");
    }
  }

  private static String acceptSpnego(String authorization) throws Exception {
    if (authorization == null || !authorization.startsWith(NEGOTIATE)) {
      throw new IOException("missing Negotiate header: " + authorization);
    }
    byte[] token = Base64.getDecoder().decode(
        authorization.substring(NEGOTIATE.length()));
    return serverUgi.doAs((PrivilegedExceptionAction<String>) () -> {
      GSSManager manager = GSSManager.getInstance();
      GSSCredential serverCreds = manager.createCredential(
          manager.createName(SERVER_PRINCIPAL + "@" + kdc.getRealm(),
              KerberosUtil.NT_GSS_KRB5_PRINCIPAL_OID),
          GSSCredential.INDEFINITE_LIFETIME,
          new Oid[] {KerberosUtil.GSS_SPNEGO_MECH_OID,
              KerberosUtil.GSS_KRB5_MECH_OID},
          GSSCredential.ACCEPT_ONLY);
      GSSContext context = manager.createContext(serverCreds);
      try {
        context.acceptSecContext(token, 0, token.length);
        if (!context.isEstablished()) {
          throw new GSSException(GSSException.DEFECTIVE_TOKEN);
        }
        return context.getSrcName().toString();
      } finally {
        context.dispose();
      }
    });
  }

  private void handleSecret(HttpExchange exchange) throws IOException {
    String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");
    if (issuedToken.equals(token)) {
      sendResponse(exchange, 200, "{\"data\":{\"data\":{\"value\":\"s3cret\"}}}");
    } else {
      sendResponse(exchange, 403, PERMISSION_DENIED);
    }
  }

  private static void sendResponse(HttpExchange exchange, int statusCode,
      String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(statusCode, bytes.length > 0 ? bytes.length : -1);
    if (bytes.length > 0) {
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(bytes);
      }
    }
    exchange.close();
  }
}
