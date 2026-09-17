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
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.DataOutputBuffer;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.WritableUtils;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.test.GenericTestUtils;
import org.apache.hadoop.thirdparty.com.google.common.base.Ticker;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.slf4j.LoggerFactory;

import static org.apache.hadoop.security.alias.vault.VaultKerberosTestFixture.CLIENT_PRINCIPAL;
import static org.apache.hadoop.security.alias.vault.VaultKerberosTestFixture.RENEWER_PRINCIPAL;
import static org.apache.hadoop.test.LambdaTestUtils.intercept;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * Delegation token round trips against a mock of the Vault Kerberos auth
 * backend: issue over SPNEGO as the current user, log in with the token
 * from a process without Kerberos credentials, renew and cancel as the
 * renewer.
 */
public class TestVaultDelegationTokens {

  private static final String AUTH_MOUNT = "auth/kerberos";
  private static final String LOGIN_PATH = "/v1/" + AUTH_MOUNT + "/login";
  private static final String DELEGATION_PREFIX =
      "/v1/" + AUTH_MOUNT + "/delegation/";
  private static final byte[] PASSWORD =
      "token-password".getBytes(StandardCharsets.UTF_8);
  private static final long RENEW_INTERVAL_MS = 3600_000L;
  private static final long MAX_LIFETIME_MS = 7 * 24 * 3600_000L;
  private static final ObjectMapper MAPPER = new ObjectMapper();

  @ClassRule
  public static final TemporaryFolder FOLDER = new TemporaryFolder();

  private static final VaultKerberosTestFixture KRB =
      new VaultKerberosTestFixture();

  private HttpServer server;
  private int port;
  private String providerUri;
  private Configuration conf;
  private UserGroupInformation clientUgi;
  /** Sequence number to expiry of the tokens the mock has issued. */
  private final Map<Integer, Long> expiries = new ConcurrentHashMap<>();
  private final AtomicInteger sequence = new AtomicInteger();
  private final Set<String> vaultTokens = ConcurrentHashMap.newKeySet();
  private final List<String> requests =
      Collections.synchronizedList(new ArrayList<>());
  /** Vault token each read of the secret carried. */
  private final List<String> secretReads =
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
    server.createContext("/v1/" + AUTH_MOUNT + "/", this::handleAuth);
    server.createContext(MockVault.SECRET_PATH, exchange -> {
      secretReads.add(exchange.getRequestHeaders().getFirst("X-Vault-Token"));
      MockVault.handleSecret(exchange, vaultTokens::contains);
    });
    server.start();

    providerUri = "vault://http@localhost:" + port + "/secret/hadoop/creds";
    conf = KRB.kerberosConf();
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
        providerUri);
    conf.setInt(VaultCredentialProviderConfig.RETRY_COUNT_KEY, 0);
    conf.setBoolean(VaultCredentialProviderConfig.CACHE_ENABLED_KEY, false);
    clientUgi = KRB.loginFromKeytab(CLIENT_PRINCIPAL);
    VaultCredentialProvider.clearCaches();
  }

  @After
  public void tearDown() {
    if (server != null) {
      server.stop(0);
    }
    UserGroupInformation.setLoginUser(null);
    VaultCredentialProvider.clearCaches();
  }

  @Test
  public void testTokenLoginWithoutKerberosCredentials() throws Exception {
    Credentials creds = new Credentials();
    VaultCredentialProvider provider = provider(conf);
    Token<?>[] issued = asClient(
        () -> provider.addDelegationTokens(RENEWER_PRINCIPAL, creds));

    assertEquals(1, issued.length);
    Token<?> token = issued[0];
    assertEquals(VaultDelegationTokenIdentifier.KIND_NAME, token.getKind());
    assertSame(token, creds.getToken(new Text(tokenService())));
    VaultDelegationTokenIdentifier id =
        (VaultDelegationTokenIdentifier) token.decodeIdentifier();
    assertEquals(KRB.principal(CLIENT_PRINCIPAL), id.getOwner().toString());
    assertEquals(RENEWER_PRINCIPAL, id.getRenewer().toString());
    assertEquals(0, asClient(
        () -> provider.addDelegationTokens(RENEWER_PRINCIPAL, creds)).length);

    String password = container(creds).doAs(
        (PrivilegedExceptionAction<String>) () ->
            new String(containerConf().getPassword("db.password")));

    assertEquals(MockVault.SECRET_VALUE, password);
    String client = KRB.principal(CLIENT_PRINCIPAL);
    assertEquals(Arrays.asList(
        "issue " + client + " renewer=" + RENEWER_PRINCIPAL,
        "token-login 1"), requests);
  }

  @Test
  public void testIssuerRequiresOwnKerberosLogin() throws Exception {
    GenericTestUtils.LogCapturer logs = GenericTestUtils.LogCapturer
        .captureLogs(LoggerFactory.getLogger(VaultCredentialProvider.class));
    VaultCredentialProvider provider = provider(conf);
    Credentials creds = new Credentials();
    UserGroupInformation nobody = UserGroupInformation.createRemoteUser("nobody");
    UserGroupInformation remote = UserGroupInformation.createRemoteUser("alice");
    remote.setAuthenticationMethod(
        UserGroupInformation.AuthenticationMethod.KERBEROS);
    UserGroupInformation proxy =
        UserGroupInformation.createProxyUser("bob", clientUgi);

    for (UserGroupInformation ugi : Arrays.asList(nobody, remote, proxy)) {
      assertNull(ugi.getUserName(), ugi.doAs(
          (PrivilegedExceptionAction<Token<?>>) () ->
              provider.getDelegationToken(RENEWER_PRINCIPAL)));
    }
    assertEquals(0, nobody.doAs((PrivilegedExceptionAction<Token<?>[]>) () ->
        provider.addDelegationTokens(RENEWER_PRINCIPAL, creds)).length);

    assertEquals(0, creds.numberOfTokens());
    assertFalse(requests.toString(),
        requests.stream().anyMatch(r -> r.startsWith("issue ")));
    assertTrue(logs.getOutput(),
        logs.getOutput().contains("a proxy user cannot own one"));
    assertTrue(logs.getOutput(),
        logs.getOutput().contains("the user has no Kerberos login"));
  }

  @Test
  public void testIssuerReturnsNullForTokenAuth() throws Exception {
    Configuration tokenConf = new Configuration(conf);
    tokenConf.set(VaultCredentialProviderConfig.AUTH_METHOD_KEY,
        VaultCredentialProviderConfig.AUTH_METHOD_TOKEN);
    tokenConf.set(VaultCredentialProviderConfig.TOKEN_KEY, "s.static");
    VaultCredentialProvider provider = provider(tokenConf);

    assertEquals(tokenService(), provider.getCanonicalServiceName());
    assertNull(asClient(() -> provider.getDelegationToken(RENEWER_PRINCIPAL)));
  }

  @Test
  public void testDelegationAuthMethodRequiresToken() throws Exception {
    Configuration containerConf = new Configuration(conf);
    containerConf.set(VaultCredentialProviderConfig.AUTH_METHOD_KEY,
        VaultCredentialProviderConfig.AUTH_METHOD_DELEGATION);
    IOException e = UserGroupInformation.createRemoteUser("spark").doAs(
        (PrivilegedExceptionAction<IOException>) () -> intercept(
            IOException.class, "Failed to resolve the Vault identity",
            () -> provider(containerConf).getCredentialEntry("db.password")));
    assertEquals("User spark has no Vault delegation token for "
        + serverService(), e.getCause().getMessage());
  }

  @Test
  public void testKerberosAuthWithoutCredentialsOrTokenFails()
      throws Exception {
    UserGroupInformation.setLoginUser(
        UserGroupInformation.createRemoteUser("os-user"));
    Configuration containerConf = new Configuration(conf);
    containerConf.set(VaultCredentialProviderConfig.KERBEROS_UGI_MODE_KEY,
        VaultCredentialProviderConfig.KERBEROS_UGI_MODE_CURRENT);
    IOException e = UserGroupInformation.createRemoteUser("nobody").doAs(
        (PrivilegedExceptionAction<IOException>) () -> intercept(
            IOException.class, "Failed to resolve the Vault identity",
            () -> provider(containerConf).getCredentialEntry("db.password")));
    assertEquals("User nobody has neither Kerberos credentials nor a Vault "
        + "delegation token for " + serverService()
        + ", and neither has the login user os-user",
        e.getCause().getMessage());
  }

  @Test
  public void testCallerWithoutCredentialsUsesTheLoginUser()
      throws Exception {
    UserGroupInformation.setLoginUser(clientUgi);
    Configuration currentConf = new Configuration(conf);
    currentConf.set(VaultCredentialProviderConfig.KERBEROS_UGI_MODE_KEY,
        VaultCredentialProviderConfig.KERBEROS_UGI_MODE_CURRENT);
    UserGroupInformation remote = UserGroupInformation.createRemoteUser("alice");
    remote.setAuthenticationMethod(
        UserGroupInformation.AuthenticationMethod.KERBEROS);

    assertEquals(MockVault.SECRET_VALUE,
        readAs(UserGroupInformation.createRemoteUser("nobody"), currentConf));
    assertEquals(MockVault.SECRET_VALUE, readAs(remote, currentConf));

    assertEquals(requests.toString(), 1, spnegoLoginCount());
    assertTrue(requests.toString(), requests.contains(
        "spnego-login " + KRB.principal(CLIENT_PRINCIPAL)));
  }

  @Test
  public void testDelegationAuthMethodIssuesTokens() throws Exception {
    Configuration delegationConf = new Configuration(conf);
    delegationConf.set(VaultCredentialProviderConfig.AUTH_METHOD_KEY,
        VaultCredentialProviderConfig.AUTH_METHOD_DELEGATION);
    VaultCredentialProvider provider = provider(delegationConf);

    Token<?> token = asClient(
        () -> provider.getDelegationToken(RENEWER_PRINCIPAL));

    assertEquals(VaultDelegationTokenIdentifier.KIND_NAME, token.getKind());
  }

  @Test
  public void testNoTokenWhenDelegationTokensAreDisabled() throws Exception {
    Configuration disabled = new Configuration(conf);
    disabled.setBoolean(
        VaultCredentialProviderConfig.DELEGATION_TOKEN_ENABLED_KEY, false);
    VaultCredentialProvider provider = provider(disabled);

    assertEquals(0, asClient(() -> provider.addDelegationTokens(
        RENEWER_PRINCIPAL, new Credentials())).length);
    assertFalse(requests.toString(),
        requests.stream().anyMatch(r -> r.startsWith("issue ")));
  }

  @Test
  public void testAnUnrenewableTokenHasNoRenewer() throws Exception {
    Configuration unrenewable = new Configuration(conf);
    unrenewable.setBoolean(
        VaultCredentialProviderConfig.DELEGATION_TOKEN_RENEWABLE_KEY, false);
    VaultCredentialProvider provider = provider(unrenewable);

    Token<?> token = asClient(
        () -> provider.getDelegationToken(RENEWER_PRINCIPAL));

    assertEquals("", renewerOf(token));
    assertTrue(requests.toString(), requests.contains(
        "issue " + KRB.principal(CLIENT_PRINCIPAL) + " renewer="));
  }

  @Test
  public void testTokenOfAProxyLoginUserIsUsed() throws Exception {
    UserGroupInformation proxy = UserGroupInformation.createProxyUser("bob",
        UserGroupInformation.createRemoteUser("os-user"));
    proxy.addCredentials(credentialsWithToken());

    assertEquals(MockVault.SECRET_VALUE, readAs(proxy, containerConf()));
    assertTrue(requests.toString(), requests.contains("token-login 1"));
  }

  @Test
  public void testRenewerRefusesAServerThisHostIsNotConfiguredFor()
      throws Exception {
    Token<?> token = issueToken(RENEWER_PRINCIPAL);
    UserGroupInformation renewer = KRB.loginFromKeytab(RENEWER_PRINCIPAL);
    Configuration other = rmConf();
    other.set(VaultCredentialProviderConfig.DELEGATION_TOKEN_SERVERS_KEY,
        "https@vault.example.com:8200");

    renewer.doAs((PrivilegedExceptionAction<Void>) () -> {
      intercept(IOException.class, "is not one this host is configured for",
          () -> token.renew(other));
      return null;
    });
    assertFalse(requests.toString(),
        requests.stream().anyMatch(r -> r.startsWith("renew ")));

    Configuration listed = rmConf();
    listed.set(VaultCredentialProviderConfig.DELEGATION_TOKEN_SERVERS_KEY,
        "https@vault.example.com:8200, http@localhost:" + port);
    long expiry = renewer.doAs(
        (PrivilegedExceptionAction<Long>) () -> token.renew(listed));
    assertEquals(expiries.get(1).longValue(), expiry);

    Configuration fromProviderPath = rmConf();
    fromProviderPath.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
        "jceks://file/tmp/other.jceks," + providerUri);
    expiry = renewer.doAs(
        (PrivilegedExceptionAction<Long>) () -> token.renew(fromProviderPath));
    assertEquals(expiries.get(1).longValue(), expiry);
  }

  @Test
  public void testRenewAndCancelAsRenewer() throws Exception {
    Token<?> token = issueToken(RENEWER_PRINCIPAL);
    Configuration rmConf = rmConf();
    UserGroupInformation renewer = KRB.loginFromKeytab(RENEWER_PRINCIPAL);

    long expiry = renewer.doAs(
        (PrivilegedExceptionAction<Long>) () -> token.renew(rmConf));
    assertEquals(expiries.get(1).longValue(), expiry);

    renewer.doAs((PrivilegedExceptionAction<Void>) () -> {
      token.cancel(rmConf);
      return null;
    });
    assertFalse(expiries.containsKey(1));

    Credentials creds = new Credentials();
    creds.addToken(token.getService(), token);
    Configuration containerConf = containerConf();
    containerConf.set(VaultCredentialProviderConfig.AUTH_METHOD_KEY,
        VaultCredentialProviderConfig.AUTH_METHOD_DELEGATION);
    IOException e = container(creds).doAs(
        (PrivilegedExceptionAction<IOException>) () -> intercept(
            IOException.class, "Failed to create VaultHttpClient",
            () -> provider(containerConf).getCredentialEntry("db.password")));
    assertTrue(e.getCause().getMessage(), e.getCause().getMessage().contains(
        "Vault delegation token login to http://localhost:" + port
            + LOGIN_PATH + " failed with status 403"));
  }

  @Test
  public void testRenewerIsRecordedByPrimaryForOwnerRealm()
      throws Exception {
    String client = KRB.principal(CLIENT_PRINCIPAL);

    Token<?> sameRealm = issueToken(
        RENEWER_PRINCIPAL + "/rm1.example.com@" + KRB.realm());
    assertEquals(RENEWER_PRINCIPAL, renewerOf(sameRealm));
    assertTrue(requests.toString(), requests.contains(
        "issue " + client + " renewer=" + RENEWER_PRINCIPAL));

    String foreign = RENEWER_PRINCIPAL + "/rm1.example.com@OTHER.REALM";
    assertEquals(foreign, renewerOf(issueToken(foreign)));

    assertEquals("", renewerOf(issueToken(null)));

    Configuration rmConf = rmConf();
    long expiry = KRB.loginFromKeytab(RENEWER_PRINCIPAL).doAs(
        (PrivilegedExceptionAction<Long>) () -> sameRealm.renew(rmConf));
    assertEquals(expiries.get(1).longValue(), expiry);
  }

  @Test
  public void testRenewRejectsNonRenewer() throws Exception {
    Token<?> token = issueToken(RENEWER_PRINCIPAL);
    Configuration rmConf = rmConf();

    clientUgi.doAs((PrivilegedExceptionAction<Void>) () -> {
      intercept(IOException.class,
          "Vault delegation token renewal to http://localhost:" + port
              + DELEGATION_PREFIX + "renew failed with status 403",
          () -> token.renew(rmConf));
      return null;
    });
    assertTrue(expiries.containsKey(1));
  }

  @Test
  public void testRenewerHandlesOnlyVaultTokens() throws Exception {
    VaultDelegationTokenRenewer renewer = new VaultDelegationTokenRenewer();
    assertTrue(renewer.handleKind(VaultDelegationTokenIdentifier.KIND_NAME));
    assertFalse(renewer.handleKind(new Text("HDFS_DELEGATION_TOKEN")));
    assertTrue(renewer.isManaged(new Token<>()));
  }

  @Test
  public void testContainerPicksUpReplacedToken() throws Exception {
    Credentials creds = new Credentials();
    Token<?> first = issueToken(RENEWER_PRINCIPAL);
    creds.addToken(first.getService(), first);
    UserGroupInformation container = container(creds);
    Configuration containerConf = containerConf();
    containerConf.setInt(VaultCredentialProviderConfig.RETRY_COUNT_KEY, 1);
    containerConf.setInt(VaultCredentialProviderConfig.RETRY_INTERVAL_MS_KEY,
        10);
    PrivilegedExceptionAction<String> read = () ->
        new String(containerConf.getPassword("db.password"));

    assertEquals(MockVault.SECRET_VALUE, container.doAs(read));

    expiries.remove(1);
    vaultTokens.remove("s.dt-1");
    Token<?> second = issueToken(RENEWER_PRINCIPAL);
    Credentials replaced = new Credentials();
    replaced.addToken(second.getService(), second);
    container.addCredentials(replaced);

    assertEquals(MockVault.SECRET_VALUE, container.doAs(read));
    assertTrue(requests.toString(), requests.contains("token-login 2"));
  }

  @Test
  public void testKerberosClientIsReusedForOneIdentity() throws Exception {
    assertEquals(MockVault.SECRET_VALUE, readAs(clientUgi, conf));
    assertEquals(MockVault.SECRET_VALUE, readAs(clientUgi, conf));

    assertEquals(requests.toString(), 1, spnegoLoginCount());
  }

  @Test
  public void testTheClientIsBuiltOnFirstUseNotOnConstruction()
      throws Exception {
    VaultCredentialProvider provider = provider(conf);

    assertEquals(requests.toString(), 0, requests.size());

    assertEquals(MockVault.SECRET_VALUE, new String(
        provider.getCredentialEntry("db.password").getCredential()));
    assertEquals(requests.toString(), 1, spnegoLoginCount());
  }

  @Test
  public void testCacheSettingsOfALaterConfigurationAreReported()
      throws Exception {
    GenericTestUtils.LogCapturer logs = GenericTestUtils.LogCapturer
        .captureLogs(LoggerFactory.getLogger(VaultCredentialProvider.class));
    readAs(clientUgi, conf);

    Configuration lateConf = new Configuration(conf);
    lateConf.setInt(
        VaultCredentialProviderConfig.CLIENT_CACHE_MAX_SIZE_KEY, 8);
    readAs(clientUgi, lateConf);

    assertTrue(logs.getOutput(), logs.getOutput().contains(
        VaultCredentialProviderConfig.CLIENT_CACHE_MAX_SIZE_KEY + "=8"));
  }

  @Test
  public void testDefaultCacheSettingsAreNotReportedAsIgnored()
      throws Exception {
    GenericTestUtils.LogCapturer logs = GenericTestUtils.LogCapturer
        .captureLogs(LoggerFactory.getLogger(VaultCredentialProvider.class));
    Configuration tunedConf = new Configuration(conf);
    tunedConf.setInt(
        VaultCredentialProviderConfig.CLIENT_CACHE_MAX_SIZE_KEY, 8);
    readAs(clientUgi, tunedConf);

    readAs(clientUgi, conf);

    assertFalse(logs.getOutput(), logs.getOutput().contains("is ignored"));
  }

  @Test
  public void testIdleClientIsDroppedFromTheCache() throws Exception {
    MovingTicker ticker = new MovingTicker();
    VaultCredentialProvider.setClientCacheTicker(ticker);

    assertEquals(MockVault.SECRET_VALUE, readAs(clientUgi, conf));
    assertEquals(MockVault.SECRET_VALUE, readAs(clientUgi, conf));
    assertEquals(requests.toString(), 1, spnegoLoginCount());

    ticker.advanceMs(
        VaultCredentialProviderConfig.CLIENT_CACHE_IDLE_MS_DEFAULT + 1);
    assertEquals(MockVault.SECRET_VALUE, readAs(clientUgi, conf));

    assertEquals(requests.toString(), 2, spnegoLoginCount());
  }

  @Test
  public void testTheClientOutlivesAnIdleClientCacheWhenNotBound()
      throws Exception {
    MovingTicker ticker = new MovingTicker();
    VaultCredentialProvider.setClientCacheTicker(ticker);
    conf.setLong(VaultCredentialProviderConfig.CLIENT_CACHE_IDLE_MS_KEY, 0);

    assertEquals(MockVault.SECRET_VALUE, readAs(clientUgi, conf));
    ticker.advanceMs(TimeUnit.DAYS.toMillis(7));
    assertEquals(MockVault.SECRET_VALUE, readAs(clientUgi, conf));

    assertEquals(requests.toString(), 1, spnegoLoginCount());
  }

  /** A clock the test moves by hand. */
  private static final class MovingTicker extends Ticker {
    private final AtomicLong nanos = new AtomicLong();

    void advanceMs(long ms) {
      nanos.addAndGet(TimeUnit.MILLISECONDS.toNanos(ms));
    }

    @Override
    public long read() {
      return nanos.get();
    }
  }

  @Test
  public void testClientIsNotSharedBetweenSessionsOfOneUser()
      throws Exception {
    Configuration containerConf = containerConf();
    UserGroupInformation session = container("spark", credentialsWithToken());
    UserGroupInformation other = container("spark", credentialsWithToken());

    assertEquals(MockVault.SECRET_VALUE, readAs(session, containerConf));
    assertEquals(MockVault.SECRET_VALUE, readAs(other, containerConf));

    assertEquals(requests.toString(), 2, loginCount());
    assertEquals(secretReads.toString(),
        Arrays.asList("s.dt-1", "s.dt-2"), secretReads);
  }

  @Test
  public void testRevokedTokenOfAnotherSessionIsRejected() throws Exception {
    Configuration containerConf = containerConf();
    UserGroupInformation session = container("spark", credentialsWithToken());
    Credentials revoked = credentialsWithToken();
    expiries.remove(2);

    assertEquals(MockVault.SECRET_VALUE, readAs(session, containerConf));

    intercept(IOException.class, "Configuration problem with provider path",
        () -> readAs(container("spark", revoked), containerConf));
    assertEquals(secretReads.toString(),
        Collections.singletonList("s.dt-1"), secretReads);
  }

  @Test
  public void testDelegationLoginUsesItsOwnersToken() throws Exception {
    UserGroupInformation owner = container("spark", credentialsWithToken());
    UserGroupInformation caller = container("hive", credentialsWithToken());
    VaultConnectionInfo vault = new VaultConnectionInfo(new URI(providerUri));
    VaultAuthMethod auth =
        new VaultDelegationTokenAuth(vault, AUTH_MOUNT, owner);

    caller.doAs((PrivilegedExceptionAction<String>) () ->
        auth.authenticate(VaultHttpClient.unauthenticated(conf, vault)));

    assertTrue(requests.toString(), requests.contains("token-login 1"));
    assertFalse(requests.toString(), requests.contains("token-login 2"));
  }

  @Test
  public void testClientIsReusedWithinOneSession() throws Exception {
    Configuration containerConf = containerConf();
    UserGroupInformation session = container("spark", credentialsWithToken());

    assertEquals(MockVault.SECRET_VALUE, readAs(session, containerConf));
    assertEquals(MockVault.SECRET_VALUE, readAs(session, containerConf));

    assertEquals(requests.toString(), 1, loginCount());
    assertEquals(2, secretReads.size());
  }

  @Test
  public void testCachedSecretIsNotServedToAnotherSession() throws Exception {
    Configuration containerConf = containerConf();
    containerConf.setBoolean(VaultCredentialProviderConfig.CACHE_ENABLED_KEY,
        true);
    UserGroupInformation session = container("spark", credentialsWithToken());
    UserGroupInformation other = container("spark", credentialsWithToken());

    assertEquals(MockVault.SECRET_VALUE, readAs(session, containerConf));
    assertEquals(MockVault.SECRET_VALUE, readAs(session, containerConf));
    assertEquals(MockVault.SECRET_VALUE, readAs(other, containerConf));

    assertEquals(secretReads.toString(), Arrays.asList("s.dt-1", "s.dt-2"),
        secretReads);
  }

  @Test
  public void testTokenFoundByServerWhenConfiguredMountDiffers()
      throws Exception {
    Credentials creds = new Credentials();
    Token<?> token = issueToken(RENEWER_PRINCIPAL);
    creds.addToken(token.getService(), token);
    Configuration containerConf = containerConf();
    containerConf.set(VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_KEY,
        "auth/other");

    String password = container(creds).doAs(
        (PrivilegedExceptionAction<String>) () ->
            new String(containerConf.getPassword("db.password")));

    assertEquals(MockVault.SECRET_VALUE, password);
    assertTrue(requests.toString(), requests.contains("token-login 1"));
  }

  private String serverService() {
    return "vault://http@localhost:" + port;
  }

  private String tokenService() {
    return serverService() + "/" + AUTH_MOUNT;
  }

  private VaultCredentialProvider provider(Configuration providerConf)
      throws Exception {
    return new VaultCredentialProvider(new URI(providerUri), providerConf);
  }

  private <T> T asClient(PrivilegedExceptionAction<T> action)
      throws Exception {
    return clientUgi.doAs(action);
  }

  private Token<?> issueToken(String renewer) throws Exception {
    VaultCredentialProvider provider = provider(conf);
    return asClient(() -> provider.getDelegationToken(renewer));
  }

  private static String renewerOf(Token<?> token) throws IOException {
    return ((VaultDelegationTokenIdentifier) token.decodeIdentifier())
        .getRenewer().toString();
  }

  /** A YARN container: no Kerberos credentials, only the job's tokens. */
  private UserGroupInformation container(Credentials creds) {
    VaultCredentialProvider.clearCaches();
    return container("spark", creds);
  }

  /** A YARN container of the given user. */
  private UserGroupInformation container(String user, Credentials creds) {
    UserGroupInformation container =
        UserGroupInformation.createRemoteUser(user);
    container.addCredentials(creds);
    return container;
  }

  /** Credentials holding a token this server has just issued. */
  private Credentials credentialsWithToken() throws Exception {
    Credentials creds = new Credentials();
    Token<?> token = issueToken(RENEWER_PRINCIPAL);
    creds.addToken(token.getService(), token);
    return creds;
  }

  private long spnegoLoginCount() {
    return requests.stream().filter(r -> r.startsWith("spnego-login")).count();
  }

  private long loginCount() {
    return requests.stream().filter(r -> r.startsWith("token-login")).count();
  }

  private String readAs(UserGroupInformation session,
      Configuration sessionConf) throws Exception {
    return session.doAs((PrivilegedExceptionAction<String>) () ->
        new String(sessionConf.getPassword("db.password")));
  }

  /** Cluster core-site as seen in a container: no principal or keytab. */
  private Configuration containerConf() {
    Configuration containerConf = new Configuration();
    containerConf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
        providerUri);
    containerConf.set(VaultCredentialProviderConfig.AUTH_METHOD_KEY,
        VaultCredentialProviderConfig.AUTH_METHOD_KERBEROS);
    containerConf.setInt(VaultCredentialProviderConfig.RETRY_COUNT_KEY, 0);
    containerConf.setBoolean(VaultCredentialProviderConfig.CACHE_ENABLED_KEY,
        false);
    return containerConf;
  }

  /** ResourceManager configuration: only the Vault service principal. */
  private Configuration rmConf() {
    Configuration rmConf = new Configuration();
    rmConf.set(VaultCredentialProviderConfig.KERBEROS_SERVICE_PRINCIPAL_KEY,
        "HTTP/_HOST@" + KRB.realm());
    return rmConf;
  }

  /**
   * Mock of the Kerberos auth backend: {@code login} takes SPNEGO or a
   * delegation token, {@code delegation/*} takes SPNEGO only.
   */
  private void handleAuth(HttpExchange exchange) throws IOException {
    String path = exchange.getRequestURI().getPath();
    String body = IOUtils.toString(exchange.getRequestBody(),
        StandardCharsets.UTF_8);
    JsonNode json = body.isEmpty() ? MAPPER.createObjectNode()
        : MAPPER.readTree(body);
    String authorization =
        exchange.getRequestHeaders().getFirst("Authorization");
    try {
      if (path.equals(LOGIN_PATH)) {
        handleLogin(exchange, json, authorization);
      } else if (path.startsWith(DELEGATION_PREFIX)) {
        handleDelegation(exchange, path.substring(DELEGATION_PREFIX.length()),
            json, KRB.acceptSpnego(authorization));
      } else {
        MockVault.sendResponse(exchange, 403, MockVault.PERMISSION_DENIED);
      }
    } catch (Exception e) {
      MockVault.sendResponse(exchange, 403, "{\"errors\":[\"" + e + "\"]}");
    }
  }

  private void handleLogin(HttpExchange exchange, JsonNode json,
      String authorization) throws Exception {
    String vaultToken;
    if (json.has("delegation_token")) {
      Token<?> token = decodeToken(json.path("delegation_token").asText());
      int seq = identifier(token).getSequenceNumber();
      Long expiry = expiries.get(seq);
      if (expiry == null || expiry < System.currentTimeMillis()
          || !Arrays.equals(PASSWORD, token.getPassword())) {
        MockVault.sendResponse(exchange, 403, MockVault.PERMISSION_DENIED);
        return;
      }
      vaultToken = "s.dt-" + seq;
      requests.add("token-login " + seq);
    } else {
      String principal = KRB.acceptSpnego(authorization);
      vaultToken = "s.spnego";
      requests.add("spnego-login " + principal);
    }
    vaultTokens.add(vaultToken);
    MockVault.sendResponse(exchange, 200,
        "{\"auth\":{\"client_token\":\"" + vaultToken + "\"}}");
  }

  private void handleDelegation(HttpExchange exchange, String action,
      JsonNode json, String principal) throws Exception {
    long now = System.currentTimeMillis();
    if (action.equals("token")) {
      String renewer = json.path("renewer").asText("");
      int seq = sequence.incrementAndGet();
      Token<VaultDelegationTokenIdentifier> token = new Token<>(
          rawIdentifier(principal, renewer, seq, now), PASSWORD,
          VaultDelegationTokenIdentifier.KIND_NAME,
          new Text(json.path("service").asText("")));
      expiries.put(seq, now + RENEW_INTERVAL_MS);
      requests.add("issue " + principal + " renewer=" + renewer);
      MockVault.sendResponse(exchange, 200, "{\"data\":{\"token\":\""
          + token.encodeToUrlString() + "\",\"expiry\":"
          + expiries.get(seq) + ",\"sequence_number\":" + seq + "}}");
      return;
    }

    Token<?> token = decodeToken(json.path("token").asText());
    VaultDelegationTokenIdentifier id = identifier(token);
    int seq = id.getSequenceNumber();
    if (!expiries.containsKey(seq)
        || !Arrays.equals(PASSWORD, token.getPassword())) {
      MockVault.sendResponse(exchange, 403, MockVault.PERMISSION_DENIED);
      return;
    }
    boolean isRenewer = callerMatches(principal, id.getRenewer().toString());
    boolean isOwner = principal.equals(id.getOwner().toString());
    if (action.equals("renew") && isRenewer) {
      expiries.put(seq, now + RENEW_INTERVAL_MS);
      requests.add("renew " + seq + " by " + principal);
      MockVault.sendResponse(exchange, 200,
          "{\"data\":{\"expiry\":" + expiries.get(seq) + "}}");
    } else if (action.equals("cancel") && (isRenewer || isOwner)) {
      expiries.remove(seq);
      MockVault.sendResponse(exchange, 204, "");
    } else {
      MockVault.sendResponse(exchange, 403, "{\"errors\":[\"principal "
          + principal + " may not " + action + " delegation token " + seq
          + "\"]}");
    }
  }

  /**
   * Vault's renewer rule: the full principal, or for callers from the
   * owner's realm the primary/instance or bare primary.
   */
  private boolean callerMatches(String principal, String name) {
    if (name.equals(principal)) {
      return true;
    }
    int at = principal.indexOf('@');
    if (!principal.substring(at + 1).equals(KRB.realm())) {
      return false;
    }
    String user = principal.substring(0, at);
    int slash = user.indexOf('/');
    String primary = slash < 0 ? user : user.substring(0, slash);
    return name.equals(user) || name.equals(primary);
  }

  /**
   * Identifier bytes as the server writes them: the renewer is recorded
   * exactly as requested, without auth_to_local shortening.
   */
  private static byte[] rawIdentifier(String owner, String renewer, int seq,
      long now) throws IOException {
    DataOutputBuffer out = new DataOutputBuffer();
    out.writeByte(0);
    new Text(owner).write(out);
    new Text(renewer).write(out);
    new Text("").write(out);
    WritableUtils.writeVLong(out, now);
    WritableUtils.writeVLong(out, now + MAX_LIFETIME_MS);
    WritableUtils.writeVInt(out, seq);
    WritableUtils.writeVInt(out, 1);
    return Arrays.copyOf(out.getData(), out.getLength());
  }

  private static Token<?> decodeToken(String encoded) throws IOException {
    Token<VaultDelegationTokenIdentifier> token = new Token<>();
    token.decodeFromUrlString(encoded);
    return token;
  }

  private static VaultDelegationTokenIdentifier identifier(Token<?> token)
      throws IOException {
    return (VaultDelegationTokenIdentifier) token.decodeIdentifier();
  }
}
