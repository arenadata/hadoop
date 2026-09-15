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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedExceptionAction;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;

/**
 * Tests for {@link VaultClientIdentity}: which callers share a Vault
 * client, and which must never share one.
 */
public class TestVaultClientIdentity {

  private static final String URI_STRING =
      "vault://https@vault.example.com:8200/secret/hadoop/creds";

  private VaultConnectionInfo connInfo;

  @Before
  public void setUp() throws Exception {
    connInfo = new VaultConnectionInfo(new URI(URI_STRING));
  }

  @Test
  public void testTokenIdentityFollowsTheConfiguredToken() throws Exception {
    VaultClientIdentity first = identity(tokenConf("s.tenant-a"));
    VaultClientIdentity second = identity(tokenConf("s.tenant-b"));
    VaultClientIdentity sameAsFirst = identity(tokenConf("s.tenant-a"));

    assertNotEquals(first, second);
    assertEquals(first, sameAsFirst);
    assertFalse(first.toString(), first.toString().contains("s.tenant-a"));
  }

  @Test
  public void testDedicatedKerberosIdentityIsSharedByEveryCaller()
      throws Exception {
    Configuration conf = dedicatedConf();

    assertEquals(identityAs("alice", conf), identityAs("bob", conf));
  }

  @Test
  public void testDedicatedKerberosIdentityFollowsThePrincipal()
      throws Exception {
    Configuration other = dedicatedConf();
    other.set(VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY,
        "other/_HOST@EXAMPLE.COM");

    assertNotEquals(identity(dedicatedConf()), identity(other));
  }

  @Test
  public void testDedicatedKerberosIdentityFollowsTheKeytab()
      throws Exception {
    Configuration rotated = dedicatedConf();
    rotated.set(VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY,
        "/etc/security/keytabs/vault.new.keytab");

    assertNotEquals(identity(dedicatedConf()), identity(rotated));
  }

  @Test
  public void testCurrentUgiIdentityIsPerSession() throws Exception {
    Configuration conf = currentUgiConf();
    UserGroupInformation session = kerberosUser("spark");
    UserGroupInformation otherSession = kerberosUser("spark");

    VaultClientIdentity identity = identityAs(session, conf);

    assertEquals(identity, identityAs(session, conf));
    assertNotEquals("sessions of one user name must not share a client",
        identity, identityAs(otherSession, conf));
  }

  @Test
  public void testDelegationIdentityIsPerSession() throws Exception {
    Configuration conf = new Configuration(false);
    conf.set(VaultCredentialProviderConfig.AUTH_METHOD_KEY,
        VaultCredentialProviderConfig.AUTH_METHOD_DELEGATION);
    conf.set(VaultCredentialProviderConfig.KERBEROS_LOGIN_PATH_KEY,
        "auth/kerberos");
    UserGroupInformation container = containerWithToken("spark");
    UserGroupInformation otherContainer = containerWithToken("spark");

    VaultClientIdentity identity = identityAs(container, conf);

    assertEquals(identity, identityAs(container, conf));
    assertNotEquals("containers of one user name must not share a client",
        identity, identityAs(otherContainer, conf));
  }

  private VaultClientIdentity identity(Configuration conf) throws Exception {
    return VaultClientIdentity.of(conf, connInfo);
  }

  private VaultClientIdentity identityAs(String user, Configuration conf)
      throws Exception {
    return identityAs(kerberosUser(user), conf);
  }

  private VaultClientIdentity identityAs(UserGroupInformation ugi,
      Configuration conf) throws Exception {
    return ugi.doAs((PrivilegedExceptionAction<VaultClientIdentity>) () ->
        identity(conf));
  }

  /** A UGI that reports Kerberos credentials without a real login. */
  private static UserGroupInformation kerberosUser(String name) {
    UserGroupInformation ugi = UserGroupInformation.createRemoteUser(name);
    ugi.setAuthenticationMethod(
        UserGroupInformation.AuthenticationMethod.KERBEROS);
    return ugi;
  }

  /** A YARN container: no Kerberos credentials, one Vault token. */
  private UserGroupInformation containerWithToken(String name) {
    UserGroupInformation container =
        UserGroupInformation.createRemoteUser(name);
    Text service = new Text(connInfo.getTokenService("auth/kerberos"));
    container.addToken(service, new Token<>(
        "identifier".getBytes(StandardCharsets.UTF_8),
        "password".getBytes(StandardCharsets.UTF_8),
        VaultDelegationTokenIdentifier.KIND_NAME, service));
    return container;
  }

  private static Configuration tokenConf(String token) {
    Configuration conf = new Configuration(false);
    conf.set(VaultCredentialProviderConfig.TOKEN_KEY, token);
    return conf;
  }

  private static Configuration dedicatedConf() {
    Configuration conf = new Configuration(false);
    conf.set(VaultCredentialProviderConfig.AUTH_METHOD_KEY,
        VaultCredentialProviderConfig.AUTH_METHOD_KERBEROS);
    conf.set(VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY,
        "vault/_HOST@EXAMPLE.COM");
    conf.set(VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY,
        "/etc/security/keytabs/vault.service.keytab");
    return conf;
  }

  private static Configuration currentUgiConf() {
    Configuration conf = dedicatedConf();
    conf.set(VaultCredentialProviderConfig.KERBEROS_UGI_MODE_KEY,
        VaultCredentialProviderConfig.KERBEROS_UGI_MODE_CURRENT);
    return conf;
  }
}
