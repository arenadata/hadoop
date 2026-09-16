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
import java.net.InetAddress;
import java.util.Objects;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeysPublic;
import org.apache.hadoop.net.DNS;
import org.apache.hadoop.security.SecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Vault identity a client authenticates as, and the key the cached
 * clients and credentials are held under. A client is reused only for an
 * equal identity, so an identity names everything Vault grants access on:
 * the server, the auth mount, and the credential that is presented.
 *
 * <p>A user is held as a {@link UserGroupInformation}, which compares by
 * subject, following {@code FileSystem.Cache.Key}: two sessions of one
 * user name are different identities, so neither can use the other's
 * client or read its cached secrets.
 *
 * <p>Choosing an identity must not contact the KDC or Vault;
 * {@link #createAuthMethod} runs only when no client for the identity is
 * cached yet.
 */
@InterfaceAudience.Private
abstract class VaultClientIdentity {

  private static final Logger LOG =
      LoggerFactory.getLogger(VaultClientIdentity.class);

  /** Properties that shape the client, beyond the credential it presents. */
  private static final String[] CLIENT_SETTINGS = {
      VaultCredentialProviderConfig.CONNECTION_TIMEOUT_MS_KEY,
      VaultCredentialProviderConfig.READ_TIMEOUT_MS_KEY,
      VaultCredentialProviderConfig.RETRY_COUNT_KEY,
      VaultCredentialProviderConfig.RETRY_INTERVAL_MS_KEY,
      VaultCredentialProviderConfig.SSL_TRUSTSTORE_LOCATION_KEY,
      VaultCredentialProviderConfig.SSL_TRUSTSTORE_TYPE_KEY,
      VaultCredentialProviderConfig.KERBEROS_SERVICE_PRINCIPAL_KEY,
  };

  private final String baseUrl;
  private final String settings;

  private VaultClientIdentity(String baseUrl, String settings) {
    this.baseUrl = baseUrl;
    this.settings = settings;
  }

  /**
   * The client is built from the configuration that first asked for this
   * identity, so two configurations that would build different clients
   * are different identities.
   */
  private static String clientSettings(Configuration conf) {
    StringBuilder sb = new StringBuilder();
    for (String key : CLIENT_SETTINGS) {
      sb.append(conf.getTrimmed(key, "")).append('\n');
    }
    return sb.toString();
  }

  /** Whether the server and the client settings are the same. */
  final boolean sameClient(VaultClientIdentity that) {
    return baseUrl.equals(that.baseUrl) && settings.equals(that.settings);
  }

  /**
   * Build the auth method of this identity, logging in from a keytab if
   * that is what the identity names.
   *
   * @param conf the configuration the provider was created with
   * @param connInfo the Vault server
   * @return the auth method
   * @throws IOException if a keytab login fails
   */
  abstract VaultAuthMethod createAuthMethod(Configuration conf,
      VaultConnectionInfo connInfo) throws IOException;

  /**
   * The identity the configuration and the caller's credentials select.
   * The caller is the current user, or the real user behind a proxy user.
   * With {@code kerberos} and {@code ugi.mode=current}, a caller holding a
   * Kerberos login authenticates with it; a caller holding a Vault
   * delegation token for this server (a YARN container) logs in with the
   * token; any other caller, such as a remote user inside a server,
   * authenticates as the process login user. With {@code ugi.mode=dedicated}
   * the configured keytab authenticates, except for a caller that holds a
   * token and no Kerberos login.
   *
   * @param conf the configuration
   * @param connInfo the Vault server
   * @return the identity
   * @throws IOException if the auth method is unsupported, or nobody on
   *     the calling thread has credentials to authenticate with
   */
  static VaultClientIdentity of(Configuration conf,
      VaultConnectionInfo connInfo) throws IOException {
    String baseUrl = connInfo.getBaseUrl();
    String settings = clientSettings(conf);
    String name = VaultCredentialProviderConfig.authMethod(conf);
    if (VaultCredentialProviderConfig.AUTH_METHOD_TOKEN
        .equalsIgnoreCase(name)) {
      return new OfToken(baseUrl, settings, tokenSource(conf));
    }
    boolean delegation = VaultCredentialProviderConfig.AUTH_METHOD_DELEGATION
        .equalsIgnoreCase(name);
    if (!delegation && !VaultCredentialProviderConfig.AUTH_METHOD_KERBEROS
        .equalsIgnoreCase(name)) {
      throw new IOException("Unsupported Vault auth method '" + name
          + "'; expected " + VaultCredentialProviderConfig.AUTH_METHOD_TOKEN
          + ", " + VaultCredentialProviderConfig.AUTH_METHOD_KERBEROS + " or "
          + VaultCredentialProviderConfig.AUTH_METHOD_DELEGATION);
    }
    String mountPath = VaultAuthRequests.mountPath(conf);
    String server = connInfo.getServerService();
    UserGroupInformation caller = UserGroupInformation.getCurrentUser();
    UserGroupInformation tokenHolder =
        VaultDelegationTokens.tokenHolder(caller, connInfo, mountPath);
    if (delegation) {
      if (tokenHolder == null) {
        throw new IOException("User " + caller.getUserName()
            + " has no Vault delegation token for " + server);
      }
      return new OfDelegationToken(baseUrl, settings, mountPath, tokenHolder);
    }
    UserGroupInformation login = VaultDelegationTokens.kerberosLogin(caller);
    if (!isCurrentUgiMode(conf)) {
      return login == null && tokenHolder != null
          ? new OfDelegationToken(baseUrl, settings, mountPath, tokenHolder)
          : OfKerberos.ofKeytab(baseUrl, settings, mountPath, conf);
    }
    if (login != null) {
      return OfKerberos.ofUser(baseUrl, settings, mountPath, login);
    }
    if (tokenHolder != null) {
      LOG.debug("User {} has no Kerberos login, using the Vault delegation "
          + "token for {}", caller.getUserName(), server);
      return new OfDelegationToken(baseUrl, settings, mountPath, tokenHolder);
    }
    UserGroupInformation loginUser = UserGroupInformation.getLoginUser();
    if (loginUser.shouldRelogin()) {
      LOG.debug("User {} has neither a Kerberos login nor a Vault delegation "
          + "token for {}, using the login user {}", caller.getUserName(),
          server, loginUser.getUserName());
      return OfKerberos.ofUser(baseUrl, settings, mountPath, loginUser);
    }
    throw new IOException("User " + caller.getUserName()
        + " has neither Kerberos credentials nor a Vault delegation token for "
        + server + ", and neither has the login user "
        + loginUser.getUserName());
  }

  /**
   * Log in from a keytab, which needs Hadoop security to be on: without
   * it the login silently yields the current user.
   */
  static UserGroupInformation loginFromKeytab(String principal, String keytab)
      throws IOException {
    if (!UserGroupInformation.isSecurityEnabled()) {
      throw new IOException("Kerberos auth to Vault as " + principal
          + " requires hadoop.security.authentication=kerberos");
    }
    return UserGroupInformation.loginUserFromKeytabAndReturnUGI(principal,
        keytab);
  }

  /**
   * The configured principal with {@code _HOST} expanded to the local
   * host name the way the daemon logins expand it.
   *
   * @param principal the configured principal
   * @param conf the configuration naming the interface to resolve by
   * @return the principal to authenticate as
   * @throws IOException if the host name cannot be resolved
   */
  static String serverPrincipal(String principal, Configuration conf)
      throws IOException {
    if (!principal.contains(SecurityUtil.HOSTNAME_PATTERN)) {
      return principal;
    }
    return SecurityUtil.getServerPrincipal(principal, localHostName(conf));
  }

  /** The local host name as SecurityUtil.login resolves it. */
  private static String localHostName(Configuration conf) throws IOException {
    String dnsInterface = conf.getTrimmed(
        CommonConfigurationKeysPublic.HADOOP_SECURITY_DNS_INTERFACE_KEY);
    String nameServer = conf.getTrimmed(
        CommonConfigurationKeysPublic.HADOOP_SECURITY_DNS_NAMESERVER_KEY);
    if (dnsInterface != null && !dnsInterface.isEmpty()) {
      return DNS.getDefaultHost(dnsInterface, nameServer, true);
    }
    return InetAddress.getLocalHost().getCanonicalHostName();
  }

  static boolean isCurrentUgiMode(Configuration conf) {
    return VaultCredentialProviderConfig.KERBEROS_UGI_MODE_CURRENT
        .equalsIgnoreCase(conf.getTrimmed(
            VaultCredentialProviderConfig.KERBEROS_UGI_MODE_KEY,
            VaultCredentialProviderConfig.KERBEROS_UGI_MODE_DEFAULT));
  }

  /**
   * The token by digest, whichever of the configuration, the systemd
   * credential or the environment it came from: a rotated token is a new
   * identity.
   */
  private static String tokenSource(Configuration conf) throws IOException {
    String token = VaultCredentialProviderConfig.resolveToken(conf);
    if (token == null || token.isEmpty()) {
      return "none";
    }
    return "token:" + DigestUtils.sha256Hex(token);
  }

  String getBaseUrl() {
    return baseUrl;
  }

  String getSettings() {
    return settings;
  }

  /**
   * An identity for the testing constructors of
   * {@link VaultCredentialProvider}.
   */
  static VaultClientIdentity forTesting(String name) {
    return new OfToken("test", "", name);
  }

  /** A Vault token, named by its digest. */
  private static final class OfToken extends VaultClientIdentity {
    private final String source;

    OfToken(String baseUrl, String settings, String source) {
      super(baseUrl, settings);
      this.source = source;
    }

    @Override
    VaultAuthMethod createAuthMethod(Configuration conf,
        VaultConnectionInfo connInfo) {
      return new TokenVaultAuth(conf);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof OfToken)) {
        return false;
      }
      OfToken that = (OfToken) o;
      return sameClient(that) && source.equals(that.source);
    }

    @Override
    public int hashCode() {
      return Objects.hash(getBaseUrl(), getSettings(), source);
    }

    @Override
    public String toString() {
      return getBaseUrl() + " as " + source;
    }
  }

  /**
   * A Kerberos login: either a UGI holding one, or the configured
   * principal and keytab, which are one identity for the whole process.
   */
  private static final class OfKerberos extends VaultClientIdentity {
    private final String mountPath;
    private final UserGroupInformation ugi;
    private final String principal;
    private final String keytab;

    private OfKerberos(String baseUrl, String settings, String mountPath,
        UserGroupInformation ugi, String principal, String keytab) {
      super(baseUrl, settings);
      this.mountPath = mountPath;
      this.ugi = ugi;
      this.principal = principal;
      this.keytab = keytab;
    }

    static OfKerberos ofUser(String baseUrl, String settings,
        String mountPath, UserGroupInformation ugi) {
      return new OfKerberos(baseUrl, settings, mountPath, ugi, null, null);
    }

    static OfKerberos ofKeytab(String baseUrl, String settings,
        String mountPath, Configuration conf) throws IOException {
      String principal = conf.getTrimmed(
          VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY, "");
      String keytab = conf.getTrimmed(
          VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY, "");
      if (principal.isEmpty()) {
        throw new IOException("Kerberos principal not configured. Set '"
            + VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY
            + "' or use ugi.mode=current.");
      }
      if (keytab.isEmpty()) {
        throw new IOException("Kerberos keytab not configured. Set '"
            + VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY
            + "' or use ugi.mode=current.");
      }
      return new OfKerberos(baseUrl, settings, mountPath, null,
          serverPrincipal(principal, conf), keytab);
    }

    @Override
    VaultAuthMethod createAuthMethod(Configuration conf,
        VaultConnectionInfo connInfo) throws IOException {
      return new KerberosVaultAuth(conf, connInfo, mountPath,
          ugi != null ? ugi : loginFromKeytab(principal, keytab));
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof OfKerberos)) {
        return false;
      }
      OfKerberos that = (OfKerberos) o;
      return sameClient(that)
          && mountPath.equals(that.mountPath)
          && Objects.equals(ugi, that.ugi)
          && Objects.equals(principal, that.principal)
          && Objects.equals(keytab, that.keytab);
    }

    @Override
    public int hashCode() {
      return Objects.hash(getBaseUrl(), getSettings(), mountPath, ugi,
          principal, keytab);
    }

    @Override
    public String toString() {
      return getBaseUrl() + "/" + mountPath + " as "
          + (ugi != null ? ugi.getUserName() : principal);
    }
  }

  /**
   * A holder of Vault delegation tokens. The tokens themselves are read
   * from the UGI at every login, so the UGI is the identity: a session
   * with other tokens is a different one even under the same user name.
   */
  private static final class OfDelegationToken extends VaultClientIdentity {
    private final String mountPath;
    private final UserGroupInformation ugi;

    OfDelegationToken(String baseUrl, String settings, String mountPath,
        UserGroupInformation ugi) {
      super(baseUrl, settings);
      this.mountPath = mountPath;
      this.ugi = ugi;
    }

    @Override
    VaultAuthMethod createAuthMethod(Configuration conf,
        VaultConnectionInfo connInfo) {
      return new VaultDelegationTokenAuth(connInfo, mountPath, ugi);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o instanceof OfDelegationToken)) {
        return false;
      }
      OfDelegationToken that = (OfDelegationToken) o;
      return sameClient(that)
          && mountPath.equals(that.mountPath)
          && ugi.equals(that.ugi);
    }

    @Override
    public int hashCode() {
      return Objects.hash(getBaseUrl(), getSettings(), mountPath, ugi);
    }

    @Override
    public String toString() {
      return getBaseUrl() + "/" + mountPath + " with the delegation token of "
          + ugi.getUserName();
    }
  }
}
