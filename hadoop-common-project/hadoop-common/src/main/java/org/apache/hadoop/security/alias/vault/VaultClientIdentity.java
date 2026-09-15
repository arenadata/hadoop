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
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.hadoop.classification.InterfaceAudience;
import org.apache.hadoop.conf.Configuration;
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
 * <p>Choosing an identity runs on every provider creation and must not
 * contact the KDC or Vault; {@link #createAuthMethod} runs only when no
 * client for the identity is cached yet.
 */
@InterfaceAudience.Private
abstract class VaultClientIdentity {

  private static final Logger LOG =
      LoggerFactory.getLogger(VaultClientIdentity.class);

  /** Configured principal to the same principal with {@code _HOST} expanded. */
  private static final Map<String, String> SERVER_PRINCIPALS =
      new ConcurrentHashMap<>();

  private final String baseUrl;

  private VaultClientIdentity(String baseUrl) {
    this.baseUrl = baseUrl;
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
   * With {@code kerberos}, a process without Kerberos credentials that
   * holds a Vault delegation token for this server (a YARN container)
   * logs in with the token instead of SPNEGO. Credentials are those of
   * the current user, or of the real user behind a proxy user.
   *
   * @param conf the configuration
   * @param connInfo the Vault server
   * @return the identity
   * @throws IOException if the auth method is unsupported, or the caller
   *     has no credentials it could authenticate with
   */
  static VaultClientIdentity of(Configuration conf,
      VaultConnectionInfo connInfo) throws IOException {
    String baseUrl = connInfo.getBaseUrl();
    String name = VaultCredentialProviderConfig.authMethod(conf);
    if (VaultCredentialProviderConfig.AUTH_METHOD_TOKEN
        .equalsIgnoreCase(name)) {
      return new OfToken(baseUrl, tokenSource(conf));
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
    UserGroupInformation ugi = VaultDelegationTokens.actualUser();
    if (delegation) {
      if (!hasToken(ugi, connInfo, mountPath)) {
        throw new IOException("User " + ugi.getUserName()
            + " has no Vault delegation token for "
            + connInfo.getServerService());
      }
      return new OfDelegationToken(baseUrl, mountPath, ugi);
    }
    if (!ugi.hasKerberosCredentials()) {
      if (hasToken(ugi, connInfo, mountPath)) {
        LOG.debug("User {} has no Kerberos credentials, using the Vault "
            + "delegation token for {}", ugi.getUserName(),
            connInfo.getServerService());
        return new OfDelegationToken(baseUrl, mountPath, ugi);
      }
      if (isCurrentUgiMode(conf)) {
        throw new IOException("User " + ugi.getUserName()
            + " has neither Kerberos credentials nor a Vault delegation "
            + "token for " + connInfo.getServerService());
      }
    }
    return isCurrentUgiMode(conf)
        ? OfKerberos.ofUser(baseUrl, mountPath, ugi)
        : OfKerberos.ofKeytab(baseUrl, mountPath, conf);
  }

  /**
   * The UGI a Kerberos login authenticates as: the calling user, or a
   * login from the configured principal and keytab. A proxy user has no
   * Kerberos credentials of its own and Vault has no notion of acting on
   * behalf of someone, so an impersonated call authenticates as the real
   * user behind it.
   *
   * @param conf the configuration
   * @return the UGI to authenticate with
   * @throws IOException if the principal or keytab is missing, or the
   *     keytab login fails
   */
  static UserGroupInformation kerberosLogin(Configuration conf)
      throws IOException {
    if (isCurrentUgiMode(conf)) {
      UserGroupInformation ugi = VaultDelegationTokens.actualUser();
      LOG.debug("Using current UGI for Vault Kerberos auth: {}",
          ugi.getUserName());
      return ugi;
    }
    String principal = conf.get(
        VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY);
    String keytab = conf.get(
        VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY);
    if (principal == null || principal.isEmpty()) {
      throw new IOException("Kerberos principal not configured. Set '"
          + VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY
          + "' or use ugi.mode=current.");
    }
    if (keytab == null || keytab.isEmpty()) {
      throw new IOException("Kerberos keytab not configured. Set '"
          + VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY
          + "' or use ugi.mode=current.");
    }
    return UserGroupInformation
        .loginUserFromKeytabAndReturnUGI(serverPrincipal(principal), keytab);
  }

  /**
   * The configured principal with {@code _HOST} expanded to the local
   * FQDN. Memoized: the identity names the principal the login will use,
   * and it is built on every provider creation, while the expansion
   * resolves the host name.
   *
   * @param principal the configured principal, possibly null
   * @return the principal to authenticate as
   * @throws IOException if the host name cannot be resolved
   */
  private static String serverPrincipal(String principal) throws IOException {
    if (principal == null || principal.isEmpty()) {
      return principal;
    }
    String expanded = SERVER_PRINCIPALS.get(principal);
    if (expanded == null) {
      expanded = SecurityUtil.getServerPrincipal(principal, (String) null);
      SERVER_PRINCIPALS.put(principal, expanded);
    }
    return expanded;
  }

  static boolean isCurrentUgiMode(Configuration conf) {
    return VaultCredentialProviderConfig.KERBEROS_UGI_MODE_CURRENT
        .equalsIgnoreCase(conf.get(
            VaultCredentialProviderConfig.KERBEROS_UGI_MODE_KEY,
            VaultCredentialProviderConfig.KERBEROS_UGI_MODE_DEFAULT));
  }

  private static boolean hasToken(UserGroupInformation ugi,
      VaultConnectionInfo connInfo, String mountPath) {
    return VaultDelegationTokens.selectToken(ugi.getCredentials(), connInfo,
        mountPath) != null;
  }

  /**
   * Where the Vault token comes from, as an identity. A token set in the
   * configuration is per caller, so it is named by its digest; the
   * systemd credential and the environment variable belong to the
   * process and are the same token for every caller.
   */
  private static String tokenSource(Configuration conf) {
    String configured = conf.get(VaultCredentialProviderConfig.TOKEN_KEY);
    if (configured != null && !configured.isEmpty()) {
      return "conf:" + DigestUtils.sha256Hex(configured);
    }
    File systemd =
        VaultCredentialProviderConfig.systemdCredentialFile(conf);
    if (systemd != null) {
      return "systemd:" + systemd.getPath();
    }
    return "env";
  }

  String getBaseUrl() {
    return baseUrl;
  }

  /**
   * An identity for the testing constructors of
   * {@link VaultCredentialProvider}.
   */
  static VaultClientIdentity forTesting(String name) {
    return new OfToken("test", name);
  }

  /** A Vault token, named by where it comes from. */
  private static final class OfToken extends VaultClientIdentity {
    private final String source;

    OfToken(String baseUrl, String source) {
      super(baseUrl);
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
      return getBaseUrl().equals(that.getBaseUrl())
          && source.equals(that.source);
    }

    @Override
    public int hashCode() {
      return Objects.hash(getBaseUrl(), source);
    }

    @Override
    public String toString() {
      return getBaseUrl() + " as " + source;
    }
  }

  /**
   * A Kerberos login: either the caller's own UGI, or the configured
   * principal and keytab, which are one identity for the whole process.
   */
  private static final class OfKerberos extends VaultClientIdentity {
    private final String mountPath;
    private final UserGroupInformation ugi;
    private final String principal;
    private final String keytab;

    private OfKerberos(String baseUrl, String mountPath,
        UserGroupInformation ugi, String principal, String keytab) {
      super(baseUrl);
      this.mountPath = mountPath;
      this.ugi = ugi;
      this.principal = principal;
      this.keytab = keytab;
    }

    static OfKerberos ofUser(String baseUrl, String mountPath,
        UserGroupInformation ugi) {
      return new OfKerberos(baseUrl, mountPath, ugi, null, null);
    }

    static OfKerberos ofKeytab(String baseUrl, String mountPath,
        Configuration conf) throws IOException {
      return new OfKerberos(baseUrl, mountPath, null,
          serverPrincipal(conf.get(
              VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY)),
          conf.get(VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY));
    }

    @Override
    VaultAuthMethod createAuthMethod(Configuration conf,
        VaultConnectionInfo connInfo) throws IOException {
      return new KerberosVaultAuth(conf, connInfo, mountPath,
          ugi != null ? ugi : kerberosLogin(conf));
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
      return getBaseUrl().equals(that.getBaseUrl())
          && mountPath.equals(that.mountPath)
          && Objects.equals(ugi, that.ugi)
          && Objects.equals(principal, that.principal)
          && Objects.equals(keytab, that.keytab);
    }

    @Override
    public int hashCode() {
      return Objects.hash(getBaseUrl(), mountPath, ugi, principal, keytab);
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

    OfDelegationToken(String baseUrl, String mountPath,
        UserGroupInformation ugi) {
      super(baseUrl);
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
      return getBaseUrl().equals(that.getBaseUrl())
          && mountPath.equals(that.mountPath)
          && ugi.equals(that.ugi);
    }

    @Override
    public int hashCode() {
      return Objects.hash(getBaseUrl(), mountPath, ugi);
    }

    @Override
    public String toString() {
      return getBaseUrl() + "/" + mountPath + " with the delegation token of "
          + ugi.getUserName();
    }
  }
}
