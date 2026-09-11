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
import java.security.PrivilegedExceptionAction;
import java.util.Base64;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.minikdc.MiniKdc;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

/**
 * MiniKdc with the principals of a Vault Kerberos setup: the client
 * {@code vault-client}, the renewer {@code yarn} and the Vault service
 * {@code HTTP/localhost}, all in one keytab. Accepts SPNEGO tokens with the
 * service key so a mock Vault can authenticate callers like a real one.
 * UGI relogin is forced on every authentication so the keytab relogin path
 * runs on each login.
 */
final class VaultKerberosTestFixture {

  static final String CLIENT_PRINCIPAL = "vault-client";
  static final String RENEWER_PRINCIPAL = "yarn";
  static final String SERVER_PRINCIPAL = "HTTP/localhost";
  private static final String NEGOTIATE = "Negotiate ";

  private MiniKdc kdc;
  private File keytab;
  private UserGroupInformation serverUgi;

  void start(File workDir) throws Exception {
    kdc = new MiniKdc(MiniKdc.createConf(), workDir);
    kdc.start();
    keytab = new File(workDir, "vault.keytab");
    kdc.createPrincipal(keytab, CLIENT_PRINCIPAL, RENEWER_PRINCIPAL,
        SERVER_PRINCIPAL);

    Configuration conf = new Configuration();
    conf.set(CommonConfigurationKeys.HADOOP_SECURITY_AUTHENTICATION,
        "kerberos");
    UserGroupInformation.setConfiguration(conf);
    UserGroupInformation.setShouldRenewImmediatelyForTests(true);
    serverUgi = loginFromKeytab(SERVER_PRINCIPAL);
  }

  void stop() {
    if (kdc != null) {
      kdc.stop();
    }
    UserGroupInformation.setShouldRenewImmediatelyForTests(false);
    UserGroupInformation.reset();
  }

  String realm() {
    return kdc.getRealm();
  }

  String principal(String name) {
    return name + "@" + kdc.getRealm();
  }

  UserGroupInformation loginFromKeytab(String name) throws IOException {
    return UserGroupInformation.loginUserFromKeytabAndReturnUGI(
        principal(name), keytab.getAbsolutePath());
  }

  /**
   * Client configuration for Kerberos auth as {@code vault-client} from the
   * keytab (dedicated UGI mode).
   */
  Configuration kerberosConf() {
    Configuration conf = new Configuration();
    conf.set(VaultCredentialProviderConfig.AUTH_METHOD_KEY,
        VaultCredentialProviderConfig.AUTH_METHOD_KERBEROS);
    conf.set(VaultCredentialProviderConfig.KERBEROS_PRINCIPAL_KEY,
        principal(CLIENT_PRINCIPAL));
    conf.set(VaultCredentialProviderConfig.KERBEROS_KEYTAB_KEY,
        keytab.getAbsolutePath());
    conf.set(VaultCredentialProviderConfig.KERBEROS_SERVICE_PRINCIPAL_KEY,
        "HTTP/_HOST@" + realm());
    return conf;
  }

  /**
   * Accept the SPNEGO token of an Authorization header with the
   * {@code HTTP/localhost} key.
   *
   * @return the authenticated client principal
   * @throws Exception if the header is missing or the token is rejected
   */
  String acceptSpnego(String authorization) throws Exception {
    if (authorization == null || !authorization.startsWith(NEGOTIATE)) {
      throw new IOException("missing Negotiate header: " + authorization);
    }
    byte[] token = Base64.getDecoder().decode(
        authorization.substring(NEGOTIATE.length()));
    return serverUgi.doAs((PrivilegedExceptionAction<String>) () -> {
      GSSManager manager = GSSManager.getInstance();
      GSSCredential serverCreds = manager.createCredential(
          manager.createName(principal(SERVER_PRINCIPAL),
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
}
