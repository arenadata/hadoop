/*
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

package org.apache.hadoop.fs.s3a;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManagerFactory;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import software.amazon.awssdk.http.apache.ApacheHttpClient;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.impl.AWSClientConfig;
import org.apache.hadoop.fs.s3a.impl.NetworkBinding;
import org.apache.hadoop.security.ProviderUtils;
import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.hadoop.security.ssl.DelegatingSSLSocketFactory;
import org.apache.hadoop.security.ssl.KeyStoreTestUtil;
import org.apache.hadoop.test.AbstractHadoopTestBase;

import static org.apache.hadoop.fs.s3a.Constants.SSL_CHANNEL_MODE;
import static org.apache.hadoop.fs.s3a.Constants.SSL_TRUSTSTORE;
import static org.apache.hadoop.fs.s3a.Constants.SSL_TRUSTSTORE_PASSWORD;
import static org.apache.hadoop.fs.s3a.Constants.SSL_TRUSTSTORE_TYPE;
import static org.apache.hadoop.fs.s3a.impl.NetworkBinding.bindSSLChannelMode;
import static org.apache.hadoop.security.ssl.DelegatingSSLSocketFactory.SSLChannelMode.Default;
import static org.apache.hadoop.security.ssl.DelegatingSSLSocketFactory.SSLChannelMode.Default_JSSE;
import static org.apache.hadoop.security.ssl.DelegatingSSLSocketFactory.SSLChannelMode.Default_JSSE_with_GCM;
import static org.apache.hadoop.security.ssl.DelegatingSSLSocketFactory.SSLChannelMode.OpenSSL;
import static org.apache.hadoop.test.LambdaTestUtils.intercept;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

/**
 * Make sure that wildfly is not on this classpath and that we can still
 * create connections in the default option, but that openssl fails.
 * This test suite is designed to work whether or not wildfly JAR is on
 * the classpath, and when openssl native libraries are/are not
 * on the path.
 * Some of the tests are skipped in a maven build because wildfly
 * is always on the classpath -but they are retained as in-IDE
 * runs may be different, and if wildfly is removed from
 * the compile or test CP then different test cases will execute.
 */
public class TestWildflyAndOpenSSLBinding extends AbstractHadoopTestBase {

  /** Password of the trust stores created by the trust store tests. */
  private static final String TRUSTSTORE_PASSWORD = "truststore-secret";

  @Rule
  public final TemporaryFolder tempDir = new TemporaryFolder();

  /** Was wildfly found. */
  private boolean hasWildfly;

  /** Self-signed certificate used to populate the trust stores. */
  private X509Certificate certificate;

  @Before
  public void setup() throws Exception {
    // determine whether or not wildfly is on the classpath
    ClassLoader loader = this.getClass().getClassLoader();
    try {
      loader.loadClass("org.wildfly.openssl.OpenSSLProvider");
      hasWildfly = true;
    } catch (ClassNotFoundException e) {
      hasWildfly = false;
    }
    KeyPair keyPair = KeyStoreTestUtil.generateKeyPair("RSA");
    certificate = KeyStoreTestUtil.generateCertificate(
        "CN=localhost", keyPair, 1, "SHA256withRSA");
  }


  @Test
  public void testUnknownMode() throws Throwable {
    DelegatingSSLSocketFactory.resetDefaultFactory();
    Configuration conf = new Configuration(false);
    conf.set(SSL_CHANNEL_MODE, "no-such-mode ");
    intercept(IllegalArgumentException.class, () ->
        bindSSLChannelMode(conf, ApacheHttpClient.builder(), ""));
  }

  @Test
  public void testOpenSSLNoWildfly() throws Throwable {
    assumeThat(hasWildfly).isFalse();
    intercept(NoClassDefFoundError.class, "wildfly", () ->
      bindSocketFactory(OpenSSL));
  }

  /**
   * If there is no WF on the CP, then we always downgrade
   * to default.
   */
  @Test
  public void testDefaultDowngradesNoWildfly() throws Throwable {
    assumeThat(hasWildfly).isFalse();
    expectBound(Default, Default_JSSE);
  }

  /**
   * Wildfly is on the CP; if openssl native is on the
   * path then openssl will load, otherwise JSSE.
   */
  @Test
  public void testWildflyOpenSSL() throws Throwable {
    assumeThat(hasWildfly).isTrue();
    assertThat(bindSocketFactory(Default))
        .describedAs("Sockets from mode " + Default)
        .isIn(OpenSSL, Default_JSSE);
  }

  @Test
  public void testJSSE() throws Throwable {
    expectBound(Default_JSSE, Default_JSSE);
  }

  @Test
  public void testGCM() throws Throwable {
    expectBound(Default_JSSE_with_GCM, Default_JSSE_with_GCM);
  }

  /**
   * Bind to a socket mode and verify that the result matches
   * that expected -which does not have to be the one requested.
   * @param channelMode mode to use
   * @param finalMode mode to test for
   */
  private void expectBound(
      DelegatingSSLSocketFactory.SSLChannelMode channelMode,
      DelegatingSSLSocketFactory.SSLChannelMode finalMode)
      throws Throwable {
    assertThat(bindSocketFactory(channelMode))
        .describedAs("Channel mode of socket factory created with mode %s",
            channelMode)
        .isEqualTo(finalMode);
  }

  /**
   * Bind the socket factory to a given channel mode.
   * @param channelMode mode to use
   * @return the actual channel mode.
   */
  private DelegatingSSLSocketFactory.SSLChannelMode bindSocketFactory(
      final DelegatingSSLSocketFactory.SSLChannelMode channelMode)
      throws IOException {
    DelegatingSSLSocketFactory.resetDefaultFactory();
    Configuration conf = new Configuration(false);
    conf.set(SSL_CHANNEL_MODE, channelMode.name());
    bindSSLChannelMode(conf, ApacheHttpClient.builder(), "");
    return DelegatingSSLSocketFactory.getDefaultFactory().getChannelMode();
  }


  /**
   * A trust store is loaded and installed into the socket factory.
   */
  @Test
  public void testTrustStoreBinding() throws Throwable {
    Configuration conf = confWithTrustStore(
        createTrustStore("valid.jks", TRUSTSTORE_PASSWORD),
        TRUSTSTORE_PASSWORD);
    assertThat(bindWithTrustStore(conf))
        .describedAs("Channel mode of the factory built with a trust store")
        .isEqualTo(Default_JSSE);
  }

  /**
   * A trust store is honoured in the Default channel mode too, whether the
   * OpenSSL provider loads or the binding downgrades to the JSSE. The
   * downgrade path is the one which builds a fresh "TLS" context rather than
   * reusing the already-initialized {@code SSLContext.getDefault()}.
   */
  @Test
  public void testTrustStoreBindingDefaultMode() throws Throwable {
    Configuration conf = confWithTrustStore(
        createTrustStore("default-mode.jks", TRUSTSTORE_PASSWORD),
        TRUSTSTORE_PASSWORD);
    conf.set(SSL_CHANNEL_MODE, Default.name());
    assertThat(bindWithTrustStore(conf))
        .describedAs("Channel mode of the factory built with a trust store"
            + " in mode %s", Default)
        .isIn(OpenSSL, Default_JSSE);
  }

  /**
   * A trust store with no password loads: JKS only verifies its integrity
   * when a password is supplied. This is warned about, not rejected.
   */
  @Test
  public void testTrustStoreWithoutPassword() throws Throwable {
    Configuration conf = confWithTrustStore(
        createTrustStore("nopassword.jks", TRUSTSTORE_PASSWORD), null);
    assertThat(bindWithTrustStore(conf))
        .describedAs("Channel mode of the factory built without a password")
        .isEqualTo(Default_JSSE);
  }

  /**
   * The trust store password is resolved through the Hadoop credential
   * providers, i.e. the flow documented for every other S3A secret.
   */
  @Test
  public void testTrustStorePasswordFromCredentialProvider() throws Throwable {
    Configuration conf = confWithTrustStore(
        createTrustStore("credentials.jks", TRUSTSTORE_PASSWORD), null);
    File jceks = tempDir.newFile("credentials.jceks");
    URI providerUri =
        ProviderUtils.nestURIForLocalJavaKeyStoreProvider(jceks.toURI());
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
        providerUri.toString());
    CredentialProvider provider =
        CredentialProviderFactory.getProviders(conf).get(0);
    provider.createCredentialEntry(SSL_TRUSTSTORE_PASSWORD,
        TRUSTSTORE_PASSWORD.toCharArray());
    provider.flush();

    assertThat(bindWithTrustStore(conf))
        .describedAs("Channel mode of the factory built from a credential file")
        .isEqualTo(Default_JSSE);
  }

  /**
   * The password may be declared as a bucket-scoped alias in a credential
   * provider, the usual way to hold a genuinely per-bucket secret. Bucket
   * options which live only in a provider are invisible to
   * {@code S3AUtils.propagateBucketOptions()}, so this resolves only when the
   * bucket name reaches the lookup itself.
   * <p>
   * The generic key deliberately carries the wrong password here: if the
   * bucket-scoped alias is not consulted, that wrong password reaches
   * {@code KeyStore.load()} and the binding fails.
   */
  @Test
  public void testTrustStorePasswordFromBucketScopedAlias() throws Throwable {
    String bucket = "private-store";
    Configuration conf = confWithTrustStore(
        createTrustStore("bucket-alias.jks", TRUSTSTORE_PASSWORD),
        "not-the-password");
    File jceks = tempDir.newFile("bucket-alias.jceks");
    URI providerUri =
        ProviderUtils.nestURIForLocalJavaKeyStoreProvider(jceks.toURI());
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
        providerUri.toString());
    CredentialProvider provider =
        CredentialProviderFactory.getProviders(conf).get(0);
    provider.createCredentialEntry(
        "fs.s3a.bucket." + bucket + ".ssl.truststore.password",
        TRUSTSTORE_PASSWORD.toCharArray());
    provider.flush();

    assertThat(bindWithTrustStore(conf, bucket))
        .describedAs("Channel mode of the factory built from the bucket-scoped"
            + " alias of %s", SSL_TRUSTSTORE_PASSWORD)
        .isEqualTo(Default_JSSE);
  }

  /**
   * A missing trust store must fail with an error naming the option which
   * declared it, not a bare FileNotFoundException.
   */
  @Test
  public void testTrustStoreNotFound() throws Throwable {
    Configuration conf = confWithTrustStore(
        new File(tempDir.getRoot(), "no-such-file.jks"), TRUSTSTORE_PASSWORD);
    DelegatingSSLSocketFactory.resetDefaultFactory();
    intercept(IOException.class, SSL_TRUSTSTORE, () ->
        bindSSLChannelMode(conf, ApacheHttpClient.builder(), ""));
  }

  /**
   * A wrong password must fail with an error naming the option which
   * declared the trust store.
   */
  @Test
  public void testTrustStoreWrongPassword() throws Throwable {
    Configuration conf = confWithTrustStore(
        createTrustStore("wrongpassword.jks", TRUSTSTORE_PASSWORD),
        "not-the-password");
    DelegatingSSLSocketFactory.resetDefaultFactory();
    intercept(IOException.class, SSL_TRUSTSTORE, () ->
        bindSSLChannelMode(conf, ApacheHttpClient.builder(), ""));
  }

  /**
   * An empty trust store path is treated as if the option was unset.
   */
  @Test
  public void testEmptyTrustStorePathIgnored() throws Throwable {
    Configuration conf = new Configuration(false);
    conf.set(SSL_CHANNEL_MODE, Default_JSSE.name());
    conf.set(SSL_TRUSTSTORE, " ");
    assertThat(bindWithTrustStore(conf))
        .describedAs("Channel mode with an empty trust store path")
        .isEqualTo(Default_JSSE);
  }

  /**
   * The socket factory is JVM-wide and first-write-wins: a second, different
   * trust configuration is discarded rather than applied or rejected.
   */
  @Test
  public void testFirstTrustStoreWins() throws Throwable {
    Configuration first = confWithTrustStore(
        createTrustStore("first.jks", TRUSTSTORE_PASSWORD),
        TRUSTSTORE_PASSWORD);
    bindWithTrustStore(first);
    DelegatingSSLSocketFactory installed =
        DelegatingSSLSocketFactory.getDefaultFactory();

    Configuration second = confWithTrustStore(
        createTrustStore("second.jks", TRUSTSTORE_PASSWORD),
        TRUSTSTORE_PASSWORD);
    // deliberately no resetDefaultFactory() between the two bindings
    bindSSLChannelMode(second, ApacheHttpClient.builder(), "");

    assertThat(DelegatingSSLSocketFactory.getDefaultFactory())
        .describedAs("Factory after a second binding with a different"
            + " trust store: the first one must still be in place")
        .isSameAs(installed);
  }

  /**
   * The Netty asynchronous client cannot be given a socket factory, but it
   * can be given the trust managers directly, so a configured trust store
   * reaches it too. This covers rename/copy and copyFromLocalFile, which are
   * the only operations routed through that client.
   */
  @Test
  public void testAsyncClientGetsTrustStore() throws Throwable {
    Configuration conf = confWithTrustStore(
        createTrustStore("async.jks", TRUSTSTORE_PASSWORD),
        TRUSTSTORE_PASSWORD);

    TrustManagerFactory tmf = NetworkBinding.createTrustManagerFactory(conf, "");
    assertThat(tmf)
        .describedAs("Trust managers built for the async client")
        .isNotNull();
    assertThat(tmf.getTrustManagers())
        .describedAs("Trust managers of %s", tmf)
        .isNotEmpty();

    assertThat(AWSClientConfig.createAsyncHttpClientBuilder(conf, ""))
        .describedAs("Async http client builder with a trust store")
        .isNotNull();
  }

  /**
   * With no trust store configured the async client is left on the JVM
   * defaults, as before.
   */
  @Test
  public void testAsyncClientWithoutTrustStore() throws Throwable {
    Configuration conf = new Configuration(false);
    assertThat(NetworkBinding.createTrustManagerFactory(conf, ""))
        .describedAs("Trust managers with no trust store configured")
        .isNull();
    assertThat(AWSClientConfig.createAsyncHttpClientBuilder(conf, ""))
        .describedAs("Async http client builder with no trust store")
        .isNotNull();
  }

  /**
   * Create a trust store holding the test certificate.
   * @param name file name within the temporary directory.
   * @param password password to protect it with.
   * @return the file created.
   */
  private File createTrustStore(String name, String password)
      throws Exception {
    File file = new File(tempDir.getRoot(), name);
    KeyStoreTestUtil.createTrustStore(file.getAbsolutePath(), password,
        "test-ca", certificate);
    return file;
  }

  /**
   * Build a configuration binding to a trust store in the JSSE channel mode.
   * @param trustStore the trust store file.
   * @param password its password, or null to leave the option unset.
   * @return the configuration.
   */
  private Configuration confWithTrustStore(File trustStore, String password) {
    Configuration conf = new Configuration(false);
    conf.set(SSL_CHANNEL_MODE, Default_JSSE.name());
    conf.set(SSL_TRUSTSTORE, trustStore.getAbsolutePath());
    conf.set(SSL_TRUSTSTORE_TYPE, "jks");
    if (password != null) {
      conf.set(SSL_TRUSTSTORE_PASSWORD, password);
    }
    return conf;
  }

  /**
   * Reset the factory and bind it from the given configuration.
   * @param conf configuration to bind from.
   * @return the channel mode of the resulting factory.
   */
  private DelegatingSSLSocketFactory.SSLChannelMode bindWithTrustStore(
      Configuration conf) throws IOException {
    return bindWithTrustStore(conf, "");
  }

  /**
   * Reset the factory and bind it from the given configuration, as the
   * filesystem of a given bucket.
   * @param conf configuration to bind from.
   * @param bucket bucket the binding is for.
   * @return the channel mode of the resulting factory.
   */
  private DelegatingSSLSocketFactory.SSLChannelMode bindWithTrustStore(
      Configuration conf, String bucket) throws IOException {
    DelegatingSSLSocketFactory.resetDefaultFactory();
    bindSSLChannelMode(conf, ApacheHttpClient.builder(), bucket);
    return DelegatingSSLSocketFactory.getDefaultFactory().getChannelMode();
  }

}
