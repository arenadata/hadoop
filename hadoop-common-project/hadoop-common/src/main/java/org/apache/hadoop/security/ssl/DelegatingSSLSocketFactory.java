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

package org.apache.hadoop.security.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.logging.Level;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.hadoop.classification.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link SSLSocketFactory} that can delegate to various SSL implementations.
 * Specifically, either OpenSSL or JSSE can be used. OpenSSL offers better
 * performance than JSSE and is made available via the
 * <a href="https://github.com/wildfly/wildfly-openssl">wildlfy-openssl</a>
 * library.
 *
 * <p>
 *   The factory has several different modes of operation:
 * </p>
 *
 * <ul>
 *   <li>OpenSSL: Uses the wildly-openssl library to delegate to the
 *   system installed OpenSSL. If the wildfly-openssl integration is not
 *   properly setup, an exception is thrown.</li>
 *   <li>Default: Attempts to use the OpenSSL mode, if it cannot load the
 *   necessary libraries, it falls back to the Default_JSEE mode.</li>
 *   <li>Default_JSSE: Delegates to the JSSE implementation of SSL, but
 *   it disables the GCM cipher when running on Java 8.</li>
 *   <li>Default_JSSE_with_GCM: Delegates to the JSSE implementation of
 *   SSL with no modification to the list of enabled ciphers.</li>
 * </ul>
 *
 * In order to load OpenSSL, applications must ensure the wildfly-openssl
 * artifact is on the classpath. Currently, only ABFS declares
 * wildfly-openssl as an explicit dependency.
 */
public final class DelegatingSSLSocketFactory extends SSLSocketFactory {

  /**
   * Default indicates Ordered, preferred OpenSSL, if failed to load then fall
   * back to Default_JSSE.
   *
   * <p>
   *   Default_JSSE is not truly the the default JSSE implementation because
   *   the GCM cipher is disabled when running on Java 8. However, the name
   *   was not changed in order to preserve backwards compatibility. Instead,
   *   a new mode called Default_JSSE_with_GCM delegates to the default JSSE
   *   implementation with no changes to the list of enabled ciphers.
   * </p>
   */
  public enum SSLChannelMode {
    OpenSSL,
    Default,
    Default_JSSE,
    Default_JSSE_with_GCM
  }

  private static DelegatingSSLSocketFactory instance = null;
  private static final Logger LOG = LoggerFactory.getLogger(
          DelegatingSSLSocketFactory.class);

  /**
   * Opaque descriptor of the trust material {@link #instance} was built from,
   * as supplied by whoever initialized the factory; null if it was initialized
   * with no explicit trust material.
   */
  private static String instanceTrustConfigId = null;

  /**
   * Has the "trust material is installed but this caller did not ask for it"
   * warning already been logged? This guards against unbounded logging:
   * ABFS initializes the factory on every HTTPS connection.
   */
  private static boolean trustConfigMismatchWarned = false;

  /**
   * Trust configuration of the last discarded request which was warned
   * about, so that repeating the same request stays quiet. A single binding
   * initializes the factory more than once.
   */
  private static String lastWarnedTrustConfigId = null;

  private String providerName;
  private SSLContext ctx;
  private String[] ciphers;
  private SSLChannelMode channelMode;

  // This should only be modified within the #initializeDefaultFactory
  // method which is synchronized
  private boolean openSSLProviderRegistered;

  /**
   * Initialize a singleton SSL socket factory.
   *
   * The factory is JVM-wide and first-write-wins: once it has been
   * initialized, later calls are ignored. A call which asks for trust
   * material other than the one already in use is logged at WARN, as its
   * request is silently discarded.
   *
   * @param preferredMode applicable only if the instance is not initialized.
   * @param tmf trust managers to install, or null for the JVM defaults.
   *            Applicable only if the instance is not initialized.
   * @param trustConfigId opaque identifier of the trust material behind
   *                      {@code tmf}, used to detect conflicting requests.
   *                      Must be null when {@code tmf} is null.
   * @throws IOException if an error occurs.
   */
  public static synchronized void initializeDefaultFactory(
      SSLChannelMode preferredMode,
      TrustManagerFactory tmf,
      String trustConfigId) throws IOException {
    if (instance == null) {
      instance = new DelegatingSSLSocketFactory(preferredMode, tmf);
      instanceTrustConfigId = trustConfigId;
      return;
    }
    warnOnDiscardedTrustConfig(trustConfigId);
  }

  /**
   * Initialize a singleton SSL socket factory with no explicit trust material.
   *
   * @param preferredMode applicable only if the instance is not initialized.
   * @throws IOException if an error occurs.
   */
  public static synchronized void initializeDefaultFactory(
      SSLChannelMode preferredMode) throws IOException {
    initializeDefaultFactory(preferredMode, null, null);
  }

  /**
   * Warn when an initialization request is discarded because the JVM-wide
   * factory already exists and was built from different trust material.
   * @param trustConfigId trust configuration of the discarded request.
   */
  private static void warnOnDiscardedTrustConfig(String trustConfigId) {
    if (trustConfigId != null) {
      if (!trustConfigId.equals(instanceTrustConfigId)
          && !trustConfigId.equals(lastWarnedTrustConfigId)) {
        lastWarnedTrustConfigId = trustConfigId;
        LOG.warn("The JVM-wide SSL socket factory is already initialized with"
                + " trust configuration [{}]; the request for [{}] is ignored."
                + " Only one trust store can be active per JVM process.",
            instanceTrustConfigId == null
                ? "the JVM default trust store" : instanceTrustConfigId,
            trustConfigId);
      }
    } else if (instanceTrustConfigId != null && !trustConfigMismatchWarned) {
      trustConfigMismatchWarned = true;
      LOG.warn("The JVM-wide SSL socket factory was initialized with trust"
              + " configuration [{}]; connections which did not ask for it"
              + " will use those trust anchors and not the JVM defaults.",
          instanceTrustConfigId);
    }
  }

  /**
   * For testing only: reset the socket factory.
   */
  @VisibleForTesting
  public static synchronized void resetDefaultFactory() {
    LOG.info("Resetting default SSL Socket Factory");
    instance = null;
    instanceTrustConfigId = null;
    trustConfigMismatchWarned = false;
    lastWarnedTrustConfigId = null;
  }

  /**
   * Singleton instance of the SSLSocketFactory.
   *
   * SSLSocketFactory must be initialized with appropriate SSLChannelMode
   * using initializeDefaultFactory method.
   *
   * @return instance of the SSLSocketFactory, instance must be initialized by
   * initializeDefaultFactory.
   */
  public static DelegatingSSLSocketFactory getDefaultFactory() {
    return instance;
  }

  private DelegatingSSLSocketFactory(SSLChannelMode preferredChannelMode,
      TrustManagerFactory tmf) throws IOException {
    try {
      initializeSSLContext(preferredChannelMode, tmf);
    } catch (NoSuchAlgorithmException | KeyManagementException e) {
      throw new IOException(e);
    }

    // Get list of supported cipher suits from the SSL factory.
    SSLSocketFactory factory = ctx.getSocketFactory();
    String[] defaultCiphers = factory.getSupportedCipherSuites();
    String version = System.getProperty("java.version");

    ciphers = (channelMode == SSLChannelMode.Default_JSSE
        && version.startsWith("1.8"))
        ? alterCipherList(defaultCiphers) : defaultCiphers;

    providerName = ctx.getProvider().getName() + "-"
        + ctx.getProvider().getVersion();
  }

  /**
   * Initialize {@link #ctx} for the requested channel mode.
   * @param preferredChannelMode the requested channel mode.
   * @param tmf trust managers to install, or null to use the JVM defaults.
   * @throws NoSuchAlgorithmException no such algorithm.
   * @throws KeyManagementException failure to initialize the context.
   * @throws IOException unknown channel mode.
   */
  private void initializeSSLContext(SSLChannelMode preferredChannelMode,
      TrustManagerFactory tmf)
      throws NoSuchAlgorithmException, KeyManagementException, IOException {
    LOG.debug("Initializing SSL Context to channel mode {} {} TrustManagerFactory",
        preferredChannelMode, tmf != null ? "with a" : "without a");
    switch (preferredChannelMode) {
    case Default:
      try {
        bindToOpenSSLProvider();
        ctx.init(null, trustManagers(tmf), null);
        channelMode = SSLChannelMode.OpenSSL;
      } catch (LinkageError | NoSuchAlgorithmException
          | KeyManagementException | RuntimeException e) {
        LOG.debug("Failed to load OpenSSL. Falling back to the JSSE default.",
            e);
        initializeJSSEContext(tmf);
        channelMode = SSLChannelMode.Default_JSSE;
      }
      break;
    case OpenSSL:
      bindToOpenSSLProvider();
      ctx.init(null, trustManagers(tmf), null);
      channelMode = SSLChannelMode.OpenSSL;
      break;
    case Default_JSSE:
      initializeJSSEContext(tmf);
      channelMode = SSLChannelMode.Default_JSSE;
      break;
    case Default_JSSE_with_GCM:
      initializeJSSEContext(tmf);
      channelMode = SSLChannelMode.Default_JSSE_with_GCM;
      break;
    default:
      throw new IOException("Unknown channel mode: "
          + preferredChannelMode);
    }
  }

  /**
   * Point {@link #ctx} at a JSSE context.
   * With no trust material the shared {@link SSLContext#getDefault()} is used,
   * exactly as before this method existed. That context comes back already
   * initialized and calling {@code init()} on it throws
   * {@link KeyManagementException}, so a fresh context has to be created
   * whenever trust managers must be installed.
   * @param tmf trust managers to install, or null to use the JVM defaults.
   * @throws NoSuchAlgorithmException no such algorithm.
   * @throws KeyManagementException failure to initialize the context.
   */
  private void initializeJSSEContext(TrustManagerFactory tmf)
      throws NoSuchAlgorithmException, KeyManagementException {
    if (tmf == null) {
      ctx = SSLContext.getDefault();
    } else {
      ctx = SSLContext.getInstance("TLS");
      ctx.init(null, tmf.getTrustManagers(), null);
    }
  }

  /**
   * Extract the trust managers of a factory.
   * @param tmf the factory, or null.
   * @return the trust managers, or null to use the JVM defaults.
   */
  private static TrustManager[] trustManagers(TrustManagerFactory tmf) {
    return tmf == null ? null : tmf.getTrustManagers();
  }

  /**
   * Bind to the OpenSSL provider via wildfly.
   * This MUST be the only place where wildfly classes are referenced,
   * so ensuring that any linkage problems only surface here where they may
   * be caught by the initialization code.
   */
  private void bindToOpenSSLProvider()
      throws NoSuchAlgorithmException, KeyManagementException {
    if (!openSSLProviderRegistered) {
      LOG.debug("Attempting to register OpenSSL provider");
      org.wildfly.openssl.OpenSSLProvider.register();
      openSSLProviderRegistered = true;
    }
    // Strong reference needs to be kept to logger until initialization of
    // SSLContext finished (see HADOOP-16174):
    java.util.logging.Logger logger = java.util.logging.Logger.getLogger(
        "org.wildfly.openssl.SSL");
    Level originalLevel = logger.getLevel();
    try {
      logger.setLevel(Level.WARNING);
      ctx = SSLContext.getInstance("openssl.TLS");
    } finally {
      logger.setLevel(originalLevel);
    }
  }

  public String getProviderName() {
    return providerName;
  }

  @Override
  public String[] getDefaultCipherSuites() {
    return ciphers.clone();
  }

  @Override
  public String[] getSupportedCipherSuites() {
    return ciphers.clone();
  }

  /**
   * Get the channel mode of this instance.
   * @return a channel mode.
   */
  public SSLChannelMode getChannelMode() {
    return channelMode;
  }

  public Socket createSocket() throws IOException {
    SSLSocketFactory factory = ctx.getSocketFactory();
    return configureSocket(factory.createSocket());
  }

  @Override
  public Socket createSocket(Socket s, String host, int port,
                             boolean autoClose) throws IOException {
    SSLSocketFactory factory = ctx.getSocketFactory();

    return configureSocket(
        factory.createSocket(s, host, port, autoClose));
  }

  @Override
  public Socket createSocket(InetAddress address, int port,
                             InetAddress localAddress, int localPort)
      throws IOException {
    SSLSocketFactory factory = ctx.getSocketFactory();
    return configureSocket(factory
        .createSocket(address, port, localAddress, localPort));
  }

  @Override
  public Socket createSocket(String host, int port, InetAddress localHost,
                             int localPort) throws IOException {
    SSLSocketFactory factory = ctx.getSocketFactory();

    return configureSocket(factory
        .createSocket(host, port, localHost, localPort));
  }

  @Override
  public Socket createSocket(InetAddress host, int port) throws IOException {
    SSLSocketFactory factory = ctx.getSocketFactory();

    return configureSocket(factory.createSocket(host, port));
  }

  @Override
  public Socket createSocket(String host, int port) throws IOException {
    SSLSocketFactory factory = ctx.getSocketFactory();

    return configureSocket(factory.createSocket(host, port));
  }

  private Socket configureSocket(Socket socket) {
    ((SSLSocket) socket).setEnabledCipherSuites(ciphers);
    return socket;
  }

  private String[] alterCipherList(String[] defaultCiphers) {

    ArrayList<String> preferredSuites = new ArrayList<>();

    // Remove GCM mode based ciphers from the supported list.
    for (int i = 0; i < defaultCiphers.length; i++) {
      if (defaultCiphers[i].contains("_GCM_")) {
        LOG.debug("Removed Cipher - {} from list of enabled SSLSocket ciphers",
                defaultCiphers[i]);
      } else {
        preferredSuites.add(defaultCiphers[i]);
      }
    }

    ciphers = preferredSuites.toArray(new String[0]);
    return ciphers;
  }
}
