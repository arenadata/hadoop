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

package org.apache.hadoop.fs.s3a.impl;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;

import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.http.apache.ApacheHttpClient;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.S3AUtils;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.ssl.DelegatingSSLSocketFactory;

import static org.apache.hadoop.fs.s3a.Constants.DEFAULT_ENDPOINT;
import static org.apache.hadoop.fs.s3a.Constants.DEFAULT_SSL_CHANNEL_MODE;
import static org.apache.hadoop.fs.s3a.Constants.ENDPOINT;
import static org.apache.hadoop.fs.s3a.Constants.SSL_CHANNEL_MODE;
import static org.apache.hadoop.fs.s3a.Constants.SSL_TRUSTSTORE;
import static org.apache.hadoop.fs.s3a.Constants.SSL_TRUSTSTORE_PASSWORD;
import static org.apache.hadoop.fs.s3a.Constants.SSL_TRUSTSTORE_TYPE;
import static org.apache.hadoop.fs.s3a.Constants.SSL_TRUSTSTORE_TYPE_DEFAULT;

/**
 * Configures network settings when communicating with AWS services.
 */
public final class NetworkBinding {

  private static final Logger LOG =
          LoggerFactory.getLogger(NetworkBinding.class);
  private static final String BINDING_CLASSNAME =
      "org.apache.hadoop.fs.s3a.impl.ConfigureShadedAWSSocketFactory";

  private NetworkBinding() {
  }

  /**
   * Load the trust store named by {@code fs.s3a.ssl.truststore}, if set,
   * and build a {@link TrustManagerFactory} from it.
   * @param conf the configuration of the filesystem.
   * @return the binding; {@link TrustStoreBinding#NONE} if no trust store
   *         is configured.
   * @throws IOException the trust store is configured but cannot be loaded.
   */
  private static TrustStoreBinding loadTrustStore(
      Configuration conf) throws IOException {
    String trustStorePath = conf.getTrimmed(SSL_TRUSTSTORE, "");
    if (trustStorePath.isEmpty()) {
      return TrustStoreBinding.NONE;
    }
    String trustStoreType =
        conf.getTrimmed(SSL_TRUSTSTORE_TYPE, SSL_TRUSTSTORE_TYPE_DEFAULT);
    char[] password = lookupTrustStorePassword(conf, trustStorePath);
    try {
      KeyStore trustStore = KeyStore.getInstance(trustStoreType);
      try (InputStream instream = Files.newInputStream(
          Paths.get(trustStorePath))) {
        trustStore.load(instream, password);
      }
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(
          TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore);
      return new TrustStoreBinding(tmf,
          trustConfigId(trustStorePath, trustStoreType));
    } catch (GeneralSecurityException | IOException e) {
      throw new IOException("Failed to load the trust store \"" + trustStorePath
          + "\" of type \"" + trustStoreType + "\" declared in "
          + SSL_TRUSTSTORE + ": " + e, e);
    } finally {
      if (password != null) {
        Arrays.fill(password, '\0');
      }
    }
  }

  /**
   * Look up the trust store password through the standard S3A secret
   * resolution path, which covers plain XML values, per-bucket overrides and
   * Hadoop credential providers.
   * @param conf the configuration of the filesystem.
   * @param trustStorePath path of the trust store, for the log message.
   * @return the password, or null if none is configured.
   * @throws IOException failure to read a credential provider.
   */
  private static char[] lookupTrustStorePassword(Configuration conf,
      String trustStorePath) throws IOException {
    // the bucket is empty as bucket overrides have already been propagated
    // into this configuration by S3AUtils.propagateBucketOptions().
    String password =
        S3AUtils.lookupPassword("", conf, SSL_TRUSTSTORE_PASSWORD);
    if (password == null || password.isEmpty()) {
      LOG.warn("No password declared in {}: the integrity of the trust store"
              + " {} will not be verified when it is loaded",
          SSL_TRUSTSTORE_PASSWORD, trustStorePath);
      return null;
    }
    return password.toCharArray();
  }

  /**
   * Build the identifier of a trust configuration, used to report a request
   * discarded by the JVM-wide socket factory.
   * @param trustStorePath path of the trust store.
   * @param trustStoreType type of the trust store.
   * @return an identifier of the configured trust store.
   */
  private static String trustConfigId(String trustStorePath,
      String trustStoreType) {
    return trustStorePath + " (type " + trustStoreType + ")";
  }

  /**
   * Load the trust store declared in the configuration, for clients which
   * cannot be bound to the delegating SSL socket factory and so have to
   * install the trust managers themselves; the Netty-based asynchronous
   * client is the only such client today.
   * <p>
   * Unlike {@link #bindSSLChannelMode(Configuration, ApacheHttpClient.Builder)}
   * this does not go through the JVM-wide socket factory, so each client gets
   * the trust store declared in its own configuration.
   * @param conf the configuration of the filesystem.
   * @return the trust managers, or null if no trust store is configured.
   * @throws IOException the trust store is configured but cannot be loaded.
   */
  public static TrustManagerFactory createTrustManagerFactory(
      Configuration conf) throws IOException {
    return loadTrustStore(conf).factory;
  }

  /**
   * Configures the {@code SSLConnectionSocketFactory} used by the AWS SDK.
   * A custom Socket Factory can be set using the method
   * {@code setSslSocketFactory()}.
   * Uses reflection to do this via {@link ConfigureShadedAWSSocketFactory}
   * so as to avoid 
   * @param conf the {@link Configuration} used to get the client specified
   *             value of {@code SSL_CHANNEL_MODE}
   * @param httpClientBuilder the http client builder.
   * @throws IOException if there is an error while initializing the
   * {@code SSLSocketFactory} other than classloader problems.
   */
  public static void bindSSLChannelMode(Configuration conf,
      ApacheHttpClient.Builder httpClientBuilder) throws IOException {

    // Validate that SSL_CHANNEL_MODE is set to a valid value.
    String channelModeString = conf.getTrimmed(
            SSL_CHANNEL_MODE, DEFAULT_SSL_CHANNEL_MODE.name());
    DelegatingSSLSocketFactory.SSLChannelMode channelMode = null;
    for (DelegatingSSLSocketFactory.SSLChannelMode mode :
            DelegatingSSLSocketFactory.SSLChannelMode.values()) {
      if (mode.name().equalsIgnoreCase(channelModeString)) {
        channelMode = mode;
      }
    }
    if (channelMode == null) {
      throw new IllegalArgumentException(channelModeString +
              " is not a valid value for " + SSL_CHANNEL_MODE);
    }

    TrustStoreBinding trustStore = loadTrustStore(conf);

    // initialize the factory here, outside the try/catch below, so that
    // failures to bind (missing wildfly, bad trust material) surface to the
    // caller rather than being swallowed as a classloading problem.
    DelegatingSSLSocketFactory.initializeDefaultFactory(channelMode,
        trustStore.factory, trustStore.configId);

    try {
      // use reflection to load in our own binding class.
      // this is *probably* overkill, but it is how we can be fully confident
      // that no attempt will be made to load/link to the AWS Shaded SDK except
      // within this try/catch block
      Class<? extends ConfigureAWSSocketFactory> clazz =
          (Class<? extends ConfigureAWSSocketFactory>) Class.forName(BINDING_CLASSNAME);
      clazz.getConstructor()
          .newInstance()
          .configureSocketFactory(httpClientBuilder, channelMode,
              trustStore.factory, trustStore.configId);
    } catch (ClassNotFoundException | NoSuchMethodException |
            IllegalAccessException | InstantiationException |
            InvocationTargetException | LinkageError  e) {
      LOG.debug("Unable to create class {}, value of {} will be ignored",
          BINDING_CLASSNAME, SSL_CHANNEL_MODE, e);
    }
  }

  /**
   * Is this an AWS endpoint? looks at end of FQDN.
   * @param endpoint endpoint
   * @return true if the endpoint matches the requirements for an aws endpoint.
   */
  public static boolean isAwsEndpoint(final String endpoint) {
    return (endpoint.isEmpty()
        || endpoint.endsWith(".amazonaws.com")
        || endpoint.endsWith(".amazonaws.com.cn"));
  }

  /**
   * A loaded trust store: its trust managers and the identifier of the
   * configuration they were built from, kept together so that the
   * identifier reported in a conflict always describes the material
   * actually loaded.
   */
  private static final class TrustStoreBinding {

    /** No trust store configured: use the JVM defaults. */
    private static final TrustStoreBinding NONE =
        new TrustStoreBinding(null, null);

    private final TrustManagerFactory factory;

    private final String configId;

    private TrustStoreBinding(TrustManagerFactory factory, String configId) {
      this.factory = factory;
      this.configId = configId;
    }
  }

  /**
   * Interface used to bind to the socket factory, allows the code which
   * works with the shaded AWS libraries to exist in their own class.
   */
  interface ConfigureAWSSocketFactory {

    /**
     * Initialize the delegating socket factory and bind the http client
     * builder to it.
     * @param httpClientBuilder the http client builder.
     * @param channelMode the SSL channel mode to use.
     * @param tmf trust managers to install, or null for the JVM defaults.
     * @param trustConfigId identifier of the trust configuration behind
     *                      {@code tmf}, or null when it is null.
     * @throws IOException failure to initialize the socket factory.
     */
    void configureSocketFactory(ApacheHttpClient.Builder httpClientBuilder,
        DelegatingSSLSocketFactory.SSLChannelMode channelMode,
        TrustManagerFactory tmf,
        String trustConfigId)
        throws IOException;
  }

  /**
   * Given an S3 bucket region as returned by a bucket location query,
   * fix it into a form which can be used by other AWS commands.
   * <p>
   * <a href="https://forums.aws.amazon.com/thread.jspa?messageID=796829">
   * https://forums.aws.amazon.com/thread.jspa?messageID=796829</a>
   * </p>
   * See also {@code com.amazonaws.services.s3.model.Region.fromValue()}
   * for its conversion logic.
   * @param region region from S3 call.
   * @return the region to use in AWS services.
   */
  public static String fixBucketRegion(final String region) {
    return region == null || region.equals("US")
        ? "us-east-1"
        : region;
  }

  /**
   * Log the dns address associated with s3 endpoint. If endpoint is
   * not set in the configuration, the {@code Constants#DEFAULT_ENDPOINT}
   * will be used.
   * @param conf input configuration.
   */
  public static void logDnsLookup(Configuration conf) {
    String endPoint = conf.getTrimmed(ENDPOINT, DEFAULT_ENDPOINT);
    String hostName = endPoint;
    if (!endPoint.isEmpty() && LOG.isDebugEnabled()) {
      // Updating the hostname if there is a scheme present.
      if (endPoint.contains("://")) {
        try {
          URI uri = new URI(endPoint);
          hostName = uri.getHost();
        } catch (URISyntaxException e) {
          LOG.debug("Got URISyntaxException, ignoring");
        }
      }
      LOG.debug("Bucket endpoint : {}, Hostname : {}, DNSAddress : {}",
              endPoint,
              hostName,
              NetUtils.normalizeHostName(hostName));
    }
  }
}
