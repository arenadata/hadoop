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

import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.http.apache.ApacheHttpClient;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.net.NetUtils;
import org.apache.hadoop.security.ssl.DelegatingSSLSocketFactory;

import javax.net.ssl.TrustManagerFactory;

import static org.apache.hadoop.fs.s3a.Constants.*;

/**
 * Configures network settings when communicating with AWS services.
 */
public final class NetworkBinding {

  private static final Logger LOG =
          LoggerFactory.getLogger(NetworkBinding.class);
  private static final String BINDING_CLASSNAME = "org.apache.hadoop.fs.s3a.impl.ConfigureShadedAWSSocketFactory";

  private NetworkBinding() {
  }

  private static String getTruststorePassword(Configuration conf) throws IOException {
    String trustStorePassword = conf.get(SSL_TRUSTSTORE_PASSWORD);
    if (trustStorePassword != null) {
      return trustStorePassword;
    }
    String trustStoreCredentialFile = conf.get(SSL_TRUSTSTORE_CREDENTIAL_FILE);
    if (trustStoreCredentialFile != null) {
      Configuration confProvider = new Configuration();
      confProvider.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH, trustStoreCredentialFile);
      List<CredentialProvider> providers = CredentialProviderFactory.getProviders(confProvider);
      for (CredentialProvider provider: providers) {
        try {
          CredentialProvider.CredentialEntry credEntry = provider.getCredentialEntry(SSL_TRUSTSTORE_CREDENTIAL_ALIAS);
          if (credEntry != null && credEntry.getCredential() != null) {
            return new String(credEntry.getCredential());
          }
        } catch (Exception ie) {
          LOG.error("Unable to get the Credential Provider from the Configuration", ie);
        }
      }
    }
    return null;
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

    TrustManagerFactory tmf = null;

    if (conf.get(SSL_TRUSTSTORE) != null) {
      String trustStorePath = conf.get(SSL_TRUSTSTORE);
      String trustStorePassword = getTruststorePassword(conf);
      try {
        KeyStore trustStore = KeyStore.getInstance(conf.get(SSL_TRUSTSTORE_TYPE, SSL_TRUSTSTORE_TYPE_DEFAULT));

        try (FileInputStream instream = new FileInputStream(trustStorePath)) {
          trustStore.load(instream, trustStorePassword.toCharArray());
        }

        tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
      } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
        throw new IOException(e);
      }
      DelegatingSSLSocketFactory.initializeDefaultFactory(channelMode, tmf);
    }else {
      DelegatingSSLSocketFactory.initializeDefaultFactory(channelMode);
    }
    try {
      // use reflection to load in our own binding class.
      // this is *probably* overkill, but it is how we can be fully confident
      // that no attempt will be made to load/link to the AWS Shaded SDK except
      // within this try/catch block
      Class<? extends ConfigureAWSSocketFactory> clazz =
          (Class<? extends ConfigureAWSSocketFactory>) Class.forName(BINDING_CLASSNAME);
      if (tmf != null) {
        clazz.getConstructor()
                .newInstance()
                .configureSocketFactory(httpClientBuilder, channelMode, tmf);
      } else {
        clazz.getConstructor()
                .newInstance()
                .configureSocketFactory(httpClientBuilder, channelMode);
      }
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
   * Interface used to bind to the socket factory, allows the code which
   * works with the shaded AWS libraries to exist in their own class.
   */
  interface ConfigureAWSSocketFactory {

    void configureSocketFactory(ApacheHttpClient.Builder httpClientBuilder,
        DelegatingSSLSocketFactory.SSLChannelMode channelMode)
        throws IOException;
    void configureSocketFactory(ApacheHttpClient.Builder httpClientBuilder,
                                DelegatingSSLSocketFactory.SSLChannelMode channelMode,
                                final TrustManagerFactory tmf)
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
