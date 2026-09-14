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

package org.apache.hadoop.security.alias;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.token.DelegationTokenIssuer;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;

/**
 * Test credential provider that issues delegation tokens, registered for
 * the {@code dtissuer} scheme in META-INF/services. The identifier of an
 * issued token is the renewer; the host {@code broken} cannot be created.
 */
public class TokenIssuingCredentialProvider extends CredentialProvider
    implements DelegationTokenIssuer {

  public static final String SCHEME = "dtissuer";
  public static final Text KIND = new Text("DT_ISSUER_TOKEN");
  public static final AtomicInteger ISSUED = new AtomicInteger();

  private final URI uri;

  TokenIssuingCredentialProvider(URI uri) {
    this.uri = uri;
  }

  /**
   * Factory for {@code dtissuer://<host>/} provider URIs.
   */
  public static class Factory extends CredentialProviderFactory {
    @Override
    public CredentialProvider createProvider(URI providerName,
        Configuration conf) throws IOException {
      if (!SCHEME.equals(providerName.getScheme())) {
        return null;
      }
      if ("broken".equals(providerName.getHost())) {
        throw new IOException("cannot create " + providerName);
      }
      return new TokenIssuingCredentialProvider(providerName);
    }
  }

  @Override
  public String getCanonicalServiceName() {
    return uri.toString();
  }

  @Override
  public Token<?> getDelegationToken(String renewer) {
    ISSUED.incrementAndGet();
    return new Token<TokenIdentifier>(
        renewer.getBytes(StandardCharsets.UTF_8), new byte[0], KIND,
        new Text(uri.toString()));
  }

  @Override
  public void flush() {
  }

  @Override
  public CredentialEntry getCredentialEntry(String alias) {
    return null;
  }

  @Override
  public List<String> getAliases() {
    return Collections.emptyList();
  }

  @Override
  public CredentialEntry createCredentialEntry(String name,
      char[] credential) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void deleteCredentialEntry(String name) {
    throw new UnsupportedOperationException();
  }
}
