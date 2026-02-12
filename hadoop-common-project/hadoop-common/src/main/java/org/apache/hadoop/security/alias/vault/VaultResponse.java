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

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.hadoop.classification.InterfaceAudience;

/**
 * DTOs for Vault/OpenBao JSON API responses.
 * All classes use {@code ignoreUnknown = true} so that extra fields
 * returned by Vault do not cause deserialization failures.
 */
@InterfaceAudience.Private
final class VaultResponse {

  private VaultResponse() {
  }

  /**
   * Response from KV v2 read: {@code GET /v1/{mount}/data/{path}}.
   * <pre>
   * {"data": {"data": {"value": "secret"}, "metadata": {...}}}
   * </pre>
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  static class KvRead {
    @JsonProperty("data")
    KvReadData data;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  static class KvReadData {
    @JsonProperty("data")
    Map<String, String> data;
  }

  /**
   * Response from KV v2 list: {@code LIST /v1/{mount}/metadata/{path}}.
   * <pre>
   * {"data": {"keys": ["key1", "key2", "subdir/"]}}
   * </pre>
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  static class KvList {
    @JsonProperty("data")
    KvListData data;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  static class KvListData {
    @JsonProperty("keys")
    List<String> keys;
  }

  /**
   * Response from auth login (e.g. Kerberos):
   * {@code POST /v1/auth/kerberos/login}.
   * <pre>
   * {"auth": {"client_token": "s.xxxxx", ...}}
   * </pre>
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  static class AuthLogin {
    @JsonProperty("auth")
    AuthLoginData auth;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  static class AuthLoginData {
    @JsonProperty("client_token")
    String clientToken;
  }
}
