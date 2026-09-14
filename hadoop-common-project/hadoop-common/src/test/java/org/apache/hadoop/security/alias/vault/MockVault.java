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
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.Predicate;

import com.sun.net.httpserver.HttpExchange;

/**
 * Responses of a mock Vault server backed by {@code com.sun.net.httpserver}.
 */
final class MockVault {

  static final String SECRET_PATH = "/v1/secret/data/hadoop/creds/db.password";
  static final String SECRET_VALUE = "s3cret";
  static final String PERMISSION_DENIED =
      "{\"errors\":[\"permission denied\"]}";

  private MockVault() {
  }

  /**
   * Serve the KV secret when the request carries an accepted Vault token.
   */
  static void handleSecret(HttpExchange exchange,
      Predicate<String> tokenAccepted) throws IOException {
    String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");
    if (token != null && tokenAccepted.test(token)) {
      sendResponse(exchange, 200,
          "{\"data\":{\"data\":{\"value\":\"" + SECRET_VALUE + "\"}}}");
    } else {
      sendResponse(exchange, 403, PERMISSION_DENIED);
    }
  }

  static void sendResponse(HttpExchange exchange, int statusCode,
      String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(statusCode, bytes.length > 0 ? bytes.length : -1);
    if (bytes.length > 0) {
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(bytes);
      }
    }
    exchange.close();
  }
}
