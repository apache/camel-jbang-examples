/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.util.Arrays;

import org.apache.camel.PropertyInject;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.keycloak.security.KeycloakSecurityPolicy;

/**
 * Keycloak Security REST API Example
 *
 * This example demonstrates how to secure REST APIs using Apache Camel with Keycloak
 * authentication and authorization. It uses the platform-http component to create REST
 * endpoints protected by Keycloak security policies.
 */
public class RestApi extends RouteBuilder {

    @PropertyInject("keycloak.server.url")
    private String keycloakServerUrl;

    @PropertyInject("keycloak.realm")
    private String realm;

    @PropertyInject("keycloak.client.id")
    private String clientId;

    @PropertyInject("keycloak.client.secret")
    private String clientSecret;

    @Override
    public void configure() throws Exception {

        KeycloakSecurityPolicy policy = new KeycloakSecurityPolicy();
        policy.setServerUrl(keycloakServerUrl);
        policy.setRealm(realm);
        policy.setClientId(clientId);
        policy.setClientSecret(clientSecret);
        policy.setRequiredRoles(Arrays.asList("admin"));

        // Public endpoint - no authentication required
        from("platform-http:/api/public")
            .routeId("public-api")
            .setBody()
                .simple("{\n" +
                    "  \"message\": \"This is a public endpoint, no authentication required\",\n" +
                    "  \"timestamp\": \"${date:now:yyyy-MM-dd'T'HH:mm:ss}\"\n" +
                    "}")
            .setHeader("Content-Type", constant("application/json"))
            .log("Public API called");

        // Protected endpoint - requires admin role
        from("platform-http:/api/protected")
            .routeId("protected-api")
            .policy(policy)
            .setBody()
                .simple("{\n" +
                    "  \"message\": \"This is a protected endpoint, admin role required\",\n" +
                    "  \"timestamp\": \"${date:now:yyyy-MM-dd'T'HH:mm:ss}\"\n" +
                    "}")
            .setHeader("Content-Type", constant("application/json"))
            .log("Protected API called");
    }
}
