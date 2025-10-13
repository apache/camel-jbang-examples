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
package org.apache.camel.example.pqc;

import java.security.KeyPair;
import java.security.Security;
import java.util.Base64;

import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.pqc.lifecycle.HashicorpVaultKeyLifecycleManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;

/**
 * RouteBuilder for PQC Document Signing with HashiCorp Vault integration.
 *
 * This class defines 12 routes:
 * 1. Initialize PQC signing key on startup
 * 2. REST API - Sign a document
 * 3. REST API - Verify a document signature
 * 4. REST API - Get key metadata
 * 5. REST API - List all keys
 * 6. REST API - Rotate signing key
 * 7. Scheduled job - Check key rotation needs
 * 8. Helper - Update key usage metadata
 * 9. Helper - Get key metadata
 * 10. Helper - Check key expiration and auto-rotate
 * 11. Helper - Automatic key rotation on expiration
 */
public class PQCDocumentSigningRoutes extends RouteBuilder {

    @Override
    public void configure() throws Exception {

        // Register BouncyCastle providers for PQC algorithms
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        // Register beans for HashiCorp Vault integration
        registerVaultBeans();

        // Route 1: Initialize PQC signing key on startup
        from("timer:init?repeatCount=1")
            .routeId("initialize-signing-key")
            .log("Initializing PQC signing key in Vault...")
            .bean("keyLifecycleManager", "generateKeyPair('DILITHIUM', 'document-signing-key')")
            .log("PQC signing key initialized successfully")
            .process(exchange -> {
                // Register the KeyPair bean directly for autowiring
                HashicorpVaultKeyLifecycleManager keyManager = exchange.getContext().getRegistry()
                    .lookupByNameAndType("keyLifecycleManager", HashicorpVaultKeyLifecycleManager.class);
                KeyPair keyPair = keyManager.getKey("document-signing-key");

                // Register as KeyPair type so PQC component can autowire it
                bindToRegistry("signingKey", keyPair);
            })
            .to("direct:get-key-metadata");

        // Route 2: REST API - Sign a document
        from("platform-http:/api/sign")
            .routeId("sign-document-api")
            .log("Received document signing request: ${body}")
            .setHeader("originalBody", simple("${body}"))
            // Sign the document using PQC
            .toD("pqc:sign?operation=sign&signatureAlgorithm=DILITHIUM&keyPair=#signingKey")
            // Convert binary signature to base64
            .process(exchange -> {
                byte[] signature = exchange.getMessage().getHeader("CamelPQCSignature", byte[].class);
                if (signature != null) {
                    String base64Signature = Base64.getEncoder().encodeToString(signature);
                    exchange.getMessage().setHeader("CamelPQCSignature", base64Signature);
                }
            })
            .log("Document signed with quantum-resistant signature")
            // Update key usage metadata
            .to("direct:update-key-usage")
            // Check if key needs rotation or has expired
            .to("direct:check-key-expiration")
            // Prepare response with signature and key metadata
            .setBody(simple("{\n" +
                "  \"status\": \"signed\",\n" +
                "  \"document\": \"${header.originalBody}\",\n" +
                "  \"signature\": \"${header.CamelPQCSignature}\",\n" +
                "  \"signatureAlgorithm\": \"DILITHIUM\",\n" +
                "  \"keyId\": \"document-signing-key\",\n" +
                "  \"keyMetadata\": ${body}\n" +
                "}"))
            .setHeader("Content-Type", constant("application/json"))
            .log("Response: ${body}");

        // Route 3: REST API - Verify a document signature
        from("platform-http:/api/verify")
            .routeId("verify-document-api")
            .log("Received document verification request: ${body}")
            // Get signature from X-Signature header (workaround for header filtering)
            .process(exchange -> {
                String base64Signature = exchange.getIn().getHeader("X-Signature", String.class);
                if (base64Signature == null || base64Signature.isEmpty()) {
                    throw new IllegalArgumentException("X-Signature header is missing or empty");
                }
                byte[] signature = Base64.getDecoder().decode(base64Signature);
                exchange.getIn().setHeader("CamelPQCSignature", signature);
                exchange.getIn().setHeader("signatureLength", signature.length);
            })
            .log("Verifying signature of length: ${header.signatureLength} bytes")
            // Verify the document signature using PQC
            .doTry()
                .toD("pqc:verify?operation=verify&signatureAlgorithm=DILITHIUM&keyPair=#signingKey")
                .log("Verification completed. Result: ${header.CamelPQCVerify}")
            .doCatch(Exception.class)
                .log("ERROR during verification: ${exception.message}")
                .setHeader("CamelPQCVerify", constant(false))
            .end()
            .choice()
                .when(simple("${header.CamelPQCVerify} == true"))
                    .setBody(simple("{\n" +
                        "  \"status\": \"verified\",\n" +
                        "  \"valid\": true,\n" +
                        "  \"message\": \"Document signature is valid\",\n" +
                        "  \"signatureAlgorithm\": \"DILITHIUM\"\n" +
                        "}"))
                .when(simple("${header.CamelPQCVerify} == false"))
                    .setBody(simple("{\n" +
                        "  \"status\": \"verified\",\n" +
                        "  \"valid\": false,\n" +
                        "  \"message\": \"Document signature is invalid\",\n" +
                        "  \"signatureAlgorithm\": \"DILITHIUM\"\n" +
                        "}"))
            .end()
            .setHeader("Content-Type", constant("application/json"))
            .log("Verification result: ${body}");

        // Route 4: REST API - Get key metadata
        from("platform-http:/api/key/metadata")
            .routeId("get-key-metadata-api")
            .log("Fetching key metadata...")
            .to("direct:get-key-metadata");

        // Route 5: REST API - List all keys
        from("platform-http:/api/keys")
            .routeId("list-keys-api")
            .log("Listing all PQC keys...")
            .bean("keyLifecycleManager", "listKeys")
            .setBody(simple("{\n" +
                "  \"keys\": ${body}\n" +
                "}"))
            .setHeader("Content-Type", constant("application/json"))
            .log("Keys listed: ${body}");

        // Route 6: REST API - Rotate signing key
        from("platform-http:/api/key/rotate")
            .routeId("rotate-key-api")
            .log("Rotating signing key...")
            .bean("keyLifecycleManager", "rotateKey('document-signing-key', 'document-signing-key-v2', 'DILITHIUM')")
            .log("Key rotated successfully: old key deprecated, new key active")
            .setBody(simple("{\n" +
                "  \"status\": \"rotated\",\n" +
                "  \"oldKey\": \"document-signing-key\",\n" +
                "  \"newKey\": \"document-signing-key-v2\",\n" +
                "  \"message\": \"Key rotation completed successfully\"\n" +
                "}"))
            .setHeader("Content-Type", constant("application/json"));

        // Route 7: Scheduled job - Check key rotation needs
        from("timer:checkRotation?period={{key.rotation.check.period}}")
            .routeId("check-rotation-schedule")
            .log("Checking if key needs rotation...")
            .bean("keyLifecycleManager", "needsRotation('document-signing-key', 'P{{key.max.age.days}}D', {{key.max.usage.count}})")
            .choice()
                .when(simple("${body} == true"))
                    .log("WARNING: Key 'document-signing-key' needs rotation!")
                    .to("direct:get-key-metadata")
                    .log("Current key metadata: ${body}")
                .otherwise()
                    .log("Key rotation not needed yet")
            .end();

        // Route 8: Helper - Update key usage metadata
        from("direct:update-key-usage")
            .routeId("update-key-usage")
            .bean("keyLifecycleManager", "getKeyMetadata('document-signing-key')")
            .setProperty("metadata", simple("${body}"))
            .process(exchange -> {
                // Update last used timestamp and increment usage count
                Object metadata = exchange.getProperty("metadata");
                if (metadata != null) {
                    // Call updateLastUsed on the metadata object
                    metadata.getClass().getMethod("updateLastUsed").invoke(metadata);
                    exchange.getMessage().setBody(metadata);
                }
            })
            .bean("keyLifecycleManager", "updateKeyMetadata('document-signing-key', ${body})")
            .log("Key usage updated. Usage count: ${body.usageCount}");

        // Route 9: Helper - Get key metadata
        from("direct:get-key-metadata")
            .routeId("get-key-metadata-helper")
            .bean("keyLifecycleManager", "getKeyMetadata('document-signing-key')")
            .setBody(simple("{\n" +
                "  \"keyId\": \"${body.keyId}\",\n" +
                "  \"algorithm\": \"${body.algorithm}\",\n" +
                "  \"status\": \"${body.status}\",\n" +
                "  \"createdAt\": \"${body.createdAt}\",\n" +
                "  \"lastUsedAt\": \"${body.lastUsedAt}\",\n" +
                "  \"usageCount\": ${body.usageCount},\n" +
                "  \"ageInDays\": ${body.ageInDays},\n" +
                "  \"expiresAt\": \"${body.expiresAt}\",\n" +
                "  \"nextRotationAt\": \"${body.nextRotationAt}\",\n" +
                "  \"expired\": ${body.expired},\n" +
                "  \"needsRotation\": ${body.needsRotation}\n" +
                "}"))
            .setHeader("Content-Type", constant("application/json"))
            .log("Key metadata: ${body}");

        // Route 10: Helper - Check key expiration and auto-rotate
        from("direct:check-key-expiration")
            .routeId("check-key-expiration")
            .bean("keyLifecycleManager", "getKeyMetadata('document-signing-key')")
            .choice()
                .when(simple("${body.usageCount} >= {{key.max.usage.count}}"))
                    .log("WARNING: Key has reached maximum usage count (${body.usageCount} >= {{key.max.usage.count}})")
                    .setProperty("expirationReason", simple("usage count (${body.usageCount} uses)"))
                    .to("direct:auto-rotate-key")
                .when(simple("${body.ageInDays} >= {{key.max.age.days}}"))
                    .log("WARNING: Key has reached maximum age (${body.ageInDays} >= {{key.max.age.days}} days)")
                    .setProperty("expirationReason", simple("age (${body.ageInDays} days)"))
                    .to("direct:auto-rotate-key")
                .otherwise()
                    .setBody(simple("Key is valid (usage: ${body.usageCount}/{{key.max.usage.count}}, age: ${body.ageInDays}/{{key.max.age.days}} days)"))
            .end();

        // Route 11: Helper - Automatic key rotation on expiration
        from("direct:auto-rotate-key")
            .routeId("auto-rotate-key")
            .log(">>> AUTOMATIC KEY ROTATION TRIGGERED <<<")
            .log("Reason: Key expired due to ${exchangeProperty.expirationReason}")
            // Generate new key ID with timestamp
            .setProperty("timestamp", simple("${date:now:yyyyMMdd-HHmmss}"))
            .setProperty("newKeyId", simple("document-signing-key"))
            .log("Rotating key from 'document-signing-key' to '${exchangeProperty.newKeyId}'")
            // Perform rotation
            .bean("keyLifecycleManager", "rotateKey('document-signing-key', '${exchangeProperty.newKeyId}', 'DILITHIUM')")
            .log(">>> KEY ROTATION COMPLETED <<<")
            .log("Old key 'document-signing-key' status: DEPRECATED")
            .log("New key '${exchangeProperty.newKeyId}' status: ACTIVE")
            // Update the active key reference for future operations
            .setProperty("activeKeyId", simple("${exchangeProperty.newKeyId}"))
            // Get metadata of new key
            .bean("keyLifecycleManager", "getKeyMetadata('${exchangeProperty.newKeyId}')")
            .setBody(simple("{\n" +
                "  \"rotationTriggered\": true,\n" +
                "  \"reason\": \"${exchangeProperty.expirationReason}\",\n" +
                "  \"oldKey\": \"document-signing-key\",\n" +
                "  \"oldKeyStatus\": \"DEPRECATED\",\n" +
                "  \"newKey\": \"${exchangeProperty.newKeyId}\",\n" +
                "  \"newKeyStatus\": \"ACTIVE\",\n" +
                "  \"newKeyCreatedAt\": \"${body.createdAt}\",\n" +
                "  \"message\": \"Key automatically rotated due to ${exchangeProperty.expirationReason}\"\n" +
                "}"))
            .log("Rotation details: ${body}");
    }

    /**
     * Register beans for HashiCorp Vault integration
     */
    private void registerVaultBeans() throws Exception {
        // Get configuration properties
        String vaultHost = getContext().resolvePropertyPlaceholders("{{vault.host}}");
        int vaultPort = Integer.parseInt(getContext().resolvePropertyPlaceholders("{{vault.port}}"));
        String vaultScheme = getContext().resolvePropertyPlaceholders("{{vault.scheme}}");
        String vaultToken = getContext().resolvePropertyPlaceholders("{{vault.token}}");
        String secretsEngine = getContext().resolvePropertyPlaceholders("{{vault.secrets.engine}}");
        String keyPrefix = getContext().resolvePropertyPlaceholders("{{vault.keys.prefix}}");

        // Create VaultEndpoint
        VaultEndpoint vaultEndpoint = new VaultEndpoint();
        vaultEndpoint.setHost(vaultHost);
        vaultEndpoint.setPort(vaultPort);
        vaultEndpoint.setScheme(vaultScheme);
        bindToRegistry("vaultEndpoint", vaultEndpoint);

        // Create TokenAuthentication
        TokenAuthentication tokenAuthentication = new TokenAuthentication(vaultToken);
        bindToRegistry("tokenAuthentication", tokenAuthentication);

        // Create VaultTemplate
        VaultTemplate vaultTemplate = new VaultTemplate(vaultEndpoint, tokenAuthentication);
        bindToRegistry("vaultTemplate", vaultTemplate);

        // Create HashicorpVaultKeyLifecycleManager using constructor with all parameters
        HashicorpVaultKeyLifecycleManager keyLifecycleManager =
            new HashicorpVaultKeyLifecycleManager(vaultHost, vaultPort, vaultScheme, vaultToken, secretsEngine, keyPrefix);
        bindToRegistry("keyLifecycleManager", keyLifecycleManager);
    }
}
