# Contracts and security

<!-- group:start -->
An OpenAPI contract served and called, and an API protected by Keycloak.

| Example | What you will see | Needs |
|---|---|---|
| [OpenAPI server](openapi-server/) | The stock API contract first: stock-api.json is the OpenAPI contract, the REST DSL serves its three operations on port 8080 with request validation, GET /stock/{sku} answers from a file or 404, POST /stock/{sku}/reserve answers 200, 409 when the stock is short or 400 for a bad reservation, and /openapi serves the contract. | nothing |
| [OpenAPI client](openapi-client/) | The picking desk reserves stock for every order line by calling the stock API by contract: rest-openapi turns the operationId reserveStock into the HTTP call from stock-api.json; the log shows each reservation and one 409 for the cap that is out of stock. Needs the openapi-server example running. | nothing |
| [Keycloak security](keycloak-security-rest/) | Two HTTP endpoints on port 8081: the public one answers everyone, the protected one requires a bearer token from a Keycloak started with camel infra whose user has the admin role, otherwise 403; the realm, client and users are created in the Keycloak console as the README describes. | `camel infra run keycloak` |

Start with [OpenAPI server](openapi-server/); the examples read best in the order above, each one building on what the one before it set up.

Every example has a README that says what you will see, how it works, how to build it step by step, what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
