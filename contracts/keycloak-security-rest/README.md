# Keycloak security

An API protected by Keycloak: two HTTP endpoints on port 8081, a public one that answers everyone and a
protected one that requires a bearer token from a Keycloak started with `camel infra`, issued to a user with
the `admin` role; anyone else gets 403.

## What you will see

```text
$ curl localhost:8081/api/public
{"message": "This is a public endpoint, no authentication required", "timestamp": "2026-09-20T10:30:00"}

$ curl -i -H "Authorization: Bearer $USER_TOKEN" localhost:8081/api/protected
HTTP/1.1 403 Forbidden
{"error": "Forbidden", "message": "Access denied. ...", "timestamp": "2026-09-20T10:30:05", "status": 403}

$ curl -H "Authorization: Bearer $ADMIN_TOKEN" localhost:8081/api/protected
{"message": "This is a protected endpoint, admin role required", "timestamp": "2026-09-20T10:30:10"}
```

and in the log:

```text
INFO ... rest-api.camel.yaml:80 : Public API called
INFO ... rest-api.camel.yaml:50 : Authorization failed: ...
INFO ... rest-api.camel.yaml:104 : Protected API called
```

## Install Camel CLI

Install [JBang](https://www.jbang.dev/download/) and the Camel CLI as described in the
[root README](../../README.md#install-the-camel-cli); `camel --version` confirms the install.

## Run it

The example needs a running Keycloak, which the Camel CLI starts for you in a container (Docker or Podman must
be running). In one terminal:

```shell
camel infra run keycloak
```

It prints the URL, http://localhost:8080, and the admin user (`admin`, password `admin`). Keycloak knows
nothing about the shop yet, so the realm, client, role and users are created once in its console, in the
browser at http://localhost:8080:

1. **Realm**: the dropdown top left says `master`; *Create realm*, name `camel`.
2. **Client**: *Clients*, *Create client*, client ID `camel-client`; on the next page enable *Client
   authentication* and *Service accounts roles*; save. On the *Credentials* tab copy the *Client Secret* into
   `application.properties` as `keycloak.client.secret`.
3. **Role**: *Realm roles*, *Create role*, name `admin`.
4. **Users**: *Users*, *Add user*, username `testuser`; on the *Credentials* tab set the password `password`
   with *Temporary* off. The same for `admin-user`, and on its *Role mapping* tab assign the `admin` role.

Then, in another terminal:

```shell
camel run *
```

The API starts on port 8081, because Keycloak has 8080. Get a token per user from Keycloak, with `jq` to pick it
out of the answer, and call the endpoints as above:

```shell
export USER_TOKEN=$(curl -s -X POST http://localhost:8080/realms/camel/protocol/openid-connect/token \
  -d "grant_type=password" -d "client_id=camel-client" -d "client_secret=<your-client-secret>" \
  -d "username=testuser" -d "password=password" | jq -r '.access_token')
export ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/realms/camel/protocol/openid-connect/token \
  -d "grant_type=password" -d "client_id=camel-client" -d "client_secret=<your-client-secret>" \
  -d "username=admin-user" -d "password=password" | jq -r '.access_token')
```

Stop the example with `ctrl` + `c` and the service with `camel infra stop keycloak`.

## How it works

- `rest-api.camel.yaml` declares the bean `keycloakPolicy`, a `KeycloakSecurityPolicy` from the `camel-keycloak`
  component, with the server, realm, client and `requiredRoles: admin` from `application.properties`. The
  `# camel-k: dependency=camel:keycloak` line at the top makes the CLI download the component, which it cannot
  guess from a bean class.
- Two routes from `platform-http`, the HTTP server built into the CLI. `public-api` just answers. `protected-api`
  starts with `policy: {ref: keycloakPolicy}`: the policy reads the bearer token from the `Authorization`
  header, validates it against Keycloak, checks the roles in it, and only then lets the message through to the
  steps that build the answer.
- A token that is missing, invalid or without the role makes the policy throw `CamelAuthorizationException`.
  The `onException` at the top handles it for every route: status 403 in the `CamelHttpResponseCode` header, a
  JSON error body, and a log line.
- `application.properties` holds the Keycloak details, the client secret you copied, and `camel.server.port`.

## Build it step by step

Ask your assistant, or type it yourself, one step at a time, and run after each, with Keycloak running and
configured:

1. A route from `platform-http:/api/public` that answers a JSON message; `curl` it.
2. A second route on `/api/protected` that answers another message.
3. The `keycloakPolicy` bean with the server, realm, client and secret from `application.properties`, and a
   `policy` step as the first step of the protected route; `curl` it without a token and see the error.
4. The `onException` for `CamelAuthorizationException` that answers 403 with a JSON body.
5. Get a token for `admin-user` and call the protected endpoint with it.

## Try changing

- `requiredRoles: "admin,manager"` on the policy and a `manager` role in Keycloak: `allRolesRequired` decides
  whether a user needs both or one of them.
- Log `${header.Authorization}` in the protected route to see the raw token, and paste it into
  https://jwt.io to read the roles Keycloak put in it.
- Protect the public endpoint too, with a second policy that has no `requiredRoles`: any valid token passes.

## Integration testing

The example has no Citrus test: the realm, client and users are created by hand in the Keycloak console, so
there is nothing a test could start from. Verify it with the `curl` calls above.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
