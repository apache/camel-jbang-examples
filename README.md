# Apache Camel CLI Examples

[Apache Camel](https://camel.apache.org/) is the open source integration framework: routes that connect systems
with the Enterprise Integration Patterns and 350+ components. These examples show it through the
[Camel CLI](https://camel.apache.org/manual/camel-jbang.html): one tool that runs a route, starts the services a
route needs, sends it a message, and runs its tests. No Maven, no Gradle, no Java project; a route is a YAML
file and a command.

## Install the Camel CLI

Install [JBang](https://www.jbang.dev/download/), then the CLI:

```shell
jbang app install camel@apache/camel
camel --version
```

The CLI needs a JDK 17 or later. The examples that start a service need Docker or Podman running.

## How the examples are organised

The examples form a ladder. Each group is a rung, and each rung builds on the ones before it, so read them in
order if Camel is new to you, or jump to the rung that has the thing you need. From the `run` rung onwards the
examples share one fictional web shop, with its orders, customers, warehouse and courier, so what one example
sets up the next one uses.

Every example has the same shape: a README that says what you will see when it runs, how it works, how to build
it yourself step by step and what to try changing; a `metadata.json` that lists what it teaches; and a test in
the [Citrus](https://citrusframework.org/) YAML DSL that the Camel CLI runs.

<!-- examples:start -->
### [Quick start](quick-start/)

The first ten minutes: generic examples with no story and no service, each running in seconds.

| Example | What you will see | Needs |
|---|---|---|
| [Timer Log](quick-start/timer-log/) | A timer fires every second and a log line prints the greeting from application.properties; the hello of Camel in one file. | nothing |
| [Routes](quick-start/routes/) | A timer route in YAML calls a Java bean, Greeter, that builds the message, and logs what the bean returned; the first step from YAML into your own code. | nothing |
| [Splitter](quick-start/splitter/) | A timer creates a comma-separated batch of items, the splitter turns it into one message per item, and each item is logged on its own line. | nothing |
| [REST API](quick-start/rest-api/) | A REST API on port 8080: GET /api/hello answers the greeting from application.properties and GET /api/hello/{name} answers a greeting with the name. | nothing |

### [Run](run/)

Running Camel: timers and cron schedules, a bean in a route, properties and profiles.

| Example | What you will see | Needs |
|---|---|---|
| [Order generator](run/order-generator/) | A timer creates a shop order every five seconds: a Java bean hands out the order number, the body is the order as JSON, and the log shows each new order. The order feed every later example starts from. | nothing |
| [Nightly report](run/nightly-report/) | A cron schedule runs the shop's inventory report, every ten seconds in the demo and nightly with a one-line change, and each run logs the stock counts with a timestamp. | nothing |
| [Properties and profiles](run/properties-and-profiles/) | A timer logs a welcome with the shop name and currency from application.properties; run with --profile=prod and application-prod.properties overrides both, so the same route greets with the production values. | nothing |

### [Transform and map](transform/)

JSON, XML and CSV in and out, field-by-field mapping, Groovy and XSLT.

| Example | What you will see | Needs |
|---|---|---|
| [JSON transform](transform/json-transform/) | The shop's order in order.json is reshaped for the warehouse: jsonpath reads the order id and the number of lines into headers, jq builds the pick list with only sku and quantity per line, and both the order and the pick list are logged. | nothing |
| [XML to JSON](transform/xml-to-json/) | A supplier's XML order dropped in the inbox directory is read with the Jackson XML data format and written out as the shop's JSON with the Jackson JSON data format, both logged; no mapping code, the XML elements and attributes become JSON fields. | nothing |
| [CSV to JSON](transform/csv-to-json/) | A CSV of invoices dropped in the inbox directory is read with the CSV data format, its header line naming the fields, split into one message per invoice, and each invoice is logged as JSON and written to the outbox directory as its own file. | nothing |
| [Data mapping](transform/data-mapping/) | The shop's order in order.json is mapped field by field to the courier's shipment format, with renamed fields, a nested recipient, one parcel per line, a computed total and a service chosen from the country; the order is parsed to a map, the script shipment-mapping.groovy builds the shipment, and it is logged as JSON. | nothing |
| [Groovy](transform/groovy/) | Two orders come in, one with a valid customer email and one with a bad one; a Groovy expression checks the address with Apache Commons Validator, a third-party library declared in application.properties, and the log shows one order accepted and one rejected. | nothing |
| [XSLT](transform/xslt/) | A supplier's XML order dropped in the inbox directory is transformed by the stylesheet packing-slip.xsl into the packing slip the warehouse prints, one item per line and the total pieces to pick, and the slip is logged. | nothing |

### [Route](route/)

The routing patterns: content-based router, splitter, aggregator, filter and multicast.

| Example | What you will see | Needs |
|---|---|---|
| [Content-based router](route/content-based-router/) | Three orders from three countries are read from the orders directory and a choice routes each by its country: the Danish order to local delivery, the German order to EU shipping without customs, the US order to export with a customs declaration; each branch logs what it did. | nothing |
| [Order lines](route/order-lines/) | Each order read from the orders directory is split into one message per line, the order id travels along in a header, and the log shows the order, one pick line per line, and the parent's confirmation that all lines went to picking. | nothing |
| [Aggregator](route/aggregator/) | The warehouse reports each picked line on its own and the aggregator collects the lines of one order back into a shipment, correlated by the order id and complete when as many lines are in as the order had; each shipment is logged as JSON. | nothing |
| [Filter and multicast](route/filter-and-multicast/) | Three orders are read from the orders directory; a filter lets only the paid ones through and a multicast sends each paid order to both the warehouse route and the invoicing route, which log their part; the pending order is logged as received and goes no further. | nothing |

### [Fail well](fail-well/)

Retries, a dead letter channel, and a circuit breaker in front of a flaky service.

| Example | What you will see | Needs |
|---|---|---|
| [Error handling](fail-well/error-handling/) | The three orders go to a payment provider: the first is charged at once, the second gets no answer twice and is charged on the third attempt after two retries logged as warnings, and the third is declined, logged as such and parked as a file for manual review. | nothing |
| [Circuit breaker](fail-well/circuit-breaker/) | A stock check calls the supplier every second; the supplier goes down for nine calls, the breaker opens after two failures in its window of four, answers from the fallback while open, tries the supplier again after five seconds and closes once a call succeeds; each line logs the breaker state. | nothing |

### [Connect without a service](connect/)

Files, an HTTP client and a REST server; everything runs inside the example.

| Example | What you will see | Needs |
|---|---|---|
| [File processing](connect/file-processing/) | A courier route copies five files into an inbox; the invoices are checked, archived under a month directory and moved to done, the invoice with a negative amount is rejected with a warning and moved to failed, and the driver's note is left alone because only .json files are picked up. | nothing |
| [Stock API](connect/stock-api/) | The shop's stock service on port 8080: GET /stock returns the stock file, GET /stock/{sku} returns one SKU as JSON and a 404 with an error message for an unknown SKU. | nothing |
| [HTTP client](connect/http-client/) | Every line of the three orders is checked against the stock service over HTTP, served by the same example; the log shows each line as ok, or back-order when the stock is short, with the stock level from the response. | nothing |

### [Connect to one service](connect-service/)

SQL, JMS, MQTT, Kafka and FTP against a service the Camel CLI starts for you with `camel infra run`.

| Example | What you will see | Needs |
|---|---|---|
| [SQL database](connect-service/sql/) | Against a Postgres started with camel infra, a customers table is created, the three orders register their customers with an insert that counts orders on conflict, and every ten seconds a select lists the customers; run it twice and the order counts go up. | `camel infra run postgres` |
| [Artemis queue](connect-service/artemis/) | The three orders are put on the orders queue of an ActiveMQ Artemis broker started with camel infra, and a consumer route takes them off and logs the customer and line count; the connection factory is declared in application.properties. | `camel infra run artemis` |
| [MQTT sensors](connect-service/mqtt/) | Temperature sensors in the warehouse's cold rooms publish JSON readings on an MQTT topic of a Mosquitto broker started with camel infra; a consumer logs each reading and raises a warning when a room is above 8 degrees. | `camel infra run mosquitto` |
| [Kafka orders](connect-service/kafka-orders/) | The three orders go through a shared validation route to a Kafka topic on a broker started with camel infra; the pending one is stopped, the paid ones are dispatched to the fulfilment and notifications topics, whose consumers log the picking and the email; camel cmd route-topology draws the flow. | `camel infra run kafka` |
| [FTP courier](connect-service/ftp/) | Each order on the shipments queue of an Artemis broker becomes a file on the courier's FTP server, both started with camel infra; the log shows each shipment uploaded and camel infra get ftp shows where the files landed. | `camel infra run artemis ftp` |
| [Camel 1.0 tribute](connect-service/camel-1-tribute/) | The very first Camel example of 2007, JMS to file: a timer sends ten messages to a queue on an Artemis broker started with camel infra, and the consumer writes each message to a file in outbox; the log shows both sides. | `camel infra run artemis` |

### [Contracts and security](contracts/)

An OpenAPI contract served and called, and an API protected by Keycloak.

| Example | What you will see | Needs |
|---|---|---|
| [OpenAPI server](contracts/openapi-server/) | The stock API contract first: stock-api.json is the OpenAPI contract, the REST DSL serves its three operations on port 8080 with request validation, GET /stock/{sku} answers from a file or 404, POST /stock/{sku}/reserve answers 200, 409 when the stock is short or 400 for a bad reservation, and /openapi serves the contract. | nothing |
| [OpenAPI client](contracts/openapi-client/) | The picking desk reserves stock for every order line by calling the stock API by contract: rest-openapi turns the operationId reserveStock into the HTTP call from stock-api.json; the log shows each reservation and one 409 for the cap that is out of stock. Needs the openapi-server example running. | nothing |
| [Keycloak security](contracts/keycloak-security-rest/) | Two HTTP endpoints on port 8081: the public one answers everyone, the protected one requires a bearer token from a Keycloak started with camel infra whose user has the admin role, otherwise 403; the realm, client and users are created in the Keycloak console as the README describes. | `camel infra run keycloak` |

### [AI](ai/)

A local model writing text, routes exposed as MCP tools, RAG over documents, PII redaction.

| Example | What you will see | Needs |
|---|---|---|
| [LangChain4j chat](ai/langchain4j-chat/) | A local Ollama model started with camel infra writes the shipping notification for each of the three orders; the chat model is a bean built from properties, the prompt comes from the order, and the log shows the reply with its token counts. | `camel infra run ollama`, a local model |
| [MCP server](ai/mcp-server/) | Two routes are exposed as MCP tools, stock_level by SKU and order_status by order id, on http://localhost:8080/mcp with nothing but properties to switch the server on; any MCP client, a coding agent included, can list and call them, and the log shows each call. | nothing |
| [OpenAI PII Redaction](ai/openai-pii-redaction/) | Text typed on standard input is sent to an OpenAI-compatible model with a JSON schema that asks for the personal identifiers redacted, and the redacted text is printed on standard output. | nothing |
| [Document Analysis with Docling and LangChain4j RAG](ai/docling-langchain4j-rag/) | Documents dropped in a directory are converted by a running Docling service, chunked and summarised by a local Ollama model through langchain4j-chat, and written to an output directory; an HTTP endpoint answers questions against the converted documents. | `camel infra run docling ollama` |

### [Cloud](cloud/)

A cloud service, run locally through LocalStack and switched to the real thing by properties.

| Example | What you will see | Needs |
|---|---|---|
| [AWS SQS](cloud/aws-sqs/) | Each of the three orders is put on an Amazon SQS queue called shipments and a courier route takes it off and logs the order, country and line count; locally the queue lives on the LocalStack that camel infra run aws sqs starts, and the same properties point at real AWS. | `camel infra run aws` |

### [Showcase](showcase/)

Tooling demos outside the ladder: the TUI, a memory leak, message sizes, log analysis.

| Example | What you will see | Needs |
|---|---|---|
| [TUI Hello World](showcase/tui-hello-world/) | A one-shot timer prints an invitation; the route direct:greet then logs and greets any message sent to it from the CLI (camel cmd send --endpoint=direct:greet --body=...) or from a tool that can send messages. | nothing |
| [Memory Leak](showcase/memory-leak/) | Three timer routes run side by side: two leak memory into a cache and a buffer, one is healthy, so a JFR Old Object Sample recording and the CLI's heap tools show which route leaks. | nothing |
| [Message Size](showcase/message-size/) | Timer routes send messages of small, medium and large sizes to seda queues with a Content-Length header, so camel cmd and the CLI's message-size views show sizes per endpoint. | nothing |
| [Smart Log Analyzer](showcase/smart-log-analyzer/) | A multi-part showcase: a load generator produces logs and traces, a correlator maps OpenTelemetry logs to traces, an LLM analyses the correlated records, and a small web console with a REST API shows the results. | nothing |
<!-- examples:end -->

The directories `security`, `transformation` and the rest of `cloud` hold larger examples outside the ladder,
kept as reference: post-quantum cryptography, OCSF, an LDAP to Keycloak migration, EDI over AS2, IBM Cloud
Object Storage and Kubernetes. Each has its own README.

## Run an example

Every README says the same three things. Go into the directory and run it:

```shell
cd route/content-based-router
camel run *
```

When an example needs a service, start it first, in another terminal; the CLI starts it in a container and
prints the connection details, which match the example's `application.properties`:

```shell
camel infra run postgres
```

Send a message to a running route from a third terminal, when you want to poke at it:

```shell
camel cmd send --endpoint=direct:greet --body="Hello"
```

Stop a route with `ctrl` + `c` and a service with `camel infra stop postgres`.

## Test an example

The test of an example lives in its `test/` directory, in the Citrus YAML DSL, named after the route file:
`route/aggregator/test/aggregator.citrus.it.yaml`. The Camel CLI runs it, and the test starts the route, and the
service if it needs one, itself:

```shell
camel test run test/aggregator.citrus.it.yaml
```

The test plugin installs on first use. The `build.yml` workflow runs every test on every pull request; the few
examples marked `ciSkip` in their metadata, the ones that need a language model, are run by hand.

## Add an example

`AGENTS.md` has the conventions and a checklist, written for people and for coding agents alike. In short: one
directory per example, the route in canonical YAML DSL, a README in the shape above, a `metadata.json` with the
group as `level` and a `teaches` block, a Citrus YAML test, an entry in the CI matrix, and
`./generate-catalog.sh` to refresh the catalog and the tables above.

## Other examples

More Camel CLI examples, built on Kamelets, are at
https://github.com/apache/camel-kamelets-examples/tree/main/jbang

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
