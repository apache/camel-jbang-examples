# Camel 1.0 tribute

The very first Camel example of 2007, JMS to file, as it looks today: a timer sends ten messages to a queue
on an ActiveMQ Artemis broker started with `camel infra`, and a consumer route writes each message to a file
in `outbox`.

When Apache Camel 1.0 was released in June 2007, the project shipped with just two examples. The first was
`camel-example-jms-file`: a route that consumed messages from a JMS queue and saved them to the file system.
Camel was still part of the Apache ActiveMQ project, the README was signed _"The Apache ActiveMQ team"_, and
classes like `CamelTemplate` (later renamed `ProducerTemplate`) were brand new. The original looked like this:

```java
CamelContext context = new DefaultCamelContext();

ConnectionFactory connectionFactory =
    new ActiveMQConnectionFactory("vm://localhost?broker.persistent=false");
context.addComponent("test-jms",
    JmsComponent.jmsComponentAutoAcknowledge(connectionFactory));

context.addRoutes(new RouteBuilder() {
    public void configure() {
        from("test-jms:queue:test.queue").to("file://test");
    }
});

CamelTemplate template = new CamelTemplate(context);
context.start();

for (int i = 0; i < 10; i++) {
    template.sendBody("test-jms:queue:test.queue", "Test Message: " + i);
}
```

Forty lines of Java, a Maven project, an embedded broker and manual component wiring. Today it is one YAML
file and one command.

## What you will see

```text
INFO ... jms-to-file.camel.yaml:32 : Sending: Test Message: 1
INFO ... jms-to-file.camel.yaml:10 : Received: Test Message: 1
INFO ... jms-to-file.camel.yaml:32 : Sending: Test Message: 2
INFO ... jms-to-file.camel.yaml:10 : Received: Test Message: 2
...
INFO ... jms-to-file.camel.yaml:32 : Sending: Test Message: 10
INFO ... jms-to-file.camel.yaml:10 : Received: Test Message: 10
```

and ten files in `outbox`, one per message.

## Install Camel CLI

Install [JBang](https://www.jbang.dev/download/) and the Camel CLI as described in the
[root README](../../README.md#install-the-camel-cli); `camel --version` confirms the install.

## Run it

The example needs a running ActiveMQ Artemis broker, which the Camel CLI starts for you in a container
(Docker or Podman must be running). In one terminal:

```shell
camel infra run artemis
```

It prints the connection details as JSON; they match `application.properties`. In another terminal:

```shell
camel run *
```

Stop the example with `ctrl` + `c` and the service with `camel infra stop artemis`.

## How it works

- `jms-to-file.camel.yaml` holds two routes. `jms-to-file` is the original: `from` the `jms` queue
  `test.queue`, log, `to` the `file` directory `outbox`. `send-test-messages` replaces the `for` loop: a
  `timer` with `repeatCount: 10` sends "Test Message: N" to the same queue, with `N` from the
  `CamelTimerCounter` header the timer sets when `includeMetadata` is on.
- `application.properties` declares the connection factory as a bean, `camel.beans.artemisCF`, with the
  broker URL, user and password `camel infra` printed, and hands it to the `jms` component with
  `camel.component.jms.connection-factory`. That is the `addComponent` of the original, as properties.
- The original wrote to a directory named `test`; here that name holds the integration test, so the files go
  to `outbox`.

What changed in 19 years:

| | Camel 1.0 (2007) | Camel CLI (today) |
|---|---|---|
| **Language** | Java (40+ lines) | YAML (35 lines) |
| **Build** | Maven project with pom.xml | No build needed |
| **Broker** | Embedded ActiveMQ (in-process) | Apache ActiveMQ Artemis (container) |
| **Component setup** | Manual `ConnectionFactory` wiring | Configured by properties |
| **Run command** | `mvn camel:run` | `camel run *` |
| **Dependencies** | Declared in pom.xml | Downloaded on first run |

What stayed the same: `from("jms:queue:test.queue").to("file://test")`, the routing idea that made Camel.

## Build it step by step

Ask your assistant, or type it yourself, one step at a time, and run after each, with the broker running:

1. A route from a timer, ten times, that logs "Test Message" with the timer counter.
2. Declare the Artemis connection factory in `application.properties` and send the message to the `jms`
   queue `test.queue` instead of logging it.
3. A second route from the same queue that logs what it receives.
4. Write each received message to a file in `outbox`.

## Try changing

- Open the broker's console at http://localhost:8161 (user `artemis`, password `artemis`) and watch the queue's
  message counts while the example runs.
- `fileName: "message-${header.CamelTimerCounter}.txt"` on the `file` endpoint; the header survives the queue
  because the JMS component carries headers as message properties.
- Stop the `jms-to-file` route with `camel cmd stop-route camel-1-tribute --id=jms-to-file` from another
  terminal, and the messages queue up in the broker until you start it again.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/camel-1-tribute.citrus.it.yaml`, which the Camel CLI runs. The test starts the broker itself with
`camel infra`, so nothing must be running beforehand:

```shell
camel test run test/camel-1-tribute.citrus.it.yaml
```

The test verifies the tenth message is sent and received.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
