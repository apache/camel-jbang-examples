# Artemis queue

Orders go on a queue on an ActiveMQ Artemis broker and a consumer takes them off. The queue keeps the two sides
apart: the intake keeps working when processing is down, and the broker holds the orders until it is back.

## What you will see

```text
INFO ... artemis.camel.yaml:23 : Order ORD-1001 put on the queue
INFO ... artemis.camel.yaml:37 : Took ORD-1001 off the queue: 2 line(s) for customer C-482 in DK
INFO ... artemis.camel.yaml:23 : Order ORD-1002 put on the queue
INFO ... artemis.camel.yaml:37 : Took ORD-1002 off the queue: 1 line(s) for customer C-207 in DE
...
```

## Install Camel CLI

<!-- see installation instructions in ../../install.adoc -->

## Run it

The example needs a running artemis, which the Camel CLI starts for you in a container
(Docker or Podman must be running). In one terminal:

```shell
camel infra run artemis
```

It prints the connection details as JSON; they match `application.properties`. In another terminal:

```shell
camel run *
```

The broker's web console is at http://localhost:8161 (user `artemis`, password `artemis`), where the `orders`
queue shows its message counts.

Stop the example with `ctrl` + `c` and the service with `camel infra stop artemis`.

## How it works

- `application.properties` declares the connection factory as a bean, `#class:...ActiveMQConnectionFactory`,
  with the broker URL, user and password `camel infra run artemis` prints, and wires it into the `jms` component.
  The CLI downloads the Artemis client from the class name.
- `order-intake` reads each order file and sends the text to the `orders` queue; `order-processing` consumes the
  queue. JMS delivers each message to one consumer, which is what makes a queue a work list.
- The order id is put in a header before sending: JMS headers travel with the message.

## Build it step by step

1. A file route on `orders` sending to `jms:queue:orders`; start the broker and see the messages arrive in the
   console.
2. Add the consumer route with a log of `${body}`.
3. Parse the JSON and log the customer and line count; add the header.

## Try changing

- Stop the consumer route with `camel cmd stop-route order-processing`, drop a new order file in, and see it
  wait on the queue in the console until you `start-route` again.
- Use a topic instead of a queue, `destinationType: topic`, and add a second consumer route: both get every order.
- Add `camel.beans.artemisCF.retryInterval` and other factory properties and see them applied.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/artemis.citrus.it.yaml`, which the Camel CLI runs. The test starts the service itself
with the same `camel infra` mechanism, so nothing must be running beforehand:

```shell
camel test run test/artemis.citrus.it.yaml
```

The test starts Artemis, runs the routes and verifies both sides of the queue.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
