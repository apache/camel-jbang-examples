# JMS request-reply

Traditional messaging with a broker. The orders go on a queue, each order asks a stock service for a reservation
and waits for the answer, and a reserved order is published on a topic that two departments subscribe to. An order
that cannot be reserved is tried three more times and then moved to a dead letter queue.

## What you will see

```text
INFO ... jms-request-reply.camel.yaml:28 : Order ORD-1001 put on the queue
INFO ... jms-request-reply.camel.yaml:47 : Reserving ORD-1001 for customer C-482
INFO ... jms-request-reply.camel.yaml:56 : Stock service answered for ORD-1001: reserved
INFO ... jms-request-reply.camel.yaml:122 : Shipping ORD-1001
INFO ... jms-request-reply.camel.yaml:133 : Invoicing ORD-1001
...
INFO ... jms-request-reply.camel.yaml:56 : Stock service answered for ORD-1003: not enough CAMEL-CAP
INFO ... jms-request-reply.camel.yaml:110 : Dead order ORD-1003
```

## Install Camel CLI

Install [JBang](https://www.jbang.dev/download/) and the Camel CLI as described in the
[root README](../../README.md#install-the-camel-cli); `camel --version` confirms the install.

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

The broker's web console is at http://localhost:8161 (user `artemis`, password `artemis`). It shows the queues
`orders`, `stock` and `orders.dead`, and the topic `orders.reserved`.

Stop the example with `ctrl` + `c` and the service with `camel infra stop artemis`.

## How it works

- `application.properties` declares the connection factory as a bean, as in the [artemis](../artemis/) example,
  and wires it into the `jms` component.
- `order-intake` reads each order, puts the order id and the customer in headers (JMS headers travel with the
  message), and sends the order to the `orders` queue.
- `reserve-order` takes the orders off the queue and asks the stock service. `exchangePattern: InOut` makes it a
  request-reply: the `jms` producer sends to the `stock` queue with a temporary reply queue and waits for the
  answer (20 seconds by default, the `requestTimeout` option). `variableReceive: answer` keeps the answer in a
  variable, so the order stays the body.
- `stock-service` is an ordinary consumer of the `stock` queue. Its answer is the body the route ends with, which
  the `jms` consumer sends to the reply queue the request named.
- An order the stock service cannot reserve throws an exception. The route's `deadLetterChannel` redelivers it
  three times, one second apart, and then sends the original order (`useOriginalMessage`) to the `orders.dead`
  queue, where `dead-orders` logs it.
- A reserved order goes to the topic `orders.reserved`. Unlike a queue, a topic gives every subscriber a copy, so
  `shipping` and `invoicing` both get it.

## Build it step by step

Ask your assistant, or type it yourself, one step at a time, and run after each:

1. A file route on `orders` that puts the order id and the customer in headers and logs each order.
2. Connect to the broker with the connection factory in `application.properties`, put the orders on the
   `orders` queue, and add a route `reserve-order` that takes them off and logs the customer.
3. Add the stock service on the `stock` queue, and ask it from `reserve-order` with request-reply.
4. Fail an order the stock service cannot reserve: redeliver it three times, then move it to the dead letter
   queue `orders.dead`, with a route that logs it.
5. Publish the reserved orders on the topic `orders.reserved`, with two subscriber routes.

## Try changing

- Give `CAMEL-CAP` a stock of 5 in `stock.json`: ORD-1003 is reserved and shipped.
- Stop the stock service with `camel cmd stop-route stock-service` and drop in a new order: the request waits
  for the `requestTimeout`, fails, and the order goes to the dead letter queue after the redeliveries.
- Remove the `dead-orders` route and restart: ORD-1003 stays on `orders.dead` in the console, as the broker keeps
  what no one has taken.
- Add a third subscriber to the topic.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/jms-request-reply.citrus.it.yaml`, which the Camel CLI runs. The test starts the service itself
with the same `camel infra` mechanism, so nothing must be running beforehand:

```shell
camel test run test/jms-request-reply.citrus.it.yaml
```

The test starts Artemis, runs the routes and verifies the answers of the stock service and the dead letter queue.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
