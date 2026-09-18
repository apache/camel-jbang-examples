# Kafka orders

Orders flow through validation to a Kafka topic, where two departments pick them up independently: fulfilment
picks the goods, notification emails the customer. Each department is its own consumer, so one can be down
while the other keeps working, and the topic keeps the orders until they catch up.

## What you will see

```text
INFO ... kafka-orders.camel.yaml:56 : Order ORD-1001 validated
INFO ... kafka-orders.camel.yaml:34 : Published ORD-1001 to the orders topic
INFO ... kafka-orders.camel.yaml:56 : Order ORD-1002 validated
INFO ... kafka-orders.camel.yaml:34 : Published ORD-1002 to the orders topic
INFO ... kafka-orders.camel.yaml:51 : Order ORD-1003 is pending, not published
INFO ... kafka-orders.camel.yaml:67 : Dispatching ORD-1001 from partition 0 offset 0
INFO ... kafka-orders.camel.yaml:90 : Fulfilment: 2 line(s) of ORD-1001 to the warehouse
INFO ... kafka-orders.camel.yaml:103 : Notification: email to customer C-482 about ORD-1001
...
```

## Install Camel CLI

<!-- see installation instructions in ../../install.adoc -->

## Run it

The example needs a running kafka, which the Camel CLI starts for you in a container
(Docker or Podman must be running). In one terminal:

```shell
camel infra run kafka
```

It prints the connection details as JSON; they match `application.properties`. In another terminal:

```shell
camel run *
```

See how the routes connect, with the topics between them, while it runs:

```shell
camel cmd route-topology kafka-orders
```

Run it again and the offsets continue where they were: the topic remembers.

Stop the example with `ctrl` + `c` and the service with `camel infra stop kafka`.

## How it works

- `camel.component.kafka.brokers` in `application.properties` points every `kafka` endpoint at the broker.
- `incoming-orders` reads the order files, keeps the order id and status in headers with `jsonpath`, and calls
  the shared `validate-order` route, which logs and `stop`s a pending order; `stop` ends the whole exchange,
  so the caller does not publish it.
- The paid order is published with `CamelKafkaKey` set to the order id, so all events of one order land on the
  same partition and stay in order.
- `dispatch` consumes `orders` and `multicast`s to two topics; `fulfilment` and `notification` consume those.
  `CamelKafkaPartition` and `CamelKafkaOffset` are set by the consumer on every message.
- Topics are created on first use by this broker; a production cluster usually has that switched off.

## Build it step by step

1. A file route on `orders` that publishes each file to `kafka:orders`, and a consumer route that logs it.
2. Pull the validation into a `direct` route with the `choice` and `stop`.
3. Add the `multicast` to two more topics and a consumer for each.
4. Set the key and log partition and offset in `dispatch`.

## Try changing

- Kill the example while it is running and start it again: the consumers resume from their committed offsets.
- Give `fulfilment` a `groupId` and start the example twice: the two instances share the partitions.
- Replace the file consumer with a `platform-http` route that accepts orders with `POST /orders`.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/kafka-orders.citrus.it.yaml`, which the Camel CLI runs. The test starts the service itself
with the same `camel infra` mechanism, so nothing must be running beforehand:

```shell
camel test run test/kafka-orders.citrus.it.yaml
```

The test starts Kafka, runs the routes and verifies validation, the stopped order and both departments.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
