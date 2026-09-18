# MQTT sensors

Temperature sensors in the warehouse's cold rooms publish readings over MQTT every two seconds. The shop
watches the topic and raises an alert when a room gets too warm. The first route plays the sensors.

## What you will see

```text
INFO ... mqtt.camel.yaml:44 : cold-room-2: 6 °C, ok
WARN ... mqtt.camel.yaml:39 : cold-room-3: 10 °C, too warm, alert the warehouse
INFO ... mqtt.camel.yaml:44 : cold-room-1: 3 °C, ok
WARN ... mqtt.camel.yaml:39 : cold-room-1: 9 °C, too warm, alert the warehouse
```

## Install Camel CLI

<!-- see installation instructions in ../../install.adoc -->

## Run it

The example needs a running mosquitto, which the Camel CLI starts for you in a container
(Docker or Podman must be running). In one terminal:

```shell
camel infra run mosquitto
```

It prints the connection details as JSON; they match `application.properties`. In another terminal:

```shell
camel run *
```

Publish a reading yourself from a third terminal, and see the consumer react:

```shell
camel cmd send --endpoint="paho-mqtt5:warehouse/temperature?brokerUrl=tcp://localhost:1883" --body='{"sensor": "cold-room-9", "value": 14}'
```

Stop the example with `ctrl` + `c` and the service with `camel infra stop mosquitto`.

## How it works

- `paho-mqtt5` is the MQTT 5 client component; the topic is the endpoint path and the broker URL a parameter,
  read from `application.properties` with `{{mqtt.broker.url}}`.
- The `sensors` route publishes a JSON reading with a random room and value; a real warehouse has the sensors
  publishing and only the second route would be Camel.
- The `cold-rooms` route subscribes to the same topic, parses the JSON and logs at WARN above 8 degrees. MQTT
  delivers each message to every subscriber, so several consumers can watch the topic.

## Build it step by step

1. A timer route that publishes a fixed reading to `paho-mqtt5:warehouse/temperature`; start the broker and
   watch it connect.
2. Add the consumer route with a log of `${body}` and see the readings come back.
3. Randomise the reading, parse it and add the `choice` on the value.

## Try changing

- Subscribe with a wildcard, `warehouse/#`, and publish on `warehouse/humidity` as well.
- Set `qos: 1` on both endpoints and `retained: true` on the producer, then start a second consumer late.
- Point `mqtt.broker.url` at a real broker and delete the `sensors` route.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/mqtt.citrus.it.yaml`, which the Camel CLI runs. The test starts the service itself
with the same `camel infra` mechanism, so nothing must be running beforehand:

```shell
camel test run test/mqtt.citrus.it.yaml
```

The test starts Mosquitto, publishes a warm reading itself and verifies the alert.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
