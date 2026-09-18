# Connect to one service

<!-- group:start -->
SQL, JMS, MQTT, Kafka and FTP against a service the Camel CLI starts for you with `camel infra run`.

| Example | What you will see | Needs |
|---|---|---|
| [SQL database](sql/) | Against a Postgres started with camel infra, a customers table is created, the three orders register their customers with an insert that counts orders on conflict, and every ten seconds a select lists the customers; run it twice and the order counts go up. | `camel infra run postgres` |
| [Artemis queue](artemis/) | The three orders are put on the orders queue of an ActiveMQ Artemis broker started with camel infra, and a consumer route takes them off and logs the customer and line count; the connection factory is declared in application.properties. | `camel infra run artemis` |
| [MQTT sensors](mqtt/) | Temperature sensors in the warehouse's cold rooms publish JSON readings on an MQTT topic of a Mosquitto broker started with camel infra; a consumer logs each reading and raises a warning when a room is above 8 degrees. | `camel infra run mosquitto` |
| [Kafka orders](kafka-orders/) | The three orders go through a shared validation route to a Kafka topic on a broker started with camel infra; the pending one is stopped, the paid ones are dispatched to the fulfilment and notifications topics, whose consumers log the picking and the email; camel cmd route-topology draws the flow. | `camel infra run kafka` |
| [FTP courier](ftp/) | Each order on the shipments queue of an Artemis broker becomes a file on the courier's FTP server, both started with camel infra; the log shows each shipment uploaded and camel infra get ftp shows where the files landed. | `camel infra run artemis ftp` |
| [Camel 1.0 tribute](camel-1-tribute/) | The very first Camel example of 2007, JMS to file: a timer sends ten messages to a queue on an Artemis broker started with camel infra, and the consumer writes each message to a file in outbox; the log shows both sides. | `camel infra run artemis` |

Start with [SQL database](sql/); the examples read best in the order above, each one building on what the one before it set up.

Every example has a README that says what you will see, how it works, how to build it step by step, what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
