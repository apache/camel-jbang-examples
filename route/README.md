# Route

<!-- group:start -->
The routing patterns: content-based router, splitter, aggregator, filter and multicast.

| Example | What you will see | Needs |
|---|---|---|
| [Content-based router](content-based-router/) | Three orders from three countries are read from the orders directory and a choice routes each by its country: the Danish order to local delivery, the German order to EU shipping without customs, the US order to export with a customs declaration; each branch logs what it did. | nothing |
| [Order lines](order-lines/) | Each order read from the orders directory is split into one message per line, the order id travels along in a header, and the log shows the order, one pick line per line, and the parent's confirmation that all lines went to picking. | nothing |
| [Aggregator](aggregator/) | The warehouse reports each picked line on its own and the aggregator collects the lines of one order back into a shipment, correlated by the order id and complete when as many lines are in as the order had; each shipment is logged as JSON. | nothing |
| [Filter and multicast](filter-and-multicast/) | Three orders are read from the orders directory; a filter lets only the paid ones through and a multicast sends each paid order to both the warehouse route and the invoicing route, which log their part; the pending order is logged as received and goes no further. | nothing |

Start with [Content-based router](content-based-router/); the examples read best in the order above, each one building on what the one before it set up.

Every example has a README that says what you will see, how it works, how to build it step by step, what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
