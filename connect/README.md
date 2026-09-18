# Connect without a service

<!-- group:start -->
Files, an HTTP client and a REST server; everything runs inside the example.

| Example | What you will see | Needs |
|---|---|---|
| [File processing](file-processing/) | A courier route copies five files into an inbox; the invoices are checked, archived under a month directory and moved to done, the invoice with a negative amount is rejected with a warning and moved to failed, and the driver's note is left alone because only .json files are picked up. | nothing |
| [Stock API](stock-api/) | The shop's stock service on port 8080: GET /stock returns the stock file, GET /stock/{sku} returns one SKU as JSON and a 404 with an error message for an unknown SKU. | nothing |
| [HTTP client](http-client/) | Every line of the three orders is checked against the stock service over HTTP, served by the same example; the log shows each line as ok, or back-order when the stock is short, with the stock level from the response. | nothing |

Start with [File processing](file-processing/); the examples read best in the order above, each one building on what the one before it set up.

Every example has a README that says what you will see, how it works, how to build it step by step, what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
