# Quick start

<!-- group:start -->
The first ten minutes: generic examples with no story and no service, each running in seconds.

| Example | What you will see | Needs |
|---|---|---|
| [Timer Log](timer-log/) | A timer fires every second and a log line prints the greeting from application.properties; the hello of Camel in one file. | nothing |
| [Routes](routes/) | A timer route in YAML calls a Java bean, Greeter, that builds the message, and logs what the bean returned; the first step from YAML into your own code. | nothing |
| [Splitter](splitter/) | A timer creates a comma-separated batch of items, the splitter turns it into one message per item, and each item is logged on its own line. | nothing |
| [REST API](rest-api/) | A REST API on port 8080: GET /api/hello answers the greeting from application.properties and GET /api/hello/{name} answers a greeting with the name. | nothing |

Start with [Timer Log](timer-log/); the others stand on their own, in any order.

Every example has a README that says what you will see, how it works, how to build it step by step, what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
