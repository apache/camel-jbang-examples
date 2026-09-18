# Run

<!-- group:start -->
Running Camel: timers and cron schedules, a bean in a route, properties and profiles.

| Example | What you will see | Needs |
|---|---|---|
| [Order generator](order-generator/) | A timer creates a shop order every five seconds: a Java bean hands out the order number, the body is the order as JSON, and the log shows each new order. The order feed every later example starts from. | nothing |
| [Nightly report](nightly-report/) | A cron schedule runs the shop's inventory report, every ten seconds in the demo and nightly with a one-line change, and each run logs the stock counts with a timestamp. | nothing |
| [Properties and profiles](properties-and-profiles/) | A timer logs a welcome with the shop name and currency from application.properties; run with --profile=prod and application-prod.properties overrides both, so the same route greets with the production values. | nothing |

Start with [Order generator](order-generator/); the examples read best in the order above, each one building on what the one before it set up.

Every example has a README that says what you will see, how it works, how to build it step by step, what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
