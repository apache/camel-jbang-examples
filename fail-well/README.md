# Fail well

<!-- group:start -->
Retries, a dead letter channel, and a circuit breaker in front of a flaky service, then chaos rules that break the routes on purpose to prove it.

| Example | What you will see | Needs |
|---|---|---|
| [Error handling](error-handling/) | The three orders go to a payment provider: the first is charged at once, the second gets no answer twice and is charged on the third attempt after two retries logged as warnings, and the third is declined, logged as such and parked as a file for manual review. | nothing |
| [Circuit breaker](circuit-breaker/) | A stock check calls the supplier every second; the supplier goes down for nine calls, the breaker opens after two failures in its window of four, answers from the fallback without calling the supplier while open, tries it again after five seconds and closes once a call succeeds; each line logs the breaker state and whether the supplier failed or was not called. | nothing |
| [Chaos](chaos/) | The shop charges an order every second at a payment service over HTTP and hands it to shipping; chaos rules added while it runs make the payment service answer 503, go down for 10 seconds and fail shipping, the retries recover most orders and the dead letter channel parks the rest, and a scenario file replays a bad half minute with a seed and ends with the verdict PASS as its exit code; a refunds route from Kafka (stubbed) has a gap on purpose, for an AI to find with camel cmd chaos-explore. | Camel 4.24 or newer |

Start with [Error handling](error-handling/); the examples read best in the order above, each one building on what the one before it set up.

Every example has a README that says what you will see, how it works, how to build it step by step and what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
