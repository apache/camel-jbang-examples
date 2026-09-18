# Fail well

<!-- group:start -->
Retries, a dead letter channel, and a circuit breaker in front of a flaky service.

| Example | What you will see | Needs |
|---|---|---|
| [Error handling](error-handling/) | The three orders go to a payment provider: the first is charged at once, the second gets no answer twice and is charged on the third attempt after two retries logged as warnings, and the third is declined, logged as such and parked as a file for manual review. | nothing |
| [Circuit breaker](circuit-breaker/) | A stock check calls the supplier every second; the supplier goes down for nine calls, the breaker opens after two failures in its window of four, answers from the fallback while open, tries the supplier again after five seconds and closes once a call succeeds; each line logs the breaker state. | nothing |

Start with [Error handling](error-handling/); the examples read best in the order above, each one building on what the one before it set up.

Every example has a README that says what you will see, how it works, how to build it step by step, what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
