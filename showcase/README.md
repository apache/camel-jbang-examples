# Showcase

<!-- group:start -->
Tooling demos outside the ladder: the TUI, a memory leak, message sizes, log analysis.

| Example | What you will see | Needs |
|---|---|---|
| [TUI Hello World](tui-hello-world/) | A one-shot timer prints an invitation; the route direct:greet then logs and greets any message sent to it from the CLI (camel cmd send --endpoint=direct:greet --body=...) or from a tool that can send messages. | nothing |
| [Memory Leak](memory-leak/) | Three timer routes run side by side: two leak memory into a cache and a buffer, one is healthy, so a JFR Old Object Sample recording and the CLI's heap tools show which route leaks. | nothing |
| [Message Size](message-size/) | Timer routes send messages of small, medium and large sizes to seda queues with a Content-Length header, so camel cmd and the CLI's message-size views show sizes per endpoint. | nothing |
| [Smart Log Analyzer](smart-log-analyzer/) | A multi-part showcase: a load generator produces logs and traces, a correlator maps OpenTelemetry logs to traces, an LLM analyses the correlated records, and a small web console with a REST API shows the results. | nothing |

Start with [TUI Hello World](tui-hello-world/); the others stand on their own, in any order.

Every example has a README that says what you will see, how it works, how to build it step by step, what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
