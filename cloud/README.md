# Cloud

<!-- group:start -->
A cloud service, run locally through LocalStack and switched to the real thing by properties.

| Example | What you will see | Needs |
|---|---|---|
| [AWS SQS](aws-sqs/) | Each of the three orders is put on an Amazon SQS queue called shipments and a courier route takes it off and logs the order, country and line count; locally the queue lives on the LocalStack that camel infra run aws sqs starts, and the same properties point at real AWS. | `camel infra run aws` |

Start with [AWS SQS](aws-sqs/).

Every example has a README that says what you will see, how it works, how to build it step by step, what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
