# AWS SQS

Shipments are handed to the courier through an Amazon SQS queue: the shop puts each order on the queue, the
courier's system takes it off. Nothing here needs an AWS account: the Camel CLI starts LocalStack, an AWS
look-alike, in a container, and the same two routes run against the real service with other properties.

## What you will see

```text
INFO ... aws-sqs.camel.yaml:22 : Order ORD-1001 handed over on the shipments queue
INFO ... aws-sqs.camel.yaml:22 : Order ORD-1002 handed over on the shipments queue
INFO ... aws-sqs.camel.yaml:22 : Order ORD-1003 handed over on the shipments queue
INFO ... aws-sqs.camel.yaml:35 : Courier picked up ORD-1001 for DK: 2 line(s)
INFO ... aws-sqs.camel.yaml:35 : Courier picked up ORD-1002 for DE: 1 line(s)
INFO ... aws-sqs.camel.yaml:35 : Courier picked up ORD-1003 for US: 3 line(s)
```

## Install Camel CLI

<!-- see installation instructions in ../../install.adoc -->

## Run it

The example needs a running SQS, which the Camel CLI starts for you as LocalStack in a container (Docker or
Podman must be running). In one terminal:

```shell
camel infra run aws sqs
```

It prints the endpoint, region and keys as JSON; they match `application.properties`. In another terminal:

```shell
camel run *
```

The three orders in `orders/` are read once each (`noop: true` leaves the files in place), so the run can be
repeated. Stop the example with `ctrl` + `c` and LocalStack with `camel infra stop aws`.

### Against real AWS

Create the queue, or leave `auto-create-queue` on, and replace the LocalStack lines in `application.properties`:

```properties
camel.component.aws2-sqs.access-key=<your access key>
camel.component.aws2-sqs.secret-key=<your secret key>
camel.component.aws2-sqs.region=eu-west-1
camel.component.aws2-sqs.override-endpoint=false
```

The routes do not change. A profile, `application-aws.properties` with `camel run * --profile=aws`, keeps
both configurations side by side, as the `properties-and-profiles` example shows.

## How it works

- The `aws2-sqs` component is configured once, at component level, with `camel.component.aws2-sqs.*` in
  `application.properties`: keys, region, and for LocalStack `override-endpoint` with the local URL. Both
  endpoints then only name the queue, `aws2-sqs:shipments`.
- `hand-over` reads each order file and sends its text as the message body; the order id goes in a header
  for the log. `auto-create-queue` creates `shipments` on first use.
- `courier` polls the queue, deletes each message after the route has handled it, parses the JSON and logs it.
  In real life the courier's system would be the consumer, and the shop only the producer.

## Build it step by step

1. A `file` route on `orders` sending to `aws2-sqs:shipments`, with the component properties; start LocalStack
   and see the three messages go.
2. Add the consumer route with a log of `${body}`.
3. Parse the JSON and log the country and line count.
4. Switch the properties to a real account and run again.

## Try changing

- Stop the example, run it again: nothing new arrives, the queue was emptied. Then set `deleteAfterRead: false`
  on the consumer and see the same orders come back after the visibility timeout.
- Add `delaySeconds: 10` on the producer endpoint and watch the courier wait.
- Send an order from the CLI: `camel cmd send --endpoint=aws2-sqs:shipments --body=@orders/order-1001.json`.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/aws-sqs.citrus.it.yaml`, which the Camel CLI runs. The test starts LocalStack itself with the same
`camel infra` mechanism, so nothing must be running beforehand:

```shell
camel test run test/aws-sqs.citrus.it.yaml
```

The test starts SQS, runs the routes and verifies that the courier picked up all three orders.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
