# Ticket classifier

A local model sorts the support tickets of the shop. It names the category of each ticket, shipping, billing or
account, and the route files the ticket in that folder. The route does not trust the answer: anything else, or no
answer in time, files the ticket under `unknown`.

## What you will see

```text
INFO ... ticket-classifier.camel.yaml:16 : Ticket T-1: My order ORD-1001 has not arrived yet. It is two weeks now, where is my parcel?
INFO ... ticket-classifier.camel.yaml:65 : Ticket T-1 is shipping
INFO ... ticket-classifier.camel.yaml:16 : Ticket T-2: I was charged twice for order ORD-1002, please refund one payment.
INFO ... ticket-classifier.camel.yaml:65 : Ticket T-2 is billing
INFO ... ticket-classifier.camel.yaml:16 : Ticket T-3: How do I change the email address and the password of my account?
INFO ... ticket-classifier.camel.yaml:65 : Ticket T-3 is account
```

and the tickets in `tickets-out/shipping/T-1.json`, `tickets-out/billing/T-2.json` and
`tickets-out/account/T-3.json`. A model can answer differently, so your categories may differ.

## Install Camel CLI

Install [JBang](https://www.jbang.dev/download/) and the Camel CLI as described in the
[root README](../../README.md#install-the-camel-cli); `camel --version` confirms the install.

## Run it

The example needs a local model. Either start Ollama in a container with the Camel CLI (Docker or Podman must be
running), which pulls the model `granite4:3b` after it starts:

```shell
camel infra run ollama
```

or use an Ollama installed on the machine, with `ollama pull granite4:3b` once. Both answer at
http://localhost:11434, as `application.properties` says. Then:

```shell
camel run *
```

Stop the example with `ctrl` + `c`, and the container with `camel infra stop ollama`.

## How it works

- `langchain4j-chat` creates the chat model from `provider: ollama`, with the URL and model name from
  `application.properties`; the CLI downloads `langchain4j-ollama` for the provider. Temperature 0 makes the
  answers as steady as the model allows.
- The route builds the prompt in the variable `prompt` and calls `langchain4j-chat` with `variableSend: prompt` and
  `variableReceive: answer`. The ticket stays the body.
- The answer is normalized to lower-case letters only, so "Shipping." becomes `shipping`.
- `circuitBreaker` puts a timeout of 60 seconds around the call. `onFallback` sets the category to `unknown`, so a
  slow or stopped model does not stop the tickets.
- The `filter` treats any category other than the three as `unknown`: a model can answer anything.
- `CamelFileName` with a folder, `${variable.category}/${body[ticketId]}.json`, makes the file producer write the
  ticket into the folder of its category.

## Build it step by step

Ask your assistant, or type it yourself, one step at a time, and run after each:

1. A file route on `tickets` that unmarshals each ticket and logs its id and text.
2. Ask the local model for the category of each ticket (shipping, billing or account) with `langchain4j-chat`,
   keep the answer in a variable, and log it.
3. File each ticket in `tickets-out/<category>/`, and under `unknown` when the answer is not one of the three.
4. Put the model call in a circuit breaker with a timeout, and file the ticket under `unknown` on fallback.

## Try changing

- Add a ticket that fits none of the categories, such as a question about the shop's opening hours.
- Stop Ollama while the example runs and drop in a new ticket: it is filed under `unknown` after the timeout.
- Try another model with `ollama.model` and compare the categories.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/ticket-classifier.citrus.it.yaml`, which the Camel CLI runs:

```shell
camel test run test/ticket-classifier.citrus.it.yaml
```

The test starts Ollama in a container on a side port, waits until the model is pulled, runs the route and checks
that the tickets are filed. It needs a local model, so CI skips it.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
