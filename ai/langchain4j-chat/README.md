# LangChain4j chat

A local model writes the shipping notification for each order. The chat model is a bean built from
`application.properties`, the route turns the order into a prompt, and the reply comes back as the body with the
token counts in headers.

## What you will see

```text
INFO ... langchain4j-chat.camel.yaml:45      : Notification for ORD-1002 (107 in, 35 out): Dear Customer C-207,
Your order ORD-1002 containing 3 CAMEL-MUGs has been shipped today. We hope you enjoy your new items!
```

The wording is the model's; `granite4:3b` writes plainly, a larger model writes better.

## Install Camel CLI

<!-- see installation instructions in ../../install.adoc -->

## Run it

The example needs a running Ollama with a model, which the Camel CLI starts for you in a container (Docker or
Podman must be running); the container pulls the `granite4:3b` model on first start, which takes a while. In one
terminal:

```shell
camel infra run ollama
```

In another terminal:

```shell
camel run *
```

An Ollama installed on the machine works too: set `ollama.model` in `application.properties` to a model you have
pulled, or override it for one run with `OLLAMA_MODEL=llama3.2 camel run *`. A 3B model on a CPU takes tens of
seconds per reply; a larger model or a GPU is faster. Stop the container with `camel infra stop ollama`.

## How it works

- The `beans` block builds the chat model: LangChain4j models come from builders, so the bean names the
  `builderClass`, the `builderMethod` and the builder's properties, with the URL and model name read from
  `application.properties`. The CLI downloads `langchain4j-ollama` from the class name.
- `langchain4j-chat` with `chatModel: "#chatModel"` sends the body as a single user message and replaces the
  body with the reply; `CamelLangChain4jChatInputTokenCount` and `...OutputTokenCount` say what it cost.
- The prompt is built with the Simple language from the order fields; `${body[lines]}` prints the list of lines.
- The order id is kept in an exchange property because the reply replaces the body.

## Build it step by step

1. A timer route that sends a fixed question to `langchain4j-chat` and logs the reply; start Ollama and see
   the first answer arrive.
2. Read the orders and build the prompt from the order; log the token headers.
3. Lower `temperature` and compare the replies across runs.

## Try changing

- Run with `camel run * --observe` and open the Spans tab in `camel tui`: every call to the model is a span with
  `gen_ai.operation.name`, the model and the token usage.
- Switch to `CHAT_SINGLE_MESSAGE_WITH_PROMPT` with a `CamelLangChain4jChatPromptTemplate` header and pass the
  order fields as variables instead of building the prompt yourself.
- Point `ollama.base.url` at an OpenAI-compatible server by swapping the bean for `OpenAiChatModel` from
  `langchain4j-open-ai`.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/langchain4j-chat.citrus.it.yaml`, which the Camel CLI runs:

```shell
camel test run test/langchain4j-chat.citrus.it.yaml
```

The test starts Ollama on a side port, runs the route and verifies that a notification is logged for the
first order. It pulls a 2.5 GB model and runs it on the CPU, so it is a local check and not part of the CI build.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
