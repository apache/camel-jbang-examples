# OpenAI PII Redaction

Text typed on standard input is sent to an OpenAI-compatible model with a JSON schema that asks for the
personal identifiers redacted, and the redacted text is printed on standard output. Works with OpenAI itself
or with any server that speaks its chat API, such as a local Ollama or llama.cpp.

## What you will see

```text
$ echo 'Customer John Doe (email: john.doe@example.com) requested a refund for order #998877.' | camel run *
...
{
  "detectedPII": [
    {"span": "John Doe", "type": "PERSON", "action": "REDACTED"},
    {"span": "john.doe@example.com", "type": "EMAIL", "action": "REDACTED"}
  ],
  "sanitizedText": "Customer [REDACTED] ([REDACTED]) requested a refund for order #998877."
}
```

The order number stays: it is not a personal identifier. The exact wording differs from model to model.

## Install Camel CLI

Install [JBang](https://www.jbang.dev/download/) and the Camel CLI as described in the
[root README](../../README.md#install-the-camel-cli); `camel --version` confirms the install.

## Run it

The example needs an OpenAI-compatible chat API. Point it at one with three environment variables, which
`application.properties` reads:

```shell
export OPENAI_API_KEY=<your-api-key>
export OPENAI_BASE_URL=https://api.openai.com/v1
export OPENAI_MODEL=gpt-4o-mini
```

For a local server the key is whatever the server expects, often any non-empty string, and the URL is its
`/v1` endpoint, for example `http://localhost:11434/v1` for Ollama with `OPENAI_MODEL` set to a model you have
pulled. Then pipe the text in:

```shell
echo 'Customer John Doe (email: john.doe@example.com) requested a refund for order #998877.' | camel run *
```

The example stops by itself after the one message, because of `camel.main.durationMaxMessages=1`.

## How it works

- `pii-redaction.camel.yaml` holds two routes. The second is the plumbing: `from` the `stream` component's
  standard input, `to` the `direct` route that does the work, `to` standard output.
- The `direct` route is one `to` on the `openai` component with `operation: chat-completion`. The
  `systemMessage` tells the model what to redact and what to leave alone, `temperature: 0.15` keeps it
  predictable, and `jsonSchema` points at `pii.schema.json`, so the model must answer in that shape and the
  body that comes back is the JSON you see.
- `pii.schema.json` is the contract with the model: a list of `detectedPII` with the span, its type from a fixed
  list, and the action, plus the `sanitizedText`.
- `application.properties` sets the component's key, base URL and model from environment variables, adds the
  `camel-openai` dependency, and limits the run to one message.

## Build it step by step

Ask your assistant, or type it yourself, one step at a time, and run after each, with the environment
variables set:

1. A route from `stream:in` to `stream:out` that echoes what you pipe in; run it with `echo hello | camel run *`
   and `camel.main.durationMaxMessages=1`.
2. Put a `to: openai` with `operation: chat-completion` between them, with the key, URL and model in
   `application.properties`; the model answers in free text.
3. Add the `systemMessage` with the redaction rules.
4. Write `pii.schema.json` and hand it to the endpoint with `jsonSchema`; the answer is now JSON in that shape.
5. Move the work to a `direct` route so another route could call it.

## Try changing

- Add `"IBAN"` to the `type` enum in the schema and pipe in a bank account.
- Change the system message to mask instead of redact, `J*** D**`, and see the `action` become `MASKED`.
- Replace the `stream:in` route with a `file` consumer that redacts every text file dropped in a directory.

## Integration testing

The example has no Citrus test, because it needs a language model behind an API key; the `camel run` above
is the test.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
