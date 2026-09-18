# MCP server

Two routes exposed as MCP tools, so an AI agent can ask the shop about stock and orders. There is no server route:
`application.properties` switches the MCP server on and picks the tools by tag, and every `ai-tool` route with
that tag becomes a tool any MCP client can discover and call, a coding agent included.

## What you will see

```text
$ camel run *
...
INFO ... VertxMcpServerEngine : MCP server 'webshop' serving tools on path /mcp
INFO ... Started stock-level (ai-tool://stock_level)
INFO ... Started order-status (ai-tool://order_status)

when a client calls the tools:

INFO ... mcp-server.camel.yaml:38 : Tool stock_level(CAMEL-MUG): 42 CAMEL-MUG in stock
INFO ... mcp-server.camel.yaml:81 : Tool order_status(ORD-1003): Order ORD-1003 for customer C-134 in US is pending with 3 line(s)
```

## Install Camel CLI

<!-- see installation instructions in ../../install.adoc -->

## Run it

```shell
camel run *
```

The MCP endpoint is http://localhost:8080/mcp over streamable HTTP. Point an MCP client at it; for Claude Code,
Cursor or another agent that reads an `mcp.json`:

```json
{
  "mcpServers": {
    "webshop": {"type": "http", "url": "http://localhost:8080/mcp"}
  }
}
```

Then ask the agent how many mugs are in stock, or what the status of order ORD-1003 is, and watch the log.
Without an agent, `curl` speaks the protocol too: an `initialize` request returns an `Mcp-Session-Id` header,
and the following requests carry it:

```shell
curl -s -i -X POST localhost:8080/mcp -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'

curl -s -X POST localhost:8080/mcp -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H 'Mcp-Session-Id: <the id>' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"stock_level","arguments":{"sku":"CAMEL-MUG"}}}'
```

The MCP server is a preview feature since Camel 4.22.

## How it works

- `ai-tool:stock_level` is a consumer endpoint that registers the route as a tool: the name the model sees, a
  `description` it reads to decide when to call it, `parameter.sku` with its type, description and `required`,
  and `readOnlyHint` as an advisory hint. When a client calls the tool, the arguments arrive as headers and the
  route's final body is the tool result.
- `tags: shop` groups the tools; `camel.server.mcp-tags=shop` in `application.properties` exposes that group.
  `camel.server.mcp-enabled=true` starts the MCP server on the CLI's HTTP server and `camel.server.mcp-server-name`
  is what the client shows; Camel 4.23 adds a title, description and instructions next to it.
- `order_status` reads the order file with `pollEnrich` and a file name built from the id, `order-1001.json`
  for `ORD-1001`, and answers a sentence; a missing file leaves the body null, which becomes the unknown answer.
- Nothing here is specific to MCP: the same `ai-tool` routes are the tools of a Camel agent built with
  `langchain4j-agent` or `openai`, selected by the same tags.

## Build it step by step

1. One `ai-tool` route that answers a fixed text, with the four `camel.server.mcp-*` properties; run it and see
   the server line in the log, then `initialize` and `tools/list` with `curl`.
2. Add a parameter and use `${header.sku}` in the answer; call it with `tools/call`.
3. Answer from `stock.json` with `jsonpath` and add the unknown case.
4. Add the second tool and connect a real agent.

## Try changing

- Add an `ai-resource` route that serves `stock.json` as an MCP resource and read it from the client.
- Add `camel.server.mcp-transport=stdio` and run with `camel run * --mcp-stdio` so an IDE launches the
  example as a subprocess.
- Give a tool `returnDirect: true` and see the difference when a Camel agent calls it.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/mcp-server.citrus.it.yaml`, which the Camel CLI runs:

```shell
camel test run test/mcp-server.citrus.it.yaml
```

The test starts the example, opens an MCP session over HTTP and calls both tools, checking the answers.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
