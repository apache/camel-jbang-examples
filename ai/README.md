# AI

<!-- group:start -->
A local model writing text, routes exposed as MCP tools, RAG over documents, PII redaction.

| Example | What you will see | Needs |
|---|---|---|
| [LangChain4j chat](langchain4j-chat/) | A local Ollama model started with camel infra writes the shipping notification for each of the three orders; the chat model is a bean built from properties, the prompt comes from the order, and the log shows the reply with its token counts. | `camel infra run ollama`, a local model: `ollama pull granite4:3b` |
| [MCP server](mcp-server/) | Two routes are exposed as MCP tools, stock_level by SKU and order_status by order id, on http://localhost:8080/mcp with nothing but properties to switch the server on; any MCP client, a coding agent included, can list and call them, and the log shows each call. | nothing |
| [OpenAI PII Redaction](openai-pii-redaction/) | Text typed on standard input is sent to an OpenAI-compatible model with a JSON schema that asks for the personal identifiers redacted, and the redacted text is printed on standard output. | an OpenAI-compatible API: set `OPENAI_API_KEY` |
| [Document Analysis with Docling and LangChain4j RAG](docling-langchain4j-rag/) | Documents dropped in a directory are converted to Markdown by a Docling service, analysed by a local Ollama model through langchain4j-chat, and written as a report to an output directory; an HTTP endpoint answers questions against the latest document. | `camel infra run docling ollama`, a local model |

Start with [LangChain4j chat](langchain4j-chat/); the examples read best in the order above, each one building on what the one before it set up.

Every example has a README that says what you will see, how it works, how to build it step by step and what to try changing; the ones with a `test/` directory also say how to run their test with `camel test run`.
<!-- group:end -->
