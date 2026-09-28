# Document Analysis with Docling and LangChain4j RAG

Documents dropped in a directory are converted to Markdown by a Docling service, analysed by a local Ollama
model through `langchain4j-chat`, and written as a report to an output directory; an HTTP endpoint answers
questions against the latest document. Both services are started with `camel infra`.

## What you will see

```text
$ cp sample.md documents/

INFO ... docling-langchain4j-rag.yaml:27  : Processing document: sample.md
INFO ... docling-langchain4j-rag.yaml:38  : Converting document to Markdown with Docling...
INFO ... docling-langchain4j-rag.yaml:47  : Document converted to Markdown successfully
INFO ... docling-langchain4j-rag.yaml:77  : Analyzing document with AI model...
INFO ... docling-langchain4j-rag.yaml:89  : AI analysis completed
INFO ... docling-langchain4j-rag.yaml:120 : Analysis report saved: sample.md_analysis.md
INFO ... docling-langchain4j-rag.yaml:137 : Processing complete for: sample.md
```

and `output/sample.md_analysis.md` holds the report: the file name and date, the model's summary, key topics
and findings, then the full document as Markdown. The wording of the analysis differs from run to run; the
first one also takes a while, because the model is loaded.

```text
$ curl -X POST localhost:8080/api/ask -H "Content-Type: text/plain" -d "What DSLs does Camel support?"
The document lists four DSLs: Java, XML, YAML and Groovy.
```

## Install Camel CLI

Install [JBang](https://www.jbang.dev/download/) and the Camel CLI as described in the
[root README](../../README.md#install-the-camel-cli); `camel --version` confirms the install.

## Run it

The example needs a running Docling and a running Ollama, which the Camel CLI starts for you in containers
(Docker or Podman must be running). In one terminal:

```shell
camel infra run docling ollama
```

Docling serves on http://localhost:5001 and Ollama on http://localhost:11434, where the container pulls the
`granite4:3b` model on first start, a download of a couple of gigabytes; both match `application.properties`.
In another terminal:

```shell
camel run *
```

Then drop a document in the `documents` directory, the sample or one of your own (PDF, Word, PowerPoint,
HTML or Markdown), and watch the log; the report lands in `output` and the source file is deleted once it is
processed. Ask about the latest document with the `curl` above.

Stop the example with `ctrl` + `c` and the services with `camel infra stop docling ollama`.

## How it works

- `docling-langchain4j-rag.yaml` starts with the bean `chatModel`, an `OllamaChatModel` built through its
  LangChain4j builder from the URL and model name in `application.properties`; the `langchain4j-chat`
  component picks it up as the one chat model in the registry.
- `document-analysis-workflow` is the main route: a `file` consumer on `documents` with `include` for the
  supported extensions. The body becomes the file's absolute path, the `docling` endpoint with
  `CONVERT_TO_MARKDOWN` sends it to the Docling service and returns the Markdown, which is kept in an
  exchange property. A `setBody` builds the prompt around it, `langchain4j-chat` sends it to the model, a
  Groovy `script` assembles the report from the answer and the Markdown, and a `file` producer writes it to
  `output` under the source name plus `_analysis.md`. A last script deletes the source file.
- `document-qa-api` is `platform-http` on `POST /api/ask`: a script finds the newest file in `documents`,
  Docling converts it, and the question and the Markdown go to the model in one prompt. That is retrieval
  augmented generation in its simplest form, the whole document as context; with no document the route
  answers an error text.
- `batch-summarization` is a `timer` route, first after `batch.delay` and then every `batch.period`, that
  converts and summarises every file in `documents` in a `split`, and logs each summary.
- `health-check` on `GET /api/health` answers the configuration as JSON, and `extract-structured-data` on
  `POST /api/extract` takes a document in the request body, asks Docling for its structured data with
  `EXTRACT_STRUCTURED_DATA` and asks the model to describe the tables and fields in it.
- `application.properties` holds the directories, the two service URLs, the model name, the batch timing and
  the HTTP port.

## Build it step by step

Ask your assistant, or type it yourself, one step at a time, and run after each, with the two services running:

1. A route from `file:documents` that logs the file name.
2. Set the body to the file's absolute path and send it to `docling` with `CONVERT_TO_MARKDOWN` against the
   Docling URL; log the Markdown.
3. The `chatModel` bean from properties, a prompt around the Markdown, and a `langchain4j-chat` step; log the
   answer.
4. Write the answer and the Markdown to `output` as `<name>_analysis.md` with a `file` producer.
5. A `platform-http` route on `/api/ask` that converts the newest document and asks the model the question in
   the request body.

## Try changing

- `ollama.model.name=llama3.2` after `docker exec -it ollama ollama pull llama3.2`, or any other model Ollama
  serves, and compare the analyses.
- Change the prompt in `document-analysis-workflow` to ask for the summary in your language, or as five
  bullet points.
- `batch.period=60000` and drop three documents in `documents` to see the batch route summarise them
  together every minute; the analysis route deletes them after its own run, so be quick.
- For real retrieval, cut the Markdown into chunks with `langchain4j-tokenizer`, embed them with
  `langchain4j-embeddings` into a vector store, and put only the chunks nearest the question in the prompt.

## Integration testing

The example has no Citrus test: it needs the Docling service and a language model, which take minutes to
pull and load on a first run. Verify it with the steps under *Run it*.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
