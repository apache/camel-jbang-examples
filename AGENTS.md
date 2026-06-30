# Apache Camel JBang Examples - AI Agent Guidelines

Guidelines for AI agents contributing examples to **apache/camel-jbang-examples**.

This repository hosts low-code Apache Camel integrations that run from the
terminal with the [Camel CLI](https://camel.apache.org/manual/camel-jbang.html)
and [JBang](https://www.jbang.dev/) — no Maven/Gradle build and no Java
compilation step required.

These guidelines complement the canonical, org-wide rules in the main
[apache/camel `AGENTS.md`](https://github.com/apache/camel/blob/main/AGENTS.md).
Read that file for the full *Rules of Engagement*; the section below repeats the
essentials and adds what is specific to this examples repository.

## Project Info

- Run with: Camel CLI (`jbang app install camel@apache/camel`) + JBang
- Java: 17+ (CI uses Temurin 17)
- Tests: [Citrus](https://citrusframework.org/) YAML tests
- JIRA project: `CAMEL` (https://issues.apache.org/jira/projects/CAMEL)
- Merge strategy (`.asf.yaml`): squash or rebase; protected `main`

## Rules of Engagement (essentials)

- **Attribution**: every AI-generated PR description, review or JIRA comment MUST
  identify itself as AI-generated and name the human operator, e.g.
  `_Claude Code on behalf of [Human Name]_`.
- **JIRA ownership**: only pick **Unassigned** tickets. Before starting, assign
  the ticket to your operator and transition it to *In Progress*. Set
  `fixVersions` before closing.
- **One example per PR**, kept small and self-contained. Do not exceed 10 PRs per
  day per operator — reviewers must keep up. Quality over quantity.
- **Branch from your own fork** (not apache/), with a descriptive name containing
  the topic and JIRA id (e.g. `CAMEL-12345-mqtt-example`). Delete the branch
  after merge/close. Never push to a branch you did not create.
- **Green CI is required**: the example must build and its Citrus tests must pass.
- **Never merge** without at least one human approval; never approve your own PR.

## Repository structure

- One example per top-level directory, lowercase and hyphenated
  (e.g. `mqtt/`, `timer-log/`, `ftp/`). Related examples may be grouped under a
  category directory (e.g. `aws/aws-sqs/`, `openapi/server/`).
- Each example carries a `metadata.json` that feeds the generated
  `camel-jbang-example-catalog.json`. Do not hand-edit the catalog.

## Anatomy of an example

| File | Role |
| --- | --- |
| `README.md` | What it does, how to run, expected output, how to test |
| `<name>.camel.yaml` | The route(s) in Camel YAML DSL |
| `application.properties` | Runtime properties (ASF license header required) |
| `metadata.json` | Catalog entry: `name`, `title`, `description`, `tags`, `level` (`beginner`/`intermediate`/`advanced`), `infraServices`, `hasCitrusTests` |
| `compose.yaml` | Optional Docker Compose for required infra |
| `beans.yaml` / `*.java` | Optional beans/processors (package `camel.example.*`) |
| `test/<name>.citrus.it.yaml` | Optional Citrus integration test |

## Build, run and validate

```shell
# install tooling once
jbang app install camel@apache/camel
jbang app install citrus@citrusframework/citrus

# start infra if the example needs it
camel infra run <service>        # or: docker compose up --detach

# run the example
camel run *                      # loads every YAML in the directory
# or be explicit:
camel run <name>.camel.yaml application.properties

# run its test
citrus run test/<name>.citrus.it.yaml
```

The CI workflow (`.github/workflows/build.yml`) installs the Camel CLI and Citrus
and runs `jbang citrus@citrusframework/citrus run <example>/test` for each tested
example. If your example ships a `test/`, add it to that workflow.

## Conventions

- **Naming**: directory `kebab-case`; route file `<name>.camel.yaml`; test file
  `<name>.citrus.it.yaml`; Java package `camel.example.*`.
- **License headers**: required on `application.properties` and `*.java`
  (ASF header). YAML route files do not carry a header.
- **README**: follow the existing examples — title, description, install CLI,
  start infra, how to run, stop/cleanup, integration testing, community footer.

## Adding a new example (checklist)

1. Create `<name>/` (or `<category>/<name>/`).
2. Add `README.md`, `<name>.camel.yaml`, `application.properties` (with header),
   and a correct `metadata.json`.
3. Add `compose.yaml` if infra is required; add `test/` Citrus tests where it
   makes sense and wire them into `.github/workflows/build.yml`.
4. Run it locally with `camel run` and verify the README's expected output.
5. Open the PR from your fork, link the JIRA ticket, and request review from
   active committers.

## Links

- Camel CLI manual: https://camel.apache.org/manual/camel-jbang.html
- JBang: https://www.jbang.dev/
- Citrus: https://citrusframework.org/
- Canonical agent rules: https://github.com/apache/camel/blob/main/AGENTS.md
