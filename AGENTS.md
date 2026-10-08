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
- Java: 17+ (CI uses Temurin 21)
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

The examples form a ladder: one directory per group, one directory per example
inside it, both lowercase and hyphenated (e.g. `route/aggregator/`,
`connect-service/mqtt/`). The groups, in reading order, are `quick-start`, then
the rungs `run`, `transform`, `route`, `fail-well`, `connect`, `connect-service`,
`contracts`, `ai`, `cloud`, and `showcase` for tooling demos outside the ladder.
The `README.md` at the root explains the ladder; `generate-catalog.sh` holds the
group order and intros.

- From the `run` rung onwards the examples share one fictional web shop and the
  order shape that `run/order-generator` defines; a new example on the ladder
  reuses that story and that JSON rather than inventing its own domain.
- Each example carries a `metadata.json` that feeds the generated
  `camel-jbang-example-catalog.json` and the example tables in the root and group
  READMEs. Do not hand-edit the catalog or those tables; run
  `./generate-catalog.sh` after adding or changing a `metadata.json`.
- `security/`, `transformation/`, the non-ladder examples in `cloud/` and
  `showcase/smart-log-analyzer` (several apps, run one by one as its README says)
  are larger reference examples marked `"exclude": true`; they are not on the ladder.

## Anatomy of an example

| File | Role |
| --- | --- |
| `README.md` | What it does, how to run, expected output, how to test |
| `<name>.camel.yaml` | The route(s) in Camel YAML DSL |
| `application.properties` | Runtime properties (ASF license header required) |
| `metadata.json` | Catalog entry: `title`, `description` (the behaviour you observe when it runs), `level` (the group), `order` (its place in the group, the reading order the group page and the listings use), `teaches` (the `components`, `eips`, `languages` and `dataformats` it introduces), `tags`, `infraServices` (what `camel infra run` must start), `needs` (anything else the *Needs* column should say, e.g. `a local model`), `ciSkip` (the test cannot run in CI) |
| `compose.yaml` | Optional Docker Compose for required infra |
| `beans.yaml` / `*.java` | Optional beans/processors (package `camel.example.*`) |
| `test/<name>.citrus.it.yaml` | The Citrus integration test, run by CI |

## Build, run and validate

```shell
# install tooling once
jbang app install camel@apache/camel

# start infra if the example needs it
camel infra run <service>        # or: docker compose up --detach

# run the example
camel run *                      # loads every YAML in the directory
# or be explicit:
camel run <name>.camel.yaml application.properties

# run its test
camel test run test/<name>.citrus.it.yaml
```

The CI workflow (`.github/workflows/build.yml`) installs the Camel CLI and its test
plugin and runs `camel test run <example>/test` for each tested
example. If your example ships a `test/`, add it to that workflow.

## Conventions

- **Naming**: directory `kebab-case`; route file `<name>.camel.yaml`; test file
  `<name>.citrus.it.yaml`; Java package `camel.example.*`.
- **License headers**: required on `application.properties` and `*.java`
  (ASF header). YAML route files do not carry a header.
- **YAML format**: write routes in the canonical YAML DSL format — an expression
  under `expression:` and a step as a map of its options
  (`setBody: {expression: {simple: {expression: "..."}}}`, `log: {message: "..."}`,
  `to: {uri: "..."}`). The compact notation (`setBody: {simple: "..."}`,
  `log: "..."`, `- simple:` in a `when` item) is deprecated and `camel run` warns
  about it. Check with `camel validate yaml --canonical <file>` (Camel 4.23+);
  `camel validate normalize` rewrites a file but drops its comments.
- **README**: follow the existing examples, `run/order-generator/README.md` is
  the reference. Title and a two-line description, then these sections in this
  order: *What you will see* (the literal log output), *Install Camel CLI* (the
  one-line link to the root README), *Run it* (including how to start the
  service, if any, and how to stop), *How it works* (one bullet per file),
  *Build it step by step* (numbered prompts a reader or an assistant can follow,
  running after each), *Try changing*, *Integration testing*, and the
  *Help and contributions* footer.

## Adding a new example (checklist)

1. Pick the group (rung) it belongs to and create `<group>/<name>/`.
2. Add `README.md`, `<name>.camel.yaml`, `application.properties` (with header),
   and a `metadata.json` with `level`, `order` and `teaches`.
3. Add `test/<name>.citrus.it.yaml` and wire it into
   `.github/workflows/build.yml`; the test starts the route, and the service if
   it needs one, itself. Set `ciSkip` only when the test truly cannot run in CI.
4. Run it locally with `camel run` and verify the README's expected output;
   `camel validate yaml --canonical` must report nothing.
5. Run `./generate-catalog.sh` to refresh the catalog and the README tables.
6. Open the PR from your fork, link the JIRA ticket, and request review from
   active committers.

## Links

- Camel CLI manual: https://camel.apache.org/manual/camel-jbang.html
- JBang: https://www.jbang.dev/
- Citrus: https://citrusframework.org/
- Canonical agent rules: https://github.com/apache/camel/blob/main/AGENTS.md
