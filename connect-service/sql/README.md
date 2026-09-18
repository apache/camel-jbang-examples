# SQL database

The shop's customers in a Postgres table: one row per customer, with the number of orders they placed.
The three orders register their customers; a report lists the table.

## What you will see

```text
INFO ... sql.camel.yaml:16 : Table customers is ready
INFO ... sql.camel.yaml:38 : Customer C-482 from DK registered with order ORD-1001
INFO ... sql.camel.yaml:38 : Customer C-207 from DE registered with order ORD-1002
INFO ... sql.camel.yaml:38 : Customer C-134 from US registered with order ORD-1003
INFO ... sql.camel.yaml:54 : 3 customer(s) in the table
INFO ... sql.camel.yaml:61 :   C-134 (US): 1 order(s)
INFO ... sql.camel.yaml:61 :   C-207 (DE): 1 order(s)
INFO ... sql.camel.yaml:61 :   C-482 (DK): 1 order(s)
```

## Install Camel CLI

<!-- see installation instructions in ../../install.adoc -->

## Run it

The example needs a running postgres, which the Camel CLI starts for you in a container
(Docker or Podman must be running). In one terminal:

```shell
camel infra run postgres
```

It prints the connection details as JSON; they match `application.properties`. In another terminal:

```shell
camel run *
```

Run it a second time while the database is still up: the customers are already there, so the insert's
`ON CONFLICT` branch counts a second order for each.

Stop the example with `ctrl` + `c` and the service with `camel infra stop postgres`.

## How it works

- `application.properties` declares the datasource with the `spring.datasource.*` keys the CLI understands:
  URL, user and password as `camel infra run postgres` prints them, plus the driver class, from which the CLI
  works out the JDBC driver to download.
- The `sql` component runs the query in the endpoint URI. The first route creates the table once.
- The insert uses named parameters, `:#${body[customer]}`: the value comes from the message, so there is no
  string concatenation and no SQL injection. `noop: true` keeps the order as the body instead of the update count.
- A select returns a list of maps, one per row; the report logs the size and splits it to log each row.

## Build it step by step

1. A timer route with `sql:CREATE TABLE ...` and a log; run it, then `camel infra run postgres` in the other
   terminal and watch the retry succeed.
2. Add the file route on `orders` with the insert; run twice and see the conflict error, then add `ON CONFLICT`.
3. Add the report timer with the select and log `${body}` to see the list of maps, then split it.

## Try changing

- Add a `WHERE country = :#${header.country}` select behind a `direct` route and call it from `camel cmd send`.
- Switch to `camel infra run mysql` and adapt the URL, driver and the `ON CONFLICT` clause.
- Replace `noop: true` by a log of `${header.CamelSqlUpdateCount}` after the insert.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/sql.citrus.it.yaml`, which the Camel CLI runs. The test starts the service itself
with the same `camel infra` mechanism, so nothing must be running beforehand:

```shell
camel test run test/sql.citrus.it.yaml
```

The test starts Postgres, runs the routes and verifies the registered customers and the report.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
