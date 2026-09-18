# Properties and profiles

One route, two configurations. `application.properties` is what `camel run` uses; `application-prod.properties`
holds the values that differ in production and is chosen with `--profile=prod`.

## What you will see

```text
camel run *
INFO ... properties-and-profiles.camel.yaml:15 : Welcome to Camel Shop (development), prices in EUR

camel run * --profile=prod
INFO ... properties-and-profiles.camel.yaml:15 : Welcome to Camel Shop, prices in USD
```

## Install Camel CLI

<!-- see installation instructions in ../../install.adoc -->

## Run it

```shell
camel run *
```

and then the production profile:

```shell
camel run * --profile=prod
```

## How it works

- `{{shop.name}}` and `{{shop.currency}}` in the route are property placeholders; Camel resolves them
  from `application.properties` at startup.
- With `--profile=prod` Camel also reads `application-prod.properties`, and a value there wins over the
  same key in `application.properties`. Only the differing values need to be in the profile file.
- `welcome.period` is only in `application.properties`, so both profiles share it.

## Build it step by step

1. A timer route that logs "Welcome to Camel Shop".
2. Move the shop name to `application.properties` as `shop.name` and use `{{shop.name}}` in the message.
3. Add `shop.currency` the same way and mention it in the message.
4. Create `application-prod.properties` with a different name and currency, run with `--profile=prod`,
   and see the message change.
5. Move the timer period to a property that only `application.properties` has.

## Try changing

- Override a single value from the command line: `camel run * --prop=shop.currency=DKK`.
- Add an `application-test.properties` and run `--profile=test`.

## Integration testing

The example provides an automated integration test (`properties-and-profiles.citrus.it.yaml`) for the
[Citrus](https://citrusframework.org/) test framework (see
[Citrus installation guide](../../install-citrus.adoc)).

```shell
citrus run test/properties-and-profiles.citrus.it.yaml
```

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
