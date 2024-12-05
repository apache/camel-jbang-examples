# Apache Camel JBang Examples

[Apache Camel](http://camel.apache.org/) is a powerful open source integration framework based on known
Enterprise Integration Patterns with powerful bean integration.

## Introduction

This project provides examples for low-code integrations with Apache Camel JBang.

### Examples

This git repository hosts a set of ready-to-use examples you can try to learn more about Apache Camel,
and how Camel can be used to integrate systems. These examples are accessible for non developers, as
they can run without having to use traditional Java compilation or build systems such as Maven or Gradle.

All examples can run local on your computer from a CLI terminal by executing a few commands.

These examples uses JBang as the CLI which is a great tool that makes using Java much easier.

#### Installing JBang

First install JBang according to https://www.jbang.dev

When JBang is installed then you should be able to run from a shell:

```shell
jbang --version
```

This will output the version of JBang.

#### Installing Camel JBang

To run this example you can install Camel on JBang via:

```shell
jbang app install camel@apache/camel
```

Which allows to run Camel with `camel` as shown below.

```shell
camel --version
```

#### Integration testing

The examples provide automated integration tests that you can run with the [Citrus](https://citrusframework.org/) test framework.

You need to install Citrus as a JBang app, too:

```shell
jbang app install citrus@citrusframework/citrus
```

Now you can start running commands for the Citrus JBang app with just calling `citrus`:

```shell
citrus --version
```

Usually the Citrus tests are written in YAML files and named accordingly to the Camel JBang route source file.

For instance the Camel route `mqtt.camel.yaml` route provides a test named `mqtt.camel.it.yaml`.
You can run the test with Citrus JBang like this:

```shell
citrus run mqtt.camel.it.yaml
```

Usually the test prepares the complete infrastructure (e.g. via Docker compose) and starts the Camel route automatically via JBang.
Of course the test also performs some validation steps to make sure that the Camel route works as expected.

### Other Examples

You can also find a set of various Camel JBang examples at: https://github.com/apache/camel-kamelets-examples/tree/main/jbang 

