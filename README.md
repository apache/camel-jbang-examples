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

[source,sh]
----
$ jbang --version
----

This will output the version of JBang.

To run this example you can either install Camel on JBang via:

[source,sh]
----
$ jbang app install camel@apache/camel
----

Which allows to run Camel with `camel` as shown below.

[source,sh]
----
$ camel --version
----


### Other Examples

You can also find a set of various Camel JBang examples at: https://github.com/apache/camel-kamelets-examples/tree/main/jbang 

