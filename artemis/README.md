## Apache ActiveMQ Artemis

This example shows how to setup connection factory to a remote Apache ActiveMQ Artemis
messaging broker.

### Apache ActiveMQ Artemis

You first need to have an ActiveMQ Artemis broker up and running.
See more at: https://activemq.apache.org/components/artemis/

You can run Artemis using

```sh
$ camel infra run artemis
```

Alternatively, you can run it with Docker manually

```sh
$ docker run --detach --name mycontainer -p 61616:61616 -p 8161:8161 --rm apache/activemq-artemis:latest-alpine
```

Either command will run the broker locally. To login you need to use `artemis` as username and password,
in the `application.properties` file.


### Install JBang

First install JBang according to https://www.jbang.dev

When JBang is installed then you should be able to run from a shell:

```sh
$ jbang --version
```

This will output the version of JBang.

To run this example you can either install Camel on JBang via:

```sh
$ jbang app install camel@apache/camel
```

Which allows to run Camel CLI with `camel` as shown below.

### How to run

You can run this example using:

```sh
$ camel run *
```

Camel will start sending random numbers to Artemis and logging them. See `producer.camel.yaml` for route that sends the numbers
and `consumer.camel.yaml` for route that logs them.

### Artemis configuration

See the `application.properties` for how to configure to the ActiveMQ Artemis broker.

### Developer Web Console

You can enable the developer console via `--console` flag as show:

```sh
$ camel run * --console
```

Then you can browse: http://localhost:8080/q/dev to introspect the running Camel Application.


### Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
