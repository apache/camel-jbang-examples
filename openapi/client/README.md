# Open API client

This example uses the Open API specification as a base for a Camel REST client.
The Camel route reads files from a local directory and sends the content in the form of an Open API REST request to a service.

## Install Camel JBang

<!-- see installation instructions in ../../install.adoc -->

## How to run

First of all we need a Http REST service that is able to handle the client requests.
You may use the Open API server example in [../server](../server/README.md).

Just navigate to the server directory in a separate terminal window and start the Camel Open API server example with:

```shell
camel run *
```

You should see the Camel integration starting and listening on `http://localhost:8080` for incoming requests.
Then you can run the Camel REST client integration using:

```shell
camel run petstore-api.json application.properties petstore-client.camel.yaml
```

You may also run this even more concise with:

```shell
camel run *
```

Now you should see the client invoking the REST service using the OpenAPI specification rules.

## Integration testing

The example provides an automated integration test (`petstore-client.citrus.it.yaml`) that you can run with the [Citrus](https://citrusframework.org/) test framework.
Please make sure to install Citrus as a JBang application (see [Citrus installation guide](../../install-citrus.adoc)).

You can run the test with:

```shell
citrus test/run petstore-client.citrus.it.yaml
```

The test prepares the complete infrastructure and starts the Camel route automatically via JBang.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
