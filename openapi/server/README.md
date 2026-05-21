# Open API server

This example uses an Open API specification as a base for creating a REST service in Camel.
The Camel route is configured to implement the operations declared in the Open API specification.

## Install Camel JBang

<!-- see installation instructions in ../../install.adoc -->

## How to run

Then you can run the Camel integration using:

```shell
camel run petstore-api.json application.properties petstore.camel.yaml
```

You may also run this even more concise with:

```shell
camel run *
```

And then from another terminal (or run the integration with `--background` option),
then send a message to the REST service.

Just call the petstore REST API to retrieve a pet like this:

```shell
$ curl -i http://localhost:8080/petstore/pet/1000
HTTP/1.1 200 OK
petId: 1000
transfer-encoding: chunked
Content-Type: application/json

{
  "id": 1000,
  "name": "fluffy",
  "category": {
    "id": 1000,
    "name": "dog"
  },
  "photoUrls": [
    "petstore/v3/photos/1000"
  ],
  "tags": [
    {
      "id": 1000,
      "name": "generated"
    }
  ],
  "status": "available"
}

```

The REST service in Camel is configured to load example response data from a directory (`camel.component.rest-openapi.mockIncludePattern = file:examples/**,classpath:examples/**`).

## Integration testing

The example provides an automated integration test (`petstore.citrus.it.yaml`) that you can run with the [Citrus](https://citrusframework.org/) test framework.
Please make sure to install Citrus as a JBang application (see [Citrus installation guide](../../install-citrus.adoc)).

You can run the test with:

```shell
citrus run test/petstore.citrus.it.yaml
```

The test prepares the complete infrastructure and starts the Camel route automatically via JBang.
The Citrus test loads the Open API specification from the Camel service and uses the rules in that specification to verify the response data.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
