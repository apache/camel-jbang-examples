## Kubernetes Service

This example shows how to run a simple Camel REST service on Kubernetes.

The route exposes a REST endpoint at `/news` that returns a hello message.

### How to run

Deploy to Kubernetes:

    camel kubernetes run news-service.camel.yaml
