# FTP courier

Shipments are handed to the courier as files on its FTP server: an order on the `shipments` queue becomes one
file per order in the courier's directory. Two services, both started by the CLI.

## What you will see

```text
INFO ... ftp.camel.yaml:42 : Shipment ORD-1001 uploaded to the courier as courier/shipment-ORD-1001.json
INFO ... ftp.camel.yaml:42 : Shipment ORD-1002 uploaded to the courier as courier/shipment-ORD-1002.json
INFO ... ftp.camel.yaml:42 : Shipment ORD-1003 uploaded to the courier as courier/shipment-ORD-1003.json
```

## Install Camel CLI

<!-- see installation instructions in ../../install.adoc -->

## Run it

The example needs running artemis and ftp, which the Camel CLI starts for you in a container
(Docker or Podman must be running). In one terminal:

```shell
camel infra run artemis ftp
```

It prints the connection details as JSON; they match `application.properties`. In another terminal:

```shell
camel run *
```

The embedded FTP server keeps its files under the directory `camel infra` was started in;
`camel infra get ftp` prints the exact path as `getFtpRootDir`, and the three files are in its `courier/`
subdirectory.

Stop the example with `ctrl` + `c` and the services with `camel infra stop artemis ftp`.

## How it works

- `ready-to-ship` reads the orders and puts each on the `shipments` queue with the order id in a header, the
  same way `artemis` does.
- `courier-upload` consumes the queue and writes each message with the `ftp` producer: host and port from
  `camel infra run ftp`, user and password `admin`, `directoryName` the courier's folder, and `fileName` built
  from the header. `passiveMode` is what most servers behind a firewall need.
- `CamelFileNameProduced` is set by the producer with the name it used.
- The FTP server here runs embedded in the `camel infra` process, no container needed.

## Build it step by step

1. A timer route that writes one fixed file with the `ftp` producer; start `camel infra run ftp` and find the
   file with `camel infra get ftp`.
2. Read the orders and write one file per order with `fileName` from a header.
3. Put the queue in between and split the work in two routes.

## Try changing

- Use `sftp` instead: `camel infra run sftp` and the `sftp` component with the same options.
- Add `tempPrefix: .uploading-` so the courier never picks up a half-written file.
- Consume from the FTP server with `ftp://...&delete=true` in a third route and log what the courier gets.

## Integration testing

The example comes with a test in the [Citrus](https://citrusframework.org/) YAML DSL,
`test/ftp.citrus.it.yaml`, which the Camel CLI runs. The test starts the services itself
with the same `camel infra` mechanism, so nothing must be running beforehand:

```shell
camel test run test/ftp.citrus.it.yaml
```

The test starts Artemis and the FTP server, runs the routes and verifies the three uploads.

## Help and contributions

If you hit any problem using Camel or have some feedback, then please
[let us know](https://camel.apache.org/community/support/).

We also love contributors, so
[get involved](https://camel.apache.org/community/contributing/) :-)

The Camel riders!
