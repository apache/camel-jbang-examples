# Transform and map

<!-- group:start -->
JSON, XML and CSV in and out, field-by-field mapping, Groovy and XSLT.

| Example | What you will see | Needs |
|---|---|---|
| [JSON transform](json-transform/) | The shop's order in order.json is reshaped for the warehouse: jsonpath reads the order id and the number of lines into headers, jq builds the pick list with only sku and quantity per line, and both the order and the pick list are logged. | nothing |
| [XML to JSON](xml-to-json/) | A supplier's XML order dropped in the inbox directory is read with the Jackson XML data format and written out as the shop's JSON with the Jackson JSON data format, both logged; no mapping code, the XML elements and attributes become JSON fields. | nothing |
| [CSV to JSON](csv-to-json/) | A CSV of invoices dropped in the inbox directory is read with the CSV data format, its header line naming the fields, split into one message per invoice, and each invoice is logged as JSON and written to the outbox directory as its own file. | nothing |
| [Data mapping](data-mapping/) | The shop's order in order.json is mapped field by field to the courier's shipment format, with renamed fields, a nested recipient, one parcel per line, a computed total and a service chosen from the country; the order is parsed to a map, the script shipment-mapping.groovy builds the shipment, and it is logged as JSON. | nothing |
| [Groovy](groovy/) | Two orders come in, one with a valid customer email and one with a bad one; a Groovy expression checks the address with Apache Commons Validator, a third-party library declared in application.properties, and the log shows one order accepted and one rejected. | nothing |
| [XSLT](xslt/) | A supplier's XML order dropped in the inbox directory is transformed by the stylesheet packing-slip.xsl into the packing slip the warehouse prints, one item per line and the total pieces to pick, and the slip is logged. | nothing |

Start with [JSON transform](json-transform/); the examples read best in the order above, each one building on what the one before it set up.

Every example has a README that says what you will see, how it works, how to build it step by step, what to try changing, and how to run its test with `camel test run`.
<!-- group:end -->
