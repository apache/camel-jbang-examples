## Send Message Test

This example has a `direct` route you can send messages to, and a `timer` route that ticks in the background.

Use this to test sending messages via the TUI (F2 -> Send Message) or the CLI (`camel cmd send`).

### How to run

    camel run send-test.yaml

### Send a message (CLI)

    camel cmd send send-test --endpoint=direct:greet --body=World

### Send a message (TUI)

    camel tui

Select the integration, press `F2`, choose `Send Message`, type a message body, and press Enter.

Toggle the mode to `InOut` to see the reply ("Hello World!").
