# NETWORK_ISOLATION

**Kind:** Likely configuration cause.

The resolved source and destination have no appropriate shared inspected Docker network.

## Example

app targets api:8000; app is attached only to front and api only to back.

## Suggested fix

Attach the intended services to a shared network and recreate the owned project after review.

## What it does not establish

It does not establish that traffic was attempted or exclude additional application failures. Host/container/none network modes are not inferred as ordinary bridge topology.

[All diagnostic codes](../diagnostics.md) Â· [JSON contract](../json-output.md)
