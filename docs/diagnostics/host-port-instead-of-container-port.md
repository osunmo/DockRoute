# HOST_PORT_INSTEAD_OF_CONTAINER_PORT

**Kind:** Configuration hypothesis.

The configured internal port matches a different published host port on the destination.

## Example

db publishes 15432:5432; app targets db:15432.

## Suggested fix

Use db:5432 for traffic within the Compose network; retain 15432 for host clients.

## What it does not establish

Port mapping is configuration evidence, not evidence that the container has no other listener or that it caused the observed outage.

[All diagnostic codes](../diagnostics.md) Â· [JSON contract](../json-output.md)
