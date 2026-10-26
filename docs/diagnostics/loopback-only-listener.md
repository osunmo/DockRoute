# LOOPBACK_ONLY_LISTENER

**Kind:** Actively supported configuration cause.

Destination-side listener inspection finds only loopback listeners on the requested port, alongside relevant source failure.

## Example

api listens at 127.0.0.1:8000 while app targets api:8000.

## Suggested fix

Configure the server to bind an appropriate container-reachable interface, then recreate/restart it under your control.

## What it does not establish

A refused source connection alone cannot justify this code. Inspection is a point-in-time network-namespace observation and may race restarts.

[All diagnostic codes](../diagnostics.md) Â· [JSON contract](../json-output.md)
