# WRONG_LOCALHOST

**Kind:** Configuration hypothesis.

A source points to loopback while unambiguous dependency evidence supports another intended service.

## Example

backend DATABASE_URL uses localhost:5432 while its only relevant dependency is db.

## Suggested fix

Use the destination service name and container port when the intended server is another container.

## What it does not establish

Loopback can be intentional. A listener/public-origin/advertised address is not automatically a client endpoint; dependency evidence does not establish traffic.

[All diagnostic codes](../diagnostics.md) Â· [JSON contract](../json-output.md)
