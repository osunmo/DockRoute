# CONNECTION_TIMEOUT

**Kind:** Transport observation.

An attributable TCP connection attempt did not complete within its configured deadline.

## Example

A resolved destination address produces no completed TCP handshake before the deadline.

## Suggested fix

Inspect current network reachability, filtering, listener/service state and the reported deadlines.

## What it does not establish

It does not identify the dropping component or establish network isolation. A slow or overloaded environment can also exhaust a deadline.

[All diagnostic codes](../diagnostics.md) Â· [JSON contract](../json-output.md)
