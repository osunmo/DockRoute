# CONNECTION_REFUSED

**Kind:** Transport observation.

An attributable TCP connection attempt was explicitly refused.

## Example

DNS resolves api but connecting to port 8001 returns a refusal.

## Suggested fix

Check the requested container port, current listener, bind address and service lifecycle.

## What it does not prove

It does not prove wrong port, loopback-only binding, firewall policy or why the application stopped.

[All diagnostic codes](../diagnostics.md) Â· [JSON contract](../json-output.md)
