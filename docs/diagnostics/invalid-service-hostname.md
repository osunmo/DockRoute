# INVALID_SERVICE_HOSTNAME

**Kind:** Configuration hypothesis.

A configured internal name does not match the selected project's reachable service/alias, with supporting dependency/network evidence.

## Example

app targets apii:8000 and its unambiguous intended dependency is api.

## Suggested fix

Correct the service name or define a network-scoped alias on a shared network.

## What it does not establish

It does not establish NXDOMAIN, a complete DNS outage or the intended destination when evidence is ambiguous. External/custom names can be legitimate.

[All diagnostic codes](../diagnostics.md) Â· [JSON contract](../json-output.md)
