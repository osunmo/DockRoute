# TCP_REACHABLE

**Kind:** Successful transport observation.

Supported active DNS/TCP checks completed successfully for this endpoint.

## Example

api accepts TCP on port 8000 even when its HTTP response is 500 or 503.

## Suggested fix

No network remediation is indicated by these checks; validate the application protocol separately.

## What it does not prove

It does not prove HTTP readiness, authentication, TLS, database readiness, correct application responses or lasting availability.

[All diagnostic codes](../diagnostics.md) Â· [JSON contract](../json-output.md)
