# SERVICE_UNHEALTHY

**Kind:** Docker health observation.

The destination's Docker healthcheck currently reports unhealthy.

## Example

api has State.Health.Status=unhealthy in Docker inspection.

## Suggested fix

Review the healthcheck and application behavior in your trusted environment; correct the underlying application issue.

## What it does not prove

It does not prove network failure. TCP can succeed while the healthcheck fails, and a healthy healthcheck cannot prove an inferred connection works.

[All diagnostic codes](../diagnostics.md) Â· [JSON contract](../json-output.md)
