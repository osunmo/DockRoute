# DNS_FAILURE

**Kind:** Transport observation.

An attributable source-side lookup failed or exceeded its DNS deadline.

## Example

app cannot resolve api; probe reports dns=failed or dns=timeout with source resolver-file comparison.

## Suggested fix

Check name spelling, aliases, project network membership and source DNS settings; distinguish a deadline from a definite missing name.

## What it does not establish

It does not establish the resolver's root cause or application resolver equivalence. A timeout does not establish that the name does not exist.

[All diagnostic codes](../diagnostics.md) Â· [JSON contract](../json-output.md)
