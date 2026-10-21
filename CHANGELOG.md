# Changelog

## 0.4.0

- Rename the successful active diagnosis from `HEALTHY` to
  `TCP_REACHABLE` and increment report schema to 3.0. TCP success does not
  establish application readiness.
- Normalize supported driver-qualified connection URIs.
- Read bounded, redacted error signatures and supported mounted Nginx,
  Prometheus and Envoy configuration as supplementary evidence.
- Add deterministic restart, disappearance, recovery, DNS, port and HTTP failure
  controls, with separate automatic and explicit-check evaluation tracks.
- Retry transient selected-project inspection errors with a fixed bound.
- Lead documentation with historical real-project results and current limits.
- Move detailed evidence out of the source tree into release/CI artifacts.

The historical real-repository evaluation used 0.3.0. Its records are not
relabeled as 0.4 accuracy evidence. A release tag requires the gates in
[releasing.md](docs/releasing.md).

## 0.3.0

- Defer command-specific imports until argument validation.
- Add startup and probe timing measurement and native packaging comparisons.

## 0.2.0

- Add bounded DNS/TCP probing, listener inspection and helper lifecycle evidence.
