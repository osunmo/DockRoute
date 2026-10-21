# JSON output contract 2.1

`doctor --format json` and `check SOURCE HOST:PORT --format json` emit one JSON document on stdout. Field names and enums in [report.schema.json](report.schema.json) form the contract. Field ordering is not contractual. Findings are deterministically ordered; Docker snapshots, execution IDs and timing naturally change between runs.

## Reports and findings

| Field | Meaning |
|---|---|
| `schema_version` | `"3.0"`; incompatible changes increment the major version |
| `dockroute_version`, `docker_version` | Tool and daemon versions |
| `project` | Selected Compose project |
| `probe_requested` | Explicit opt-in; does not imply every check succeeded |
| `status` | Aggregate connection status described below |
| `services` | Allowlisted identities, lifecycle/health/restarts, network IDs/aliases/IPs and port mappings |
| `findings` | One finding per inferred source-container endpoint/dependency |
| `limitations` | Interpretation limits |
| `configuration_modified` | Always false; helpers are indicated separately by `probe_requested` |
| `timings` | Total diagnosis time, aggregate probe stage durations and optional normalized request summaries |

Each finding has `code`, `status`, `source`, `source_container`, `destination` (configured hostname/IP), nullable `destination_service`, nullable `port`, `intention_evidence`, `observations`, `explanation`, `confidence` (`high`, `medium`, `low`), `remediation`, `verification` (`static`, `active`) and nullable `probe`. Evidence entries contain `kind` and `detail`. Evidence kinds can be extended; unknown kinds should be displayed as text.

`code` is a diagnosis; `status` describes the strength and outcome of connectivity verification:

| Status | Meaning |
|---|---|
| `NO_STATIC_ISSUES_FOUND` | Compatible metadata; no active connectivity claim |
| `REACHABLE` | Supported source DNS/TCP checks succeeded |
| `NETWORK_FAILURE` | Attributable lookup failure/deadline expiry or TCP refusal/timeout was measured |
| `PROBE_UNAVAILABLE` | DockRoute helper infrastructure or prerequisites failed |
| `UNKNOWN` | Insufficient or ambiguous evidence |

A static finding such as `NETWORK_ISOLATION` may have status `UNKNOWN`; the configuration evidence does not prove that traffic was attempted. A compatible static finding has code `UNKNOWN`, status `NO_STATIC_ISSUES_FOUND`. A healthcheck never proves `TCP_REACHABLE` or `REACHABLE`. `verification` describes supporting diagnosis evidence: a static topology diagnosis stays static even if supplementary probe data is present.

Project status precedence is `NETWORK_FAILURE`, `PROBE_UNAVAILABLE`, then `UNKNOWN`. All findings must be `REACHABLE` to produce that project status, or all must be `NO_STATIC_ISSUES_FOUND` to produce that status. Empty or mixed remaining sets produce `UNKNOWN`. Always inspect individual findings too.

## Probe object

| Field | Meaning |
|---|---|
| `state` | Source worker/infrastructure outcome, enum below |
| `listener_state` | Destination inspection outcome; remains `UNKNOWN` when inspection is skipped |
| `listener_skipped`, `listener_skip_reason` | Optional boolean and nullable reason for an intentionally omitted destination inspection |
| `failure_stage` | Nullable stage of infrastructure failure; may refer to destination inspection even if source succeeded |
| `dns` | `ok`, `failed`, `timeout`, `unknown` |
| `tcp` | `ok`, `refused`, `timeout`, `blocked`, `unknown`; blocked means project address guard prevented traffic |
| `addresses` | Observed DNS IPs |
| `resolver_files_match` | `true`/`false` only after both files were compared; otherwise `null` |
| `listener_addresses`, `listener_verified` | Destination listener evidence on the requested port |
| `execution_id` | Unique execution ID shared by its helper ownership labels |
| `startup_timeout`, `execution_timeout` | Configured seconds for independent worker readiness and execution budgets |
| `dns_timeout`, `connect_timeout` | Optional configured phase budgets in seconds; effective time is capped by remaining execution time |
| `cleanup` | `complete`, `not_needed`, `failed` |
| `trace` | Sanitized source/destination stage records, always available in JSON |

Source/listener `state` values are `SUCCESS`, `DNS_FAILURE`, `TCP_REFUSED`, `TCP_TIMEOUT`, `HELPER_IMAGE_UNAVAILABLE`, `HELPER_CREATE_FAILED`, `HELPER_START_FAILED`, `HELPER_EXECUTION_FAILED`, `HELPER_TIMEOUT`, `INVALID_WORKER_OUTPUT`, `UNKNOWN`. A successful listener inspection is not a successful connection. An expired DNS phase deadline produces `DNS_FAILURE` with `dns: "timeout"`, not helper unavailability or a claim that the name does not exist. Immediate temporary/missing-name resolver errors retain `dns: "failed"` and existing confidence rules. Source attribution of hostname outcomes requires matching resolver files. IP literal checks do not require that comparison. Matching files do not prove application libc/NSS/custom resolver equivalence.

`dns_timeout` defaults to 2 seconds and `connect_timeout` to 1 second, capped by the remaining `execution_timeout` budget. Multiple address attempts share that execution deadline. The helper's parent enforces DNS timing around one short-lived resolver child; child transport, malformed or oversized private results are probe infrastructure failures rather than DNS root-cause claims. These details do not add a diagnosis code or change existing confidence.

With default conditional scheduling, an intentionally skipped listener check has `listener_skipped: true`, a non-null `listener_skip_reason`, `listener_state: "UNKNOWN"` and `listener_verified: false`. The trace includes role `destination`, stage `listener_skipped`, state `SKIPPED`. This records a scheduling decision, not successful listener evidence. The terminal report displays its reason even without `--verbose`. Source results and the existing diagnostic rule determine whether listeners can change the conclusion; refused or ambiguous outcomes retain destination inspection where needed. `--schedule sequential` preserves the full source-then-destination path for comparison.

Trace records include `role`, `stage`, `state`, `elapsed_ms`, nullable `error_type`, nullable `exit_code`, sanitized `stderr`, nullable `timeout_kind`, nullable `cleanup`, `recovered` and nullable `helper_configuration`. Version 2.1 adds optional nullable `timings` and `observe_mode`. The supported transport emits `observe_mode: "poll"`; the schema also reserves streaming values, which do not make streaming available in the CLI. Timeout kinds distinguish `api_request`, `worker_startup`, `worker_execution` and worker DNS/TCP/listener phases. Recovery indicates the same completed helper was inspected after a lost response; it does not repeat traffic.

Helper configuration is an allowlist of resolved image ID when available, namespace container ID, redacted entrypoint, worker SHA256, resource limits, generated name, execution ID and mode. It excludes payloads, DNS file contents and application configuration. `stderr` contains only byte counts and recognized exception categories, never raw stderr, source lines or exception messages. URL userinfo, paths, queries, sensitive environment values, healthcheck commands and logs are excluded. Terminal control characters are filtered and JSON uses ASCII escapes.

An unconfirmed dependency has `port: null`, `code: "UNKNOWN"`. Helper failures are represented as findings when diagnosis can continue. Exit codes remain meaningful: 0 all supported checks succeed, 1 diagnostic failure, 2 inconclusive, 3 Docker/inspection unavailable, 4 invalid selection/arguments, 5 cleanup failure, 6 aggregate probe unavailability, 130 cancellation. Project status precedence means a measured network failure can coexist with unavailable probes and exit 1; inspect findings.

## Timing object

Every diagnostic report includes `timings`, including static reports and reports containing failed findings. Detailed worker clocks and request collection require `--timing`; the total clock and existing probe elapsed stages do not. Milliseconds are nonnegative finite numbers. A static report has empty probe stages; requests are empty when collection was not enabled.

| Field | Meaning |
|---|---|
| `timings.total_ms` | Host monotonic duration from CLI main entry through completed diagnosis and helper cleanup |
| `timings.stages` | Sorted aggregate rows: `role`, `stage`, `count`, `total_ms`, `max_ms` |
| `timings.requests` | Sorted response-header aggregates: `role`, `stage`, `method`, `path`, `count`, `total_ms`, `max_ms`, optional `status_counts` |

The total includes Engine connection and project inspection, plus command-specific imports deferred until after argument validation. It excludes eager parser imports before main, process launch, standalone executable unpacking, serialization/rendering, Compose setup and teardown. Historical benchmarks before the lazy-import change loaded runtime imports before this clock; use the controlled benchmark's separate full child `wall_ms` for that before/after comparison. Aggregate stage time covers probe traces; request time is nested within stages and has a different clock boundary. Neither sum is a replacement for total elapsed time.

Request paths are normalized, for example `/containers/{id}/logs`. IDs, names, labels, query values, headers and bodies are absent from this request log; unknown paths become `/other`. `status_counts` maps received HTTP status codes to counts. This privacy constraint applies to request telemetry: existing allowlisted service identities and helper configuration remain part of the report.

The requests response hook measures send-to-response-headers latency (`response.elapsed`), excluding streaming body time. A request that fails before headers is absent from the request count, though its probe stage records the failure. Collection begins after SDK connection, so initial API negotiation and ping appear in total time but not request summaries. Later CLI metadata requests are grouped under `project/inspection`. The hook is removed at execution end without removing other hooks.

Optional `probe.trace[].timings` contains only known fields:

| Field | Meaning |
|---|---|
| `import_ms`, `ready_ms` | Worker monotonic script-entry duration to imports complete and ready-frame preparation |
| `wall_ts` | Worker kernel wall-clock **seconds**, captured at ready emission |
| `execution_ms`, `dns_ms`, `tcp_ms` | Worker monotonic execution and attempted phase durations |
| `host_ready_ms` | Host monotonic duration from helper `start()` returning until ready is observed |
| `vm_startup_ms` | Nullable worker/daemon wall-clock difference from `State.StartedAt` to ready |
| `observation_overhead_ms` | Nullable `max(host_ready_ms - vm_startup_ms, 0)` |
| `derived` | Marks the derived readiness estimate |
| `polls`, `empty_polls`, `reloads`, `http_requests` | Stage polling, explicit reload and received-response counters |

Worker script-entry timing excludes interpreter startup and importing `time`. The daemon stamps StartedAt slightly before exec, giving VM startup a small bias. Host readiness starts after the start response, so these durations cover different windows: observation overhead is a qualified estimate, not an exact partition. A zero estimate does not establish zero observation cost. Only worker and daemon wall clocks are compared; neither is compared with the Windows host wall clock. Invalid or missing StartedAt leaves derived values `null`. The opt-in post-ready inspect has its own `timing_inspect` stage and is excluded from `worker_startup` elapsed time. See [probe-latency.md](probe-latency.md) for the measurement protocol and actual baseline.

## Errors and migration

Errors use the alternative envelope:

```json
{
  "schema_version": "3.0",
  "dockroute_version": "0.4.0",
  "error": {
    "code": "DOCKER_UNAVAILABLE",
    "message": "Docker Engine unavailable. Start Docker Desktop/Engine and check DOCKER_HOST, Docker context and socket permissions."
  }
}
```

Cleanup errors can include top-level `probe_trace` with the same sanitized record schema. Invalid argparse syntax uses stderr and exit 4. Errors after parsing honor `--format json`.

Version 2.1 is retained in [report-v2.1.schema.json](report-v2.1.schema.json). Version 2.0 is retained in [report-v2.0.schema.json](report-v2.0.schema.json), and version 1.0 in [report-v1.schema.json](report-v1.schema.json).

Migration from 2.0 also requires the additive timing fields introduced by 2.1: accept `schema_version: "3.0"`, add the required report `timings` object, and allow optional trace `timings`/`observe_mode` and probe `listener_skipped`/`listener_skip_reason`/`dns_timeout`/`connect_timeout`. Other field meanings, status values, confidence and exit codes are preserved; apply the HEALTHY rename described below. Current error envelopes use 3.0 but need not contain report timings. Consumers validating against a schema with `additionalProperties: false` must update their schema as part of this migration.

Migration from 1.0 also requires report/finding `status`, nullable `probe` objects, optional error `probe_trace`, and interpreting `resolver_files_match: null` as unknown. Do not infer success from healthchecks, static compatibility, or exit code alone.

The six-scenario benchmark remains a separate `schema_version: "1.0"` suite contract with versions, observations, nested current-schema `static`/`active` reports, `behavior_validated` and per-project cleanup. `--binary PATH` selects the actual standalone CLI; otherwise source is tested. Historical benchmark records retain the report schema used when they were measured. Skips never count as runtime evidence. Suite exits: 0 passed, 1 failed, 2 incomplete, 3 Engine/Compose unavailable, 4 no matching fixtures, 130 cancelled.


## Migration from 2.1 to 3.0

DockRoute 0.4 replaces the finding code `HEALTHY` with `TCP_REACHABLE` in
both terminal and JSON reports. This is an incompatible enum change and uses a
new schema major version. Status `REACHABLE`, exit 0, confidence, fields and
worker protocol are unchanged. Update consumers to branch on `schema_version`
and accept the matching enum. Historical reports and schemas keep `HEALTHY`;
do not rewrite measured evidence. There is no legacy-output switch.

Codes are documented individually in [the code reference](diagnostics.md).
Detailed benchmark records belong in [release/CI artifacts](releasing.md).
