# Probe latency measurements

Worker clocks and request telemetry are opt-in with `--timing`; the terminal header always reports total diagnosis time, and JSON reports always include `timings.total_ms`. Schema **2.1** adds a `timings` object and optional probe trace fields without changing the meaning of schema 2.0 fields. `--verbose` includes a compact stage table. Raw Docker payloads, request bodies and query strings are never recorded.

```powershell
dockroute doctor --project myproject --probe --timing --verbose --observe poll
python scripts/benchmark_latency.py --conditions poll,poll-unlimited,floor --startup-timeout 30 --api-timeout 20 --output outputs/latency.json
```

## Clock definitions

The worker imports `time` first and captures `perf_counter()` and `time.time()` before other imports. Wire protocol 2 adds optional finite numeric fields; protocol 1 remains accepted for recovery compatibility. The same strict state/observation validation applies to both.

| Field | Clock and meaning |
|---|---|
| `import_ms` | Worker monotonic time from script entry to imports complete |
| `ready_ms` | Worker monotonic time from script entry to preparing the ready frame |
| `wall_ts` | Worker kernel wall-clock seconds at ready emission |
| `execution_ms` | Worker monotonic time after ready through execution completion |
| `dns_ms`, `tcp_ms` | Actual measured worker phases, present only when attempted |
| `host_ready_ms` | Host monotonic duration from `start()` returning through observing ready |
| `vm_startup_ms` | Derived worker wall_ts minus daemon `State.StartedAt`, in milliseconds |
| `observation_overhead_ms` | Derived max(host_ready_ms − vm_startup_ms, 0) |

Worker script-entry timing excludes the interpreter starting, importing `time`, and package initialization if imported as a module. VM startup includes pre-script interpreter time. StartedAt is stamped slightly before exec, adding a small bias. The host-ready duration starts after the start response, whereas VM startup begins at StartedAt; these are different windows. Consequently observation overhead is a qualified estimate, not an exact partition. Only worker/daemon wall clocks are compared. Neither is compared with the Windows host's wall clock. Missing or invalid StartedAt leaves derived values null.

The optional post-ready inspection has its own `timing_inspect` stage and is excluded from the recorded worker_startup duration. It is absent when timing is not requested. All probe stages retain host monotonic elapsed time. Poll, empty-poll, explicit reload and received-response counts are recorded per stage.

`timings.total_ms` covers CLI main entry through completed diagnosis, including Engine connection/inspection and helper cleanup. The CLI cold-start change moves command-specific imports inside that existing clock, after argument validation; eager parser imports before main, report serialization/rendering, process launch and standalone unpacking remain excluded. Historical datasets below used the earlier eager command imports, outside this clock. Use full process wall time to compare those revisions. The benchmark separately records full child `wall_ms`, and separately measures Compose setup, healthy settling and teardown; none are folded into a probe attempt's total. Probe stages are a subset of that total, and request elapsed time is nested inside stages. Adding either set of rows is not a substitute for the total clock.

## Request privacy and interpretation

An optional Docker SDK requests-session response hook aggregates method, normalized endpoint, status counts, count, total and maximum response-header latency per stage. Examples: `/containers/{id}/logs`, `/containers/{id}/json`, `/containers/create`, `/images/{id}/json`. Unknown paths become `/other`. Identifiers, names, labels, query values, headers and bodies are omitted. The stage is held in thread-local context; the hook is removed at execution end without disturbing other hooks.

`resp.elapsed` ends when response headers are parsed. Streaming body time is excluded. Requests that fail before any response headers do not invoke the response hook; their failure is still identified in the stage trace. Initial SDK API-version negotiation and ping occur before hook attachment, so they are covered by total elapsed time but not this request summary. CLI project inspection after connection is grouped under `project/inspection`.

The SDK's high-level logs call performs an additional inspect to determine TTY handling. Polling therefore includes both requests and, on empty polls, DockRoute's explicit reload and sleep. The worker_startup stage is host-observed readiness and cannot be treated as interpreter startup alone.

## Controlled experiment

The runner creates one fresh isolated scenario06 project from a validated frozen Compose model, waits for both containers to stay healthy and settled, and verifies actual fixture behavior before measuring. It rotates selected conditions and runs attempts sequentially, with three discarded warm-up rounds followed by at least twenty measured rounds per condition. All raw attempts remain in JSON, including failures and warm-ups.

- Polling with default limits is the baseline and remains available as `--observe poll`.
- Streaming would be compared only after measured observation overhead meets the materiality threshold. That gate was not met by the first dataset; streaming is not implemented or selectable.
- `poll-unlimited` sets the hidden debug-only `DOCKROUTE_HELPER_CPUS=0` override for that child only. The CLI warns on stderr. Other conditions remove any inherited override. Default CPU 0.25, memory 128 MiB, pids limit 32, `cap_drop ALL` and read-only root remain unchanged.
- The floor uses the locally available helper image to run `true` with a fresh owned name and automatic removal.

Distributions contain n, median, linearly interpolated IQR, minimum and maximum. p95 is omitted below forty samples. Every required ready-clock metric must have at least twenty valid measured samples; partial or missing timing coverage cannot qualify a dataset for a decision. Raw samples, including invalid attempts, and Markdown summaries are saved under ignored `outputs/` with Engine/Compose/Desktop metadata, date, source revision/hashes and cleanup observations. Scheduling changes are measured in separate datasets, with sequential benchmark attempts throughout.

## First committed result and decision


## Transport and cancellation limits

Helper lifecycles and archive reads remain sequential. Docker SDK streaming
archive reads can outlive ordinary request deadlines on some transports;
named-pipe cancellation is not established by the timeout flag alone. Do not
parallelize these reads without bounded cancellation and ownership-safe cleanup.

The worker enforces DNS timing with one owned resolver child so a libc lookup
blocked in C cannot hold the parent indefinitely. The parent reaps only its
child and closes private descriptors on completion, timeout and cancellation.
Resource limits remain unchanged.

Historical timing datasets are release/CI artifacts. They are descriptive,
machine-dependent measurements; separate non-interleaved policy batches do not
establish a causal speedup. See [release gates](releasing.md).
