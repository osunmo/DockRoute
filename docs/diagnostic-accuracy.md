# Synthetic regression matrix

These are deterministic, synthetic injected faults and controls. Repeated passes
test regression stability; they are not production accuracy measurements. Start
with [the real-repository results and limitations](corpus-evaluation.md).

The six original fixtures in `scenarios/` and nine expanded fixtures in
`scenarios-accuracy/` have separate reports. Every expanded attempt normalizes
and freezes Compose configuration, validates actual behavior, then evaluates
static `doctor`, active `doctor --probe`, and explicit manual `check --probe`
separately. `UNKNOWN` is an abstention, never a successful root-cause prediction.

| Fixture | Validated behavior | Static expected | Active expected / boundary |
| --- | --- | --- | --- |
| Missing hostname | missing name fails DNS; real service works | INVALID_SERVICE_HOSTNAME | same; manual DNS_FAILURE is a separate observation |
| Wrong port | actual port accepts TCP; configured wrong port refuses | UNKNOWN | CONNECTION_REFUSED; does not establish why |
| Host port confusion | host-published port differs from container port | HOST_PORT_INSTEAD_OF_CONTAINER_PORT | same, supported by mapping evidence |
| HTTP 500 | TCP accepts; HTTP returns 500 | UNKNOWN | TCP_REACHABLE; application readiness untested |
| HTTP 503 | TCP accepts; HTTP returns 503 | UNKNOWN | TCP_REACHABLE; application readiness untested |
| Source restart loop | exit status 1; restart count rises | UNKNOWN | UNKNOWN or probe unavailable |
| Destination restart loop | exit status 1; restart count rises | UNKNOWN | UNKNOWN or transient transport observation |
| Source disappears | owned source removed after probe helper lease | UNKNOWN | UNKNOWN or probe unavailable; race must be confirmed |
| Restart recovery | StartedAt changes; source HTTP 200 recovers | UNKNOWN | TCP_REACHABLE after behavior validation |

Each `expected.yaml` defines evidence, uncertainty, exit codes and cleanup.
An HTTP control that cannot establish TCP reachability fails its active
assertion; converting it to `UNKNOWN` does not make it pass.

## Run on Linux, macOS or Windows PowerShell

These single-line commands work in Bash and PowerShell. Docker must run Linux
containers; the runner never pulls images itself.

```sh
python -m pip install -e ".[dev]"
docker pull python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4
docker tag python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4 python:3.12-alpine
python scripts/benchmark_accuracy.py --runs 10 --allow-fixed-ports --output outputs/accuracy-new.json
python scripts/benchmark.py --allow-fixed-ports --output outputs/original-six-new.json
```

Use a fresh output filename; existing evidence is never replaced. Port 18001
must be free for the expanded mapping fixture; the original fixture uses 18000.
Only fresh owned projects are removed. No `down -v` or daemon-wide prune is used.

## Reports and metrics

The `dockroute.accuracy-benchmark/1.0` report records scenario definitions and
hashes, exact commands, source hashes/revision, tool/Engine/Compose versions,
image identity, raw output hashes, behavior validation, expected/observed codes,
grades, timing, configuration fingerprints and cleanup.

Root-cause precision/recall use only supported labeled causes. False-positive
rates distinguish the recovered healthy control from unrelated application
faults. UNKNOWN/abstention, execution failure and cleanup coverage are reported
separately. Failing/missing executions remain in recall and coverage
denominators; false-positive rates use valid executions with their denominator
reported. Median timing covers the full valid CLI process, excluding Compose
setup/teardown. Manual results never raise automatic scores.

Detailed JSON and raw outputs belong in CI/release artifacts. Raw normalized
configuration is safe only for these credential-free synthetic fixtures; never
upload real application configuration or logs without review. Historical 0.3
reports retain their original `HEALTHY` code and schema; they are not rewritten
as 0.4 results. See [release verification](releasing.md).
