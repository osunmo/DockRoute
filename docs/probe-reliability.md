# DockRoute 0.2 probe reliability

## Measured original defect

The 0.1 failure was reproduced intermittently from both the source CLI and Windows standalone executable on Docker Desktop, Engine 29.8.1 and Compose 5.5.1. Instrumentation captured `helper.wait(timeout=6)` raising `ConnectionError` after **6.031 seconds**, followed immediately by inspection reporting `Status=exited`, `ExitCode=0` and empty worker stderr. Successful healthy helper waits in that trace ranged roughly **3.3–5.7 seconds**.

The six-second deadline included helper/Python startup and Engine completion response transport. A timed-out response did not prove worker failure. The old broad exception handler discarded the completed worker output, returned DNS/TCP unknown and represented an unperformed resolver comparison as false. This was the observed route to the generic UNKNOWN report. The measurements do not establish why Docker Desktop delayed that response, nor prove CPU throttling or network failure.

The original frozen worker exactly matched source (4449 bytes, SHA256 `d2d5934d855ec096477e88da33dd5b6e4e49e8bdbf001821af458f0b29842b14`) and compiled. Successful real standalone probes also demonstrated working Linux worker injection. No PowerShell quoting is used: Docker SDK receives an entrypoint array and a JSON argument.

## Changes

- A versioned, flushed ready frame separates readiness from bounded execution. Startup, Engine request and network budgets are independently configurable.
- If a wait response fails, inspect that same helper. Recover only exit-zero, strictly validated completed output; do not repeat DNS/TCP traffic.
- If a worker exits between an empty logs snapshot and inspection, read final logs before declaring startup failure.
- Validate worker JSON structure, field types, IPs, enums and observation/state consistency. Invalid output becomes `INVALID_WORKER_OUTPUT`, without disclosing its contents.
- Preserve partial observations and distinguish DNS/TCP deadline expiry from helper startup/API/execution failure. Unknown resolver comparison is null; text reads preserve line endings and unreadable files remain unknown.
- Trace each stage with allowlisted configuration, timing, exit/error categories, sanitized stderr, timeout type and cleanup. Each execution owns unique labeled helpers; deletion checks all labels.
- Separate top-level connection statuses from detailed diagnosis codes. Compatible static metadata is not verified connectivity; container healthchecks do not establish it.

The existing helper architecture and project/address guards remain. Application containers receive no exec commands, dependency installations, filesystem writes or configuration changes from production probes. Helper images must be provisioned explicitly.

## Reproduce

With Docker Desktop running Linux containers, from the repository root:

```powershell
docker pull python:3.12-alpine
python -m pip install -e ".[dev,binary]"
python scripts/build_binary.py --output outputs
dockroute-benchmark --binary .\outputs\dockroute.exe --allow-fixed-ports --output outputs\benchmark-binary.json
```

The runner uses fresh projects, freezes validated fixture configuration, measures real behavior before grading, and cleans only its resources without `down -v`. Fixed port 18000 must be free. For an existing project:

```powershell
.\outputs\dockroute.exe doctor --project myproject --probe --verbose --startup-timeout 15 --timeout 5 --api-timeout 5
```

The live release reports are `outputs/v02-benchmark-binary.json` and `outputs/v02-binary-repeated.json`. Their observations, statuses, execution traces and cleanup records are the evidence; fixture labels alone are not. Remote CI configuration is separate from these local measurements.

## Remaining limits

Resolver snapshot equality is configuration evidence, not libc/NSS/application resolver equivalence. TCP success does not verify protocol, authentication, TLS or application readiness. Special application network modes, ambiguous destination replicas and native Windows container probes remain unsupported. An unavailable Engine or abrupt host/process kill may prevent finally-based cleanup; the visible error identifies the owning execution. Ordinary cancellation and failures are covered by regression tests. Deadlines bound stages/requests; total project runtime grows with connection count and can include cleanup/recovery requests. The original Engine response delay itself cannot be prevented by DockRoute.
