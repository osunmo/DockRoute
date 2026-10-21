# DockRoute

A networking linter for Docker Compose projects, with optional live TCP probes.

DockRoute correlates inferred endpoints with Docker networks, aliases, port
mappings and lifecycle state, then reports evidence and suggested fixes. It is a
local Python CLI using the official Docker SDK. It needs no account or LLM API.

## Measured results and known limitations

The latest **blind real-repository evaluation used DockRoute 0.3.0**:

| Measure | Recorded result |
| --- | ---: |
| Reviewed endpoint precision, five blind repositories | 42/47 (89.4%) |
| Partial-oracle recall, five blind repositories | 42/61 (68.9%) |
| Partial-oracle recall, 25 development configurations | 88/148 (59.5%) |
| Root-cause recall on four real-project injected faults | 1/4 static; 2/4 active |

These are agent source reviews with partial oracle coverage and unreviewed
predictions. They are not independently human-validated or a population-wide
accuracy estimate. The 0.4 changes have not had a new blind evaluation. See the
[evaluation method](docs/corpus-evaluation.md) and [small historical baseline](benchmarks/baseline.json).

**Known limitations:** discovery can miss mounted configuration and image or
application defaults. Version 0.4 supports a bounded subset of mounted Nginx,
Prometheus and Envoy configurations, and supported base URI schemes with driver
qualifiers such as `postgresql+psycopg://`; arbitrary formats, templating and
drivers remain unsupported. TCP success does not verify HTTP status, database
authentication, TLS or application readiness. Ambiguous evidence produces
`UNKNOWN`. A clean report does not establish a complete application graph.

The synthetic scenario suite is a **regression harness**: repeated passes show
that specified behaviors still work. They are not real-project accuracy scores.

## Install and run

Source installation requires Python 3.11+ and access to Docker Engine:

```sh
python -m pip install .
dockroute --version
dockroute doctor --project ecommerce
dockroute doctor --project ecommerce --format json
dockroute check backend postgres:5432 --project ecommerce
```

Run `doctor` from the Compose directory to select its project automatically.
DockRoute requires created Compose containers, including stopped ones. It does
not silently choose an unrelated project. The current public CLI inspects a
Compose project's Docker metadata; the files-only corpus evaluator is a
contributor tool, not a public `lint --file` command or pre-commit integration.

Static inspection is read-only. Discovery covers endpoint environment variables,
supported URLs and host/port pairs, aliases, healthcheck references, selected
mounted configs and bounded error-log signatures. `depends_on` supports an
inferred intention but does not prove traffic or readiness. Reports separate
observations, likely causes, confidence and remediation.

## Example: separate networks

With `app` on `front` and `api` on `back`, this intended connection is isolated:

```yaml
services:
  app:
    environment:
      UPSTREAM_URL: http://api:8000
    networks: [front]
  api:
    networks: [back]
networks:
  front: {}
  back: {}
```

```sh
dockroute doctor --project myproject
# app -> api:8000: NETWORK_ISOLATION
```

After reviewing the finding, connect both services to a shared network in your
Compose file and recreate the project. DockRoute does not apply this change.
Then verify TCP reachability:

```sh
docker pull python:3.12-alpine
dockroute doctor --project myproject --probe
# app -> api:8000: TCP_REACHABLE
# Application protocol readiness was not tested.
```

Use a service's container port for internal traffic. A published host port is
for clients outside that container network. Read the evidence for every finding;
an observed refusal alone does not prove the underlying cause.

## Active probes and safety

`--probe` explicitly permits temporary, labeled helper containers. The helper
image must already be local; DockRoute never pulls it automatically. Helpers
share the relevant container network namespace, use bounded timeouts and resource
limits, and are removed with ownership checks. Automatic traffic is restricted
to the selected project; an explicit `check HOST:PORT --probe` authorizes that
endpoint. Linux containers are required for probes, including on Docker Desktop.

Resolver-file comparisons support source attribution but cannot prove equivalence
with an application's resolver. Destination listener evidence is required for
`LOOPBACK_ONLY_LISTENER`. Metadata and Docker healthchecks alone cannot produce
`TCP_REACHABLE`. Abrupt host/process termination or an unavailable daemon can
prevent cleanup; cleanup failures are reported.

Docker socket access is privileged and belongs only in trusted environments.
DockRoute does not edit YAML, alter application configuration, install tools in
application containers or apply automatic fixes. Do not publish raw normalized
Compose files, application logs, environment files or credentials with bug reports.

## Public contracts

Version 0.4 uses report schema **3.0**. `HEALTHY` was renamed to
`TCP_REACHABLE`; status `REACHABLE` and exit codes retain their meaning.
See [JSON output and migration](docs/json-output.md) and the
[diagnostic code reference](docs/diagnostics.md).

| Exit | Meaning |
| --- | --- |
| 0 | All discovered endpoints completed supported active checks |
| 1 | At least one likely failure or measured network failure |
| 2 | Inconclusive or no connections discovered |
| 3 | Docker unavailable or inspection failed |
| 4 | Invalid arguments or missing/ambiguous selection |
| 5 | Helper cleanup failed |
| 6 | Active probe infrastructure unavailable |
| 130 | Cancelled |

## Contribute and reproduce

See [CONTRIBUTING](CONTRIBUTING.md) for cross-platform setup and the
`expected.yaml` fixture contract. New fixtures are a contribution path, including
cases whose correct result is `UNKNOWN`. The
[regression matrix](docs/diagnostic-accuracy.md) covers topology, ports, HTTP
failure controls, restart loops, disappearing containers and recovery.

Detailed reports and safe raw fixture evidence belong in CI artifacts or release
assets, not Git. Only the compact historical baseline is kept in-tree. Release
publication requires the [release gates](docs/releasing.md): exact source/version,
green hosted Linux Docker validation, privacy checks and matching evidence.

MIT licensed. Standalone native binaries are built with
`python scripts/build_binary.py --output outputs`; see [packaging](docs/cli-startup.md).

