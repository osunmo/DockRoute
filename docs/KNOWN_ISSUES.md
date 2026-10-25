# Known Issues in DockRoute 0.4.0

This document tracks known limitations, design anomalies, and open investigation areas identified during DockRoute 0.4 evaluation.

---

### 1. Any non-running source container forces exit 6

**Description:** When evaluating a project where at least one discovered source service container is not currently running (such as a completed database migration, one-shot seed task, or stopped worker), active probe execution marks that endpoint's status as `PROBE_UNAVAILABLE`. Under the aggregate status reporting logic in `src/dockroute/reporting.py`, `PROBE_UNAVAILABLE` takes precedence over all outcomes except `NETWORK_FAILURE`, forcing the overall CLI exit code to `6`. This occurs even when every other probeable inter-service communication edge succeeds and reports `TCP_REACHABLE`.

---

### 2. Stopped dependency alone produces code UNKNOWN, status NETWORK_FAILURE, and exit 2

**Description:** When a destination dependency container is stopped, DockRoute observes a connection failure and marks the finding's status as `NETWORK_FAILURE`. However, because the failure mechanism is an exited destination rather than a supported configuration defect (such as network separation or port mismatch), DockRoute assigns diagnostic code `UNKNOWN`. In `src/dockroute/reporting.py`, an aggregate report containing code `UNKNOWN` without any specific failure code exits with code `2` (inconclusive/uncertainty), conflicting with documentation stating that a measured network failure exits with code `1`.

---

### 3. Portless `depends_on` references make healthy projects exit 2

**Description:** In Docker Compose files where services declare `depends_on` dependencies without exposing container ports (for instance, internal database services without explicit `ports` mappings), DockRoute discovers the relationship with `port: null`. Because active probing cannot determine a destination port without configuration or traffic observation, the edge remains unprobed with code `UNKNOWN`. A healthy project containing such internal dependencies therefore exits with code `2` rather than `0`.

---

### 4. Stopped-destination remediation points at DNS configuration

**Description:** When a destination container is stopped, DockRoute's finding explanation correctly identifies that the destination container is not running. However, the accompanying suggested remediation text may direct users to inspect Docker DNS configuration or service name resolution. While a stopped container causes name resolution or socket connection attempts to fail, suggesting DNS troubleshooting is misleading when the underlying container is simply stopped.

---

### 5. `HELPER_EXECUTION_FAILED` reported for exited destinations

**Description:** When an active probe helper attempts to connect to an exited destination container, the helper execution trace can record `HELPER_EXECUTION_FAILED` rather than distinguishing between helper process execution failure and socket-level refusal or destination absence. This obscures the difference between internal probe helper errors and target availability.

---

### 6. `docker compose up --no-deps` strips Compose labels and alters static diagnosis

**Description:** When containers are created or recreated using `docker compose up --no-deps <service>`, Docker Compose may omit or alter internal dependency labels (such as `com.docker.compose.depends_on`). Because DockRoute's static inspection relies on Docker container metadata labels to infer dependency relationships, this changes the static inspection result and can cause intended edges to be missed or reclassified.

---

### 7. `NETWORK_ISOLATION` recall on disconnect-style isolation needs investigation

**Description:** In multi-project case study screening, disconnecting a source container from a shared network resulted in `NETWORK_ISOLATION` being identified in 4 of 13 runs (30.8%). In the remaining runs, DockRoute emitted `UNKNOWN` or missed the configuration cause due to lack of explicit port mappings or network endpoint inspection subtleties. Further investigation is needed into the effect of runtime network disconnect vs. Compose-level network definition separation.

---

### 8. Helper container startup appears serialized (hypothesis)

**Description:** Across multi-container active probing benchmarks, total tool duration scales roughly linearly with the number of probed endpoints ($2.0\text{–}2.5\text{ s}$ per endpoint). Initial timing traces suggest that probe helper container creation, network namespace joining, and execution proceed sequentially rather than concurrently. Investigating concurrent helper dispatch could reduce active probe wall-clock latency on projects with multiple endpoints.

---

### 9. Windows Docker named pipes (`npipe://`) not supported for helper probing

**Description:** On Windows hosts running Docker Desktop with Windows containers or native named pipe endpoints (`npipe:////./pipe/docker_engine`), DockRoute's active probing cannot spawn Linux helper containers attached to Windows named pipes. Users must expose the daemon over TCP (`tcp://host.docker.internal:2375` or `tcp://127.0.0.1:2375`) or use Docker within WSL2 with standard Unix socket mounts (`/var/run/docker.sock`).

---

### 10. Static filesystem checks alone miss stopped or hung Docker daemons

**Description:** Filesystem-only socket inspection (`stat()` and `access()`) reports that `/var/run/docker.sock` is accessible even when the daemon process has terminated or crashed, leading to unhandled connection exceptions. DockRoute 0.4.1 adds active socket connection preflight probing with short timeouts to catch `ECONNREFUSED` and unresponsiveness with explicit, actionable remediation guidance.
