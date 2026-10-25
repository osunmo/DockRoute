# DockRoute Architecture & Diagnostic Boundaries

This document defines the architectural boundaries of DockRoute, specifying the scope of its static analysis and active probing, what failure modes it is engineered to diagnose, and what remains explicitly outside its diagnostic capabilities.

---

## 1. Architectural Overview

DockRoute operates as a local-first connection linter and diagnostic tool for Docker Compose projects. It analyzes inter-service dependencies and connectivity through two complementary modes:

1. **Static Configuration Inspection**: Reads Compose labels, environment variables, published/exposed container ports, mounted configuration files (e.g. Nginx, Envoy, Prometheus), and recent log error signatures without modifying running containers.
2. **Active Network Probing (Opt-In with `--probe`)**: Spawns ephemeral, resource-bounded Linux helper containers sharing the network namespace of source containers to perform DNS resolution checks, TCP connection probes, and listener table inspection.

---

## 2. What DockRoute Diagnoses

DockRoute is designed to detect and diagnose specific Docker Engine, Compose configuration, and network topology issues:

### 2.1. Docker Daemon Reachability & Socket Preflight
- **Active Socket Connection Probing**: Validates that the Docker Engine socket (`/var/run/docker.sock` or `DOCKER_HOST`) is not only present with valid filesystem permissions, but actively responding. Detects when the Docker daemon is stopped (`ECONNREFUSED`) or hung/unresponsive (connection timeout), providing actionable remediation guidance.
- **Windows Named Pipes (`npipe://`) Guidance**: Explicitly intercepts Windows named pipe endpoints, informing the user that Windows named pipes cannot be traversed by Linux probe helpers and guiding configuration toward `tcp://host.docker.internal:2375` or the WSL2 Unix socket.

### 2.2. Socket Mounts & GID Permissions
- **Socket Permissions & Access**: Verifies accessibility of `/var/run/docker.sock` and flags permission denials caused by user/group ID mismatches with the host Docker daemon group (`docker` group GID).
- **Socket Proxy Endpoint Restrictions**: Diagnoses connection and API failures when communicating via security socket proxies (e.g., `tecnativa/docker-socket-proxy`) where specific API endpoints (such as `/containers/json` or exec endpoints) are restricted or disallowed.

### 2.3. Compose Network Topology & Ingress Routing
- **Network Isolation (`NETWORK_ISOLATION`)**: Identifies when services attempt to communicate across disparate, non-overlapping Docker bridge networks without a shared network bridge.
- **Ingress DNS & Tunnel Routing Collisions**: Detects conflicting container DNS aliases, hostname collisions across overlapping networks, and misrouted ingress or tunnel forwards.
- **Host Port vs Container Port Confusion (`HOST_PORT_INSTEAD_OF_CONTAINER_PORT`)**: Diagnoses instances where application containers target host-published ports rather than internal container ports.
- **Loopback-Only Listeners (`LOOPBACK_ONLY_LISTENER`)**: Discovers services binding exclusively to `127.0.0.1` inside their container namespace instead of `0.0.0.0`, rendering them unreachable to other containers on the same bridge network.
- **Invalid Service Hostnames (`INVALID_SERVICE_HOSTNAME`)**: Identifies configuration references to service names or hosts that do not correspond to any known container, alias, or DNS name in the project.

---

## 3. What DockRoute Does NOT Diagnose (Architectural Boundaries)

DockRoute deliberately enforces strict boundaries to avoid false certainty and fragile heuristics. The following categories are explicitly **out of scope**:

### 3.1. Inter-Container Application L4 / L7 Protocol Semantics
- **No Application-Layer Verification**: DockRoute evaluates network-layer DNS resolution and Layer 4 TCP handshakes (`TCP_REACHABLE`). It does **not** validate application-layer protocols (HTTP status codes such as 401, 403, 500; REST/GraphQL payload schemas; database wire protocols and authentication; AMQP/Redis handshakes; or gRPC stream states).
- **No TLS / Certificate Validation**: DockRoute does not negotiate TLS handshakes or validate certificate trust chains for encrypted endpoints. `TCP_REACHABLE` confirms that a listener accepted the TCP connection, **not** that application-level authentication, negotiation, or health readiness succeeded.

### 3.2. Localhost Loopback Errors in Arbitrary Runtimes
- **Internal Loopback Failures**: DockRoute does not diagnose loopback errors occurring inside complex application runtimes, nested virtual machines, sandboxes, or user processes that do not open container network listeners.

### 3.3. Cross-Network Bridge Resolution & Complex Routing
- **Host IPTables & Custom CNI Routing**: DockRoute inspects standard Docker Compose network configurations. It does not trace custom host-level `iptables` / `nftables` rules, eBPF filters, third-party CNI plugins, Kubernetes multi-cluster networking, or multi-host VPN/mesh routing overlays.
- **Arbitrary Unmounted Configurations**: Static analysis extracts endpoints only from supported configurations (environment variables, labels, and supported mounted files for Nginx, Envoy, and Prometheus). Arbitrary application configuration formats, templated secrets, and unmounted files are not analyzed.

---

## 4. Exit Code and Diagnostic Code Guarantees

| Code | Type | Meaning |
|:--|:--|:--|
| `TCP_REACHABLE` | Transport Observation | TCP handshake succeeded. Application readiness is not asserted. |
| `CONNECTION_REFUSED` | Transport Observation | TCP connection actively refused (daemon/service not listening or rejecting). |
| `CONNECTION_TIMEOUT` | Transport Observation | TCP SYN or DNS query timed out before deadline. |
| `DNS_FAILURE` | Transport Observation | Hostname failed to resolve within container network resolver. |
| `NETWORK_ISOLATION` | Configuration Cause | Source and destination share no common Docker network. |
| `UNKNOWN` | Abstention | Evidence is ambiguous or insufficient to assert a root cause. |

Refer to [diagnostics.md](docs/diagnostics.md) and [KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) for detailed case studies and tracking.
