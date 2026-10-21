# Diagnostic codes

Codes and the JSON schema form a versioned public interface. Report schema 3.0
uses `TCP_REACHABLE` in place of schema 2.1's `HEALTHY`. The code change is
incompatible; see [migration](json-output.md). Other codes, connection statuses
and exit behavior retain their meaning. Changes that remove a code or narrow its
meaning require a schema-major compatibility decision; new codes require a
published schema revision and documented consumer behavior.

A likely configuration cause, a measured transport outcome and a Docker
healthcheck observation are different evidence categories. Read the explanation,
confidence and verification on each finding. No code establishes protocol
readiness unless its documentation explicitly says so.

| Code | Evidence category |
| --- | --- |
| [NETWORK_ISOLATION](diagnostics/network-isolation.md) | Likely configuration cause |
| [WRONG_LOCALHOST](diagnostics/wrong-localhost.md) | Configuration hypothesis |
| [HOST_PORT_INSTEAD_OF_CONTAINER_PORT](diagnostics/host-port-instead-of-container-port.md) | Configuration hypothesis |
| [LOOPBACK_ONLY_LISTENER](diagnostics/loopback-only-listener.md) | Actively supported configuration cause |
| [INVALID_SERVICE_HOSTNAME](diagnostics/invalid-service-hostname.md) | Configuration hypothesis |
| [DNS_FAILURE](diagnostics/dns-failure.md) | Transport observation |
| [CONNECTION_REFUSED](diagnostics/connection-refused.md) | Transport observation |
| [CONNECTION_TIMEOUT](diagnostics/connection-timeout.md) | Transport observation |
| [SERVICE_UNHEALTHY](diagnostics/service-unhealthy.md) | Docker health observation |
| [TCP_REACHABLE](diagnostics/tcp-reachable.md) | Successful transport observation |
| [UNKNOWN](diagnostics/unknown.md) | Abstention |
