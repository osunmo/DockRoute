"""Rules state what evidence supports; a failed connection is not a proven root cause."""

import ipaddress

from dockroute.discovery import reachable_alias, resolve_hostname, shared_networks
from dockroute.models import Connection, Container, Evidence, Finding, ProbeResult
from dockroute.probe_protocol import INFRASTRUCTURE_FAILURES
from dockroute.safety import is_loopback


def diagnose(
    edge: Connection, containers: list[Container], probe: ProbeResult | None = None
) -> Finding:
    source = next((c for c in containers if c.id == edge.source_id), None)
    observations: list[Evidence] = []
    dests = resolve_hostname(edge.host, containers)
    dest = dests[0] if len(dests) == 1 else None

    def connection_status():
        if not probe:
            return "UNKNOWN"
        if probe.state in INFRASTRUCTURE_FAILURES:
            return "PROBE_UNAVAILABLE"
        try:
            ipaddress.ip_address(edge.host)
            reliable = True
        except ValueError:
            reliable = probe.dns_equivalent is True
        if reliable and probe.dns == "ok" and probe.tcp == "ok":
            return "REACHABLE"
        if reliable and (probe.dns in {"failed", "timeout"} or probe.tcp in {"refused", "timeout"}):
            return "NETWORK_FAILURE"
        return "UNKNOWN"

    def finding(code, explanation, remediation, confidence="medium", active=False, status=None):
        if source and source.state != "running" and not active and code != "UNKNOWN":
            confidence = "medium" if confidence == "high" else confidence
            explanation += " The source has exited; this is a configuration diagnosis supported by recent logs, not a current connectivity check."
        return Finding(
            code,
            edge.source,
            edge.source_id,
            edge.host,
            dest.service if dest else None,
            edge.port,
            tuple(observations),
            edge.evidence,
            explanation,
            confidence,
            remediation,
            "active" if active else "static",
            status or connection_status(),
            probe,
        )

    def unknown(reason, *, compatible=False):
        remediation = (
            "Confirm the intended endpoint; use --probe for DNS, TCP and listener observations."
        )
        if probe:
            fixes = {
                "HELPER_IMAGE_UNAVAILABLE": "Explicitly provision the configured Linux Python helper image locally; static inspection never pulls images.",
                "HELPER_CREATE_FAILED": "Check Docker permissions and support for the displayed helper resource settings.",
                "HELPER_START_FAILED": "Check the helper image entrypoint and Docker Engine startup errors.",
                "HELPER_EXECUTION_FAILED": "Inspect the reported execution stage, exit code and sanitized stderr; confirm the helper image contains Python.",
                "HELPER_TIMEOUT": "Review the timeout classification. Adjust --startup-timeout for cold helper startup, --timeout for execution, or --api-timeout for Engine requests.",
                "INVALID_WORKER_OUTPUT": "The helper did not produce the expected versioned worker response. Check worker/image compatibility and the reported stage.",
            }
            remediation = fixes.get(
                probe.state,
                "Review the measured probe observations and resolver comparison; confirm the endpoint and source DNS configuration.",
            )
            if probe.state in INFRASTRUCTURE_FAILURES:
                reason = f"Active probing was unavailable at {probe.failure_stage}: {probe.state}. {reason}"
        return finding(
            "UNKNOWN",
            reason,
            remediation,
            "low",
            status="NO_STATIC_ISSUES_FOUND" if compatible and probe is None else None,
        )

    def active_outcome():
        if not probe:
            return None
        try:
            ipaddress.ip_address(edge.host)
            reliable = True
        except ValueError:
            reliable = probe.dns_equivalent is True
        if not reliable:
            return None
        if probe.tcp == "ok":
            return finding(
                "TCP_REACHABLE",
                "TCP connectivity succeeded for this endpoint. Application protocol readiness was not tested.",
                "No network remediation indicated by these checks.",
                "high",
                True,
            )
        if probe.dns in {"failed", "timeout"} and probe.dns_equivalent:
            return finding(
                "DNS_FAILURE",
                (
                    "DNS lookup did not complete before its deadline; the underlying cause is unconfirmed. "
                    if probe.dns == "timeout"
                    else "DNS lookup failed. "
                )
                + "Resolver files match the source snapshots; application-specific resolution may differ.",
                "Check the hostname, aliases and source DNS configuration.",
                "high",
                True,
            )
        if probe.tcp == "refused":
            return finding(
                "CONNECTION_REFUSED",
                "TCP was explicitly refused; no listener, startup timing or a rejecting firewall may be involved.",
                "Check the destination listener, readiness and firewall rules.",
                "high",
                True,
            )
        if probe.tcp == "timeout":
            return finding(
                "CONNECTION_TIMEOUT",
                "TCP did not complete before the deadline; its underlying cause is unconfirmed.",
                "Check destination availability, routing and firewall policy.",
                "high",
                True,
            )
        return None

    if source is None:
        observations.append(
            Evidence("snapshot", "Source container is absent from the selected project snapshot")
        )
        return unknown("Source metadata is missing.")
    observations.append(
        Evidence(
            "source_state",
            f"Source is {source.state}; health={source.health}; restarts={source.restart_count}",
        )
    )
    log_hints = tuple(
        hint
        for hint in source.log_hints
        if hint.source_id == source.id
        and hint.host == edge.host
        and (hint.port is None or edge.port is None or hint.port == edge.port)
    )
    observations.extend(hint.evidence() for hint in log_hints)
    if source.supplemental_issues:
        observations.append(
            Evidence(
                "inspection_note",
                "Selected-project supplemental inspection: "
                + ", ".join(source.supplemental_issues),
            )
        )
    if probe:
        observations.append(
            Evidence(
                "probe",
                f"State={probe.state}; DNS={probe.dns}; TCP={probe.tcp}; resolver files match source={str(probe.dns_equivalent).lower() if probe.dns_equivalent is not None else 'unknown'}",
            )
        )
        observations.extend(Evidence("probe_note", x) for x in probe.notes)
        if probe.listener_verified:
            observations.append(
                Evidence(
                    "listeners",
                    "Destination TCP listeners on requested port: "
                    + (", ".join(probe.listener_addresses) or "none"),
                )
            )
    if source.state != "running" and not log_hints:
        return unknown("Source is not running; network reachability cannot be assessed reliably.")
    if source.state != "running" and not source.networks:
        return unknown(
            "Source exited and its network attachments are unavailable; recent logs do not establish present topology."
        )
    if edge.port is None:
        return unknown("depends_on does not establish a connection or a destination port.")
    if any(
        edge.host == x.replace("=", ":", 1).split(":", 1)[0].lower() for x in source.extra_hosts
    ):
        return unknown(
            "The endpoint has an extra_hosts override; the configured service topology may not identify its actual target."
        )
    if is_loopback(edge.host):
        observations.append(
            Evidence("loopback", "Configured endpoint resolves to this container's own loopback")
        )
        if source.network_mode in {"host", "none"} or source.network_mode.startswith("container:"):
            return unknown(
                "Special network mode prevents attributing loopback to a mistaken service target."
            )
        if probe and probe.tcp == "ok":
            outcome = active_outcome()
            if outcome:
                return outcome
        candidates = [c for c in containers if c.service in source.depends_on and c.id != source.id]
        if len({c.service for c in candidates}) == 1:
            return finding(
                "WRONG_LOCALHOST",
                "The loopback endpoint targets the source itself; a Compose dependency suggests another service was intended.",
                f"If the dependency is the intended server, use {candidates[0].service}:{edge.port}. Keep localhost for intentional in-container servers.",
            )
        return unknown(
            "Loopback may be intentional; there is insufficient evidence of another intended service."
        )
    if source.network_mode in {"host", "none"} or source.network_mode.startswith("container:"):
        return unknown(
            "Host, disabled or shared application network modes need manual investigation."
        )
    if not dests:
        observations.append(
            Evidence(
                "hostname",
                "No selected-project service, container name, network alias or IP matches the endpoint",
            )
        )
        if edge.explicit:
            outcome = active_outcome()
            if outcome:
                return outcome
        if "." not in edge.host and ":" not in edge.host and source.depends_on:
            return finding(
                "INVALID_SERVICE_HOSTNAME",
                "This hostname does not identify a selected-project service or alias; a dependency suggests an internal target.",
                "Use the intended Compose service name or add an alias on a shared network.",
            )
        if probe and probe.dns == "failed" and probe.dns_equivalent:
            observations.append(
                Evidence(
                    "dns",
                    "Resolver files match the source snapshots; lookup failed in its network namespace",
                )
            )
            return finding(
                "DNS_FAILURE",
                "Hostname resolution failed during the probe; the configuration mistake is not established.",
                "Check the hostname, source DNS configuration and network membership.",
                "high",
                True,
            )
        return unknown(
            "The endpoint may be external, custom DNS, a missing service, or a typo. Discovery does not probe unrecognized targets."
        )
    if len(dests) != 1:
        observations.append(
            Evidence(
                "hostname", f"Endpoint matches {len(dests)} containers in the selected project"
            )
        )
        return unknown(
            "The destination is ambiguous (replicas or alias collision); inspect each instance explicitly."
        )
    dest = dests[0]
    if dest.network_mode in {"host", "none"} or dest.network_mode.startswith("container:"):
        return unknown(
            "Destination uses a special network mode; ordinary Compose topology rules do not apply."
        )
    if dest.state != "running":
        observations.append(Evidence("destination_state", f"Destination is {dest.state}"))
        return unknown(
            "Destination is not running; startup or lifecycle investigation is needed before network diagnosis."
        )
    shared = shared_networks(source, dest)
    observations.append(
        Evidence(
            "networks",
            f"Source networks: {', '.join(sorted(source.networks)) or 'none'}; destination networks: {', '.join(sorted(dest.networks)) or 'none'}; shared: {', '.join(shared) or 'none'}",
        )
    )
    observations.append(
        Evidence(
            "destination_state",
            f"Destination is {dest.state}; health={dest.health}; restarts={dest.restart_count}",
        )
    )
    if not shared:
        return finding(
            "NETWORK_ISOLATION",
            "The source and destination have no shared Docker network for this internal endpoint.",
            "Attach both services to a shared Compose network and recreate them after reviewing the change.",
            "high",
        )
    if not reachable_alias(edge.host, source, dest):
        return finding(
            "INVALID_SERVICE_HOSTNAME",
            "The alias is configured on a network the source cannot reach.",
            "Use a service name or alias on a shared network.",
            "high",
        )
    if probe:
        if probe.listener_verified:
            if (
                probe.listener_addresses
                and all(is_loopback(a) for a in probe.listener_addresses)
                and probe.tcp in {"refused", "timeout"}
                and probe.dns == "ok"
            ):
                return finding(
                    "LOOPBACK_ONLY_LISTENER",
                    "Destination-side inspection found only loopback TCP listeners on this port.",
                    "Bind the server to a container-reachable interface, typically 0.0.0.0 or ::, and review access controls.",
                    "high",
                    True,
                )
        if probe.tcp == "ok" and active_outcome():
            if dest.health == "unhealthy":
                return finding(
                    "SERVICE_UNHEALTHY",
                    "TCP was reachable, but the destination healthcheck is unhealthy.",
                    "Inspect the destination healthcheck and application readiness.",
                    "high",
                    True,
                )
            return finding(
                "TCP_REACHABLE",
                "TCP connectivity succeeded for this endpoint. Application protocol readiness was not tested.",
                "No network remediation indicated by these checks.",
                "high",
                True,
            )
    mismatches = [
        p
        for p in dest.ports
        if p.protocol == "tcp" and p.host == edge.port and p.container != edge.port
    ]
    declares_internal = any(p.container == edge.port and p.protocol == "tcp" for p in dest.ports)
    runtime_listener_exists = probe and probe.listener_verified and bool(probe.listener_addresses)
    if mismatches and not declares_internal and not runtime_listener_exists:
        observations.append(
            Evidence(
                "port_mapping",
                "; ".join(
                    f"Host {p.host_ip}:{p.host} maps to container TCP {p.container}"
                    for p in mismatches
                ),
            )
        )
        return finding(
            "HOST_PORT_INSTEAD_OF_CONTAINER_PORT",
            "The endpoint uses a published host port. Internal traffic normally uses the container port; exposed ports do not prove listeners.",
            f"Use {dest.service}:{mismatches[0].container} for this internal service if that is its listener port.",
        )
    if dest.health == "unhealthy":
        return finding(
            "SERVICE_UNHEALTHY",
            "The destination healthcheck reports unhealthy; this alone does not establish a network root cause.",
            "Inspect the destination healthcheck and application readiness.",
            "high",
        )
    outcome = active_outcome()
    if outcome:
        return outcome
    return unknown(
        "Topology is compatible, but metadata and health status do not prove this application connection works.",
        compatible=True,
    )
