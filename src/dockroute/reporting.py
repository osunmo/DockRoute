"""Versioned allowlist reporting; raw Docker config must never be serialized."""

import json
from dataclasses import asdict

from dockroute import __version__
from dockroute.models import Container, Finding
from dockroute.safety import safe_text


def probe_report(probe):
    if probe is None:
        return None
    cleanup_events = [t.cleanup for t in probe.trace if t.stage == "cleanup"]
    cleanup = (
        "failed"
        if any(x in {"failed", "ownership_unconfirmed"} for x in cleanup_events)
        else "complete"
        if "removed" in cleanup_events
        else "not_needed"
    )
    return {
        "state": probe.state,
        "listener_state": probe.listener_state,
        "failure_stage": probe.failure_stage,
        "dns": probe.dns,
        "tcp": probe.tcp,
        "addresses": list(probe.addresses),
        "resolver_files_match": probe.dns_equivalent,
        "listener_addresses": list(probe.listener_addresses),
        "listener_verified": probe.listener_verified,
        "execution_id": probe.execution_id,
        "startup_timeout": probe.startup_timeout,
        "execution_timeout": probe.execution_timeout,
        "dns_timeout": probe.dns_timeout,
        "connect_timeout": probe.connect_timeout,
        "listener_skipped": probe.listener_skipped,
        "listener_skip_reason": probe.listener_skip_reason,
        "cleanup": cleanup,
        "trace": [asdict(t) for t in probe.trace],
    }


def aggregate_status(findings):
    statuses = {f["status"] for f in findings}
    for status in ("NETWORK_FAILURE", "PROBE_UNAVAILABLE", "UNKNOWN"):
        if status in statuses:
            return status
    if statuses == {"REACHABLE"}:
        return "REACHABLE"
    if statuses == {"NO_STATIC_ISSUES_FOUND"}:
        return "NO_STATIC_ISSUES_FOUND"
    return "UNKNOWN"


def make_report(
    project: str,
    containers: list[Container],
    findings: list[Finding],
    *,
    probe: bool = False,
    docker_version: str = "unknown",
    total_ms: float = 0.0,
    timing: bool = False,
    requests: list | None = None,
) -> dict:
    serialized = [{**asdict(f), "probe": probe_report(f.probe)} for f in findings]
    stages: dict = {}
    for f in findings:
        for t in f.probe.trace if f.probe else ():
            item = stages.setdefault(
                (t.role, t.stage),
                {"role": t.role, "stage": t.stage, "count": 0, "total_ms": 0.0, "max_ms": 0.0},
            )
            item["count"] += 1
            item["total_ms"] += t.elapsed_ms
            item["max_ms"] = max(item["max_ms"], t.elapsed_ms)
    timing_data = {
        "total_ms": round(total_ms, 3),
        "stages": [
            {**entry, "total_ms": round(entry["total_ms"], 3)}
            for _, entry in sorted(stages.items())
        ],
        "requests": requests or [],
    }
    return {
        "schema_version": "3.0",
        "dockroute_version": __version__,
        "docker_version": docker_version,
        "project": project,
        "probe_requested": probe,
        "services": [
            {
                "service": c.service,
                "container_id": c.id,
                "container_name": c.name,
                "state": c.state,
                "health": c.health,
                "restart_count": c.restart_count,
                "networks": [
                    {
                        "name": n.name,
                        "id": n.id,
                        "aliases": list(n.aliases),
                        "addresses": list(n.addresses),
                    }
                    for _, n in sorted(c.networks.items())
                ],
                "ports": [asdict(p) for p in c.ports],
            }
            for c in sorted(containers, key=lambda c: (c.service, c.id))
        ],
        "status": aggregate_status(serialized),
        "findings": serialized,
        "limitations": [
            "Connections are inferred intentions, not confirmed application traffic.",
            "Static metadata cannot prove TCP or application readiness.",
            "Matching resolver files do not prove application-specific resolver or libc equivalence.",
        ],
        "configuration_modified": False,
        "timings": timing_data,
    }


def report_exit_code(report: dict) -> int:
    if report.get("status") == "PROBE_UNAVAILABLE":
        return 6
    codes = {f["code"] for f in report["findings"]}
    if codes - {"TCP_REACHABLE", "UNKNOWN"}:
        return 1
    if not codes or "UNKNOWN" in codes:
        return 2
    return 0


def _sanitize(value):
    if isinstance(value, str):
        return safe_text(value, 2048)
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return value


def render_json(report: dict) -> str:
    return json.dumps(_sanitize(report), indent=2, ensure_ascii=True) + "\n"


def render_terminal(report: dict, *, verbose=False) -> str:
    report = _sanitize(report)
    lines = [
        f"DOCKROUTE {report['dockroute_version']}",
        "=" * 48,
        f"Project: {report['project']}",
        f"Status: {report.get('status', 'UNKNOWN')}",
        f"Elapsed: {report.get('timings', {}).get('total_ms', 0)} ms",
        "",
        "SERVICES",
    ]
    for c in report["services"]:
        lines.append(
            f"  {c['service']} ({c['container_name']}): {c['state']}, health={c['health']}, restarts={c['restart_count']}"
        )
    lines += ["", "DISCOVERED CONNECTIONS AND DIAGNOSES"]
    if not report["findings"]:
        lines += ["  No intended connections found. Result: UNKNOWN."]
    for f in report["findings"]:
        port = f":{f['port']}" if f["port"] else " (port unknown)"
        lines += [
            "",
            f"  {f['source']} -> {f['destination']}{port}: {f['code']}",
            f"  Connection status: {f.get('status', 'UNKNOWN')}",
            f"  {f['explanation']}",
            f"  Confidence: {f['confidence'].upper()} | {f['verification']}",
        ]
        if f["intention_evidence"]:
            lines.append("  Intention evidence:")
            lines.extend(f"    - {e['kind']}: {e['detail']}" for e in f["intention_evidence"])
        lines.append("  Observations:")
        lines.extend(f"    - {e['kind']}: {e['detail']}" for e in f["observations"])
        lines.append(f"  Suggested fix: {f['remediation']}")
        p = f.get("probe")
        if p:
            comparison = (
                "unknown"
                if p["resolver_files_match"] is None
                else str(p["resolver_files_match"]).lower()
            )
            lines.append(
                f"  Probe: {p['state']}; DNS={p['dns']}; TCP={p['tcp']}; resolver comparison={comparison}; listener={p['listener_state']}; cleanup={p['cleanup']}"
            )
            if p.get("listener_skipped"):
                lines.append("  Listener inspection skipped: " + p["listener_skip_reason"])
            if verbose:
                lines.append(
                    f"  Execution: {p['execution_id']}; startup deadline={p['startup_timeout']}s; execution deadline={p['execution_timeout']}s"
                )
                for step in p["trace"]:
                    details = [f"{step['elapsed_ms']}ms"]
                    if step["exit_code"] is not None:
                        details.append(f"exit={step['exit_code']}")
                    if step["error_type"]:
                        details.append(f"error={step['error_type']}")
                    if step["timeout_kind"]:
                        details.append(f"timeout={step['timeout_kind']}")
                    if step["recovered"]:
                        details.append("completed result recovered")
                    if step["cleanup"]:
                        details.append(f"cleanup={step['cleanup']}")
                    lines.append(
                        f"    {step['role']}.{step['stage']}: {step['state']} ({'; '.join(details)})"
                    )
                    if step["helper_configuration"]:
                        lines.append(
                            "      Helper configuration: "
                            + json.dumps(step["helper_configuration"], sort_keys=True)
                        )
                    if step["stderr"]:
                        lines.append("      " + step["stderr"])
    if verbose and report.get("timings"):
        lines += ["", "STAGE TIMINGS", "  Role         Stage                    Total ms   Calls"]
        for step in report["timings"]["stages"]:
            lines.append(
                f"  {step['role']:<12} {step['stage']:<24} {step['total_ms']:>9.3f} {step['count']:>7}"
            )
    lines += ["", "No application configuration was modified."]
    if report["probe_requested"]:
        lines.append(
            "Opt-in helper probes may create temporary containers; cleanup failures are reported."
        )
    else:
        lines.append("Read-only metadata inspection. Use --probe for active verification.")
    return "\n".join(lines) + "\n"
