"""Run isolated Compose fault fixtures and retain every diagnostic attempt.

Example: python scripts/benchmark_accuracy.py --runs 10 --allow-fixed-ports

This suite is independent of the six starter fixtures and their benchmark file.
It uses only local images, freezes each normalized Compose file before startup,
and removes only resources bearing the fresh project it created.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from dockroute import __version__  # noqa: E402
from dockroute.benchmark import FixtureSafetyError, validate_fixture  # noqa: E402
from dockroute.docker import DockerUnavailable, connect  # noqa: E402

ROOT_CAUSE_CODES = frozenset(
    {
        "NETWORK_ISOLATION",
        "WRONG_LOCALHOST",
        "HOST_PORT_INSTEAD_OF_CONTAINER_PORT",
        "LOOPBACK_ONLY_LISTENER",
        "INVALID_SERVICE_HOSTNAME",
        "SERVICE_UNHEALTHY",
    }
)
TRACKS = ("automatic_static", "automatic_active", "manual_check")
FIXTURE_IMAGE = (
    "python:3.12-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4"
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 3) if values else None


def compute_metrics(attempts: list[dict]) -> dict:
    """Count failed and missing executions in recall/coverage denominators."""
    result: dict[str, Any] = {
        "attempts": len(attempts),
        "behavior_validation_coverage": (
            sum(a.get("behavior_validated") is True for a in attempts) / len(attempts)
            if attempts
            else None
        ),
        "cleanup_coverage": (
            sum(a.get("cleanup") == "complete" for a in attempts) / len(attempts)
            if attempts
            else None
        ),
        "failure_classes": {},
    }
    for attempt in attempts:
        failure = attempt.get("failure_classification")
        if failure:
            result["failure_classes"][failure] = result["failure_classes"].get(failure, 0) + 1
    for name in TRACKS:
        eligible = [
            a
            for a in attempts
            if name != "manual_check"
            or a.get("expected", {}).get("manual_codes")
            or "manual_check" in a.get("tracks", {})
        ]
        if not eligible:
            result[name] = {"attempts": 0}
            continue
        tracks = [a.get("tracks", {}).get(name, {}) for a in eligible]
        root_cases = [a for a in eligible if a.get("root_cause_code") in ROOT_CAUSE_CODES]
        controls = [a for a in eligible if a.get("root_cause_code") not in ROOT_CAUSE_CODES]
        healthy_controls = [
            a for a in controls if a.get("expected", {}).get("runtime_kind") == "recovery"
        ]
        unrelated_controls = [a for a in controls if a not in healthy_controls]
        predictions = [
            (a, a.get("tracks", {}).get(name, {}).get("observed_code")) for a in eligible
        ]
        predicted_roots = [(a, code) for a, code in predictions if code in ROOT_CAUSE_CODES]
        true_roots = sum(
            a.get("behavior_validated") is True and code == a.get("root_cause_code")
            for a, code in predicted_roots
        )
        execution_times = [
            t["elapsed_ms"]
            for t in tracks
            if t.get("valid_json") and isinstance(t.get("elapsed_ms"), (int, float))
        ]

        def false_positive_rate(cases: list[dict]) -> float | None:
            valid_cases = [
                a for a in cases if a.get("tracks", {}).get(name, {}).get("valid_json") is True
            ]
            return (
                sum(
                    a.get("tracks", {}).get(name, {}).get("observed_code") in ROOT_CAUSE_CODES
                    for a in valid_cases
                )
                / len(valid_cases)
                if valid_cases
                else None
            )

        metrics = {
            "attempts": len(eligible),
            "root_cause_precision": true_roots / len(predicted_roots) if predicted_roots else None,
            "root_cause_recall": true_roots / len(root_cases) if root_cases else None,
            "root_cause_true_positives": true_roots,
            "root_cause_predictions": len(predicted_roots),
            "root_cause_cases": len(root_cases),
            "control_false_positive_rate": false_positive_rate(controls),
            "healthy_control_false_positive_rate": false_positive_rate(healthy_controls),
            "unrelated_fault_false_positive_rate": false_positive_rate(unrelated_controls),
            "control_cases": len(controls),
            "control_valid_executions": sum(
                a.get("tracks", {}).get(name, {}).get("valid_json") is True for a in controls
            ),
            "unknown_rate": sum(t.get("observed_code") == "UNKNOWN" for t in tracks)
            / len(eligible),
            "abstention_rate": sum(
                t.get("grade") == "abstained" or t.get("observed_code") in {"UNKNOWN", "NO_FINDING"}
                for t in tracks
            )
            / len(eligible),
            "execution_coverage": sum(t.get("valid_json") is True for t in tracks) / len(eligible),
            "median_wall_ms_valid_executions": _median(execution_times),
            "passed": sum(t.get("grade") == "passed" for t in tracks),
            "failed": sum(t.get("grade") == "failed" for t in tracks),
            "abstained": sum(t.get("grade") == "abstained" for t in tracks),
            "execution_failures": sum(t.get("grade") == "execution_failure" for t in tracks),
        }
        if name != "manual_check":
            metrics["automatic_discovery_recall"] = sum(
                t.get("target_discovered") is True for t in tracks
            ) / len(eligible)
        if name == "automatic_active":
            metrics["probe_cleanup_coverage"] = sum(
                t.get("probe_cleanup") in {"complete", "not_needed"} for t in tracks
            ) / len(eligible)
        result[name] = metrics
    return result


def grade_track(expected: dict, name: str, track: dict, behavior: dict) -> str:
    if not track.get("valid_json"):
        return "execution_failure"
    key = {
        "automatic_static": "static",
        "automatic_active": "active",
        "manual_check": "manual",
    }[name]
    codes = expected.get(key + "_codes", [])
    observed = track.get("observed_code")
    expected_exit = expected.get("expected_exit", {}).get(key, [])
    expected_exit = expected_exit if isinstance(expected_exit, list) else [expected_exit]
    if expected.get("runtime_kind") in {"http_error", "recovery"} and key != "static":
        if observed != "TCP_REACHABLE":
            return "failed"
    if observed not in codes or track.get("exit_code") not in expected_exit:
        return "abstained" if observed in expected.get("accepted_uncertainty", []) else "failed"
    required = expected.get(
        key + "_required_evidence",
        [] if observed == "UNKNOWN" else expected.get("required_evidence", []),
    )
    evidence = set(track.get("evidence_kinds", [])) | {
        x.get("kind") for x in track.get("observations", [])
    }
    if not set(required) <= evidence:
        return "failed"
    if expected.get("runtime_kind") == "http_error" and key != "static":
        if (
            behavior.get("source_tcp") != "ok"
            or behavior.get("http_status") != expected.get("http_status")
            or observed != "TCP_REACHABLE"
            or track.get("status") != "REACHABLE"
            or "Application protocol readiness was not tested" not in track.get("explanation", "")
        ):
            return "failed"
    return "abstained" if observed == "UNKNOWN" else "passed"


def _save(run_dir: Path, stem: str, stdout: str, stderr: str) -> dict:
    out, err = run_dir / f"{stem}.stdout", run_dir / f"{stem}.stderr"
    out.write_text(stdout, encoding="utf-8")
    err.write_text(stderr, encoding="utf-8")
    return {
        "stdout": out.relative_to(ROOT).as_posix(),
        "stderr": err.relative_to(ROOT).as_posix(),
        "stdout_sha256": _sha(out),
        "stderr_sha256": _sha(err),
    }


def _command(argv: list[str], run_dir: Path, stem: str, *, timeout: float = 180) -> dict:
    began = time.monotonic()
    try:
        completed = subprocess.run(
            argv, text=True, capture_output=True, timeout=timeout, check=False
        )
        stdout, stderr = completed.stdout, completed.stderr
        code, timed_out = completed.returncode, False
    except subprocess.TimeoutExpired as error:
        stdout = (
            error.stdout.decode(errors="replace")
            if isinstance(error.stdout, bytes)
            else error.stdout or ""
        )
        stderr = (
            error.stderr.decode(errors="replace")
            if isinstance(error.stderr, bytes)
            else error.stderr or ""
        )
        code, timed_out = None, True
    except OSError:
        stdout, stderr, code, timed_out = "", "", None, False
    return {
        "argv": argv,
        "exit_code": code,
        "timed_out": timed_out,
        "elapsed_ms": round((time.monotonic() - began) * 1000, 3),
        "raw": _save(run_dir, stem, stdout, stderr),
        "stdout_text": stdout,
    }


def _track_command(argv: list[str], run_dir: Path, stem: str, expected: dict) -> dict:
    raw = _command(argv, run_dir, stem)
    result = {k: v for k, v in raw.items() if k != "stdout_text"}
    try:
        report = json.loads(raw["stdout_text"])
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise ValueError
        matching = [
            f
            for f in report["findings"]
            if f.get("source") == expected["source_service"]
            and f.get("destination") == expected["target_host"]
            and f.get("port") == expected["target_port"]
        ]
        result["valid_json"] = True
        result["schema_version"] = report.get("schema_version")
        result["dockroute_version"] = report.get("dockroute_version")
        result["configuration_modified"] = report.get("configuration_modified")
        result["target_discovered"] = bool(matching)
        result["all_codes"] = [f.get("code") for f in report["findings"]]
        if len(matching) == 1:
            finding = matching[0]
            result.update(
                observed_code=finding.get("code"),
                status=finding.get("status"),
                confidence=finding.get("confidence"),
                verification=finding.get("verification"),
                explanation=finding.get("explanation", ""),
                observations=finding.get("observations", []),
                evidence_kinds=[e.get("kind") for e in finding.get("intention_evidence", [])],
                probe_state=(finding.get("probe") or {}).get("state"),
                probe_cleanup=(finding.get("probe") or {}).get("cleanup"),
            )
        else:
            result["observed_code"] = "AMBIGUOUS_RESULT" if matching else "NO_FINDING"
    except (ValueError, TypeError, KeyError):
        result.update(valid_json=False, observed_code="NO_VALID_REPORT")
    return result


def _cli_identity(binary: Path | None, run_dir: Path) -> dict:
    """Measure the tested CLI's version; the evaluator version is separate."""
    prefix = [str(binary)] if binary else [sys.executable, "-m", "dockroute"]
    try:
        digest = _sha(binary) if binary else None
        command = _command([*prefix, "--version"], run_dir, "cli-version", timeout=30)
    except OSError:
        return {"verified": False, "version": None, "binary_sha256": None}
    match = re.fullmatch(
        r"DockRoute ([0-9]+\.[0-9]+\.[0-9]+(?:[.+-][A-Za-z0-9.-]+)?)",
        command["stdout_text"].strip(),
    )
    return {
        "verified": command["exit_code"] == 0 and match is not None,
        "version": match.group(1) if match else None,
        "binary_sha256": digest,
        "command": {k: v for k, v in command.items() if k != "stdout_text"},
    }


_OBSERVER = r"""
import json,os,signal,socket,sys,urllib.error,urllib.request
from urllib.parse import urlsplit
def expire(*args): raise TimeoutError()
signal.signal(signal.SIGALRM,expire); signal.alarm(7)
uri=sys.argv[1]
u=urlsplit(uri); port=u.port or (443 if u.scheme=='https' else 80)
r={'source_dns':'unknown','source_tcp':'unknown','http_status':None}
try:
 socket.getaddrinfo(u.hostname,port,type=socket.SOCK_STREAM); r['source_dns']='ok'
except socket.gaierror: r['source_dns']='failed'
except TimeoutError: r['source_dns']='timeout'
try:
 with socket.create_connection((u.hostname,port),timeout=1): pass
 r['source_tcp']='ok'
except ConnectionRefusedError: r['source_tcp']='refused'
except TimeoutError: r['source_tcp']='timeout'
except OSError: r['source_tcp']='failed'
try:
 with urllib.request.urlopen(uri,timeout=1) as response: r['http_status']=response.status
except urllib.error.HTTPError as error: r['http_status']=error.code
except Exception: pass
print(json.dumps(r),flush=True)
"""


def _observe(source, uri: str) -> dict:
    try:
        result = source.exec_run(["python", "-I", "-c", _OBSERVER, uri])
        if result.exit_code or len(result.output) > 8192:
            return {"observer_status": "failed"}
        value = json.loads(result.output)
        return value if isinstance(value, dict) else {"observer_status": "invalid"}
    except Exception:
        return {"observer_status": "unavailable"}


def _containers(inspector, project: str) -> dict:
    return {c.service: c for c in inspector.snapshot(project)}


def _await(inspector, project: str, expected: dict, *, deadline: float = 35) -> dict:
    until = time.monotonic() + deadline
    last: dict = {}
    while time.monotonic() < until:
        try:
            last = _containers(inspector, project)
        except DockerUnavailable:
            time.sleep(0.5)
            continue
        source, dest = (
            last.get(expected["source_service"]),
            last.get(expected["destination_service"]),
        )
        kind = expected["runtime_kind"]
        if source and dest:
            if kind == "source_restart" and source.restart_count >= 2 and dest.state == "running":
                return last
            if (
                kind == "destination_restart"
                and dest.restart_count >= 2
                and source.state == "running"
            ):
                return last
            if (
                kind not in {"source_restart", "destination_restart"}
                and source.state == dest.state == "running"
                and dest.health not in {"starting", "unhealthy"}
            ):
                return last
        time.sleep(0.5)
    return last


def _behavior(inspector, project: str, expected: dict, containers: dict) -> tuple[dict, bool]:
    source, dest = (
        containers.get(expected["source_service"]),
        containers.get(expected["destination_service"]),
    )
    if not source or not dest:
        return {"observer_status": "service_missing"}, False
    kind = expected["runtime_kind"]
    facts: dict = {
        "source_state": source.state,
        "source_restarts": source.restart_count,
        "destination_state": dest.state,
        "destination_restarts": dest.restart_count,
    }
    if kind == "source_restart":
        return facts, source.restart_count >= 2 and dest.state == "running"
    if kind == "destination_restart":
        return facts, dest.restart_count >= 2 and source.state == "running"
    if source.state != "running" or dest.state != "running":
        return facts, False
    source_container = inspector.client.containers.get(source.id)
    uri = f"http://{expected['target_host']}:{expected['target_port']}/"
    samples = []
    for number in range(3):
        sample = _observe(source_container, uri)
        if kind == "missing_hostname":
            sample["reference"] = _observe(source_container, "http://api:8000/")
            valid = (
                sample.get("source_dns") == "failed"
                and sample["reference"].get("source_tcp") == "ok"
            )
        elif kind in {"wrong_port", "host_port_confusion"}:
            sample["reference"] = _observe(source_container, "http://api:8000/")
            mapping = any(
                p.host == expected["target_port"] and p.container == 8000 for p in dest.ports
            )
            sample["port_mapping_match"] = mapping
            valid = (
                sample.get("source_tcp") == "refused"
                and sample["reference"].get("source_tcp") == "ok"
                and (kind != "host_port_confusion" or mapping)
            )
        elif kind == "http_error":
            valid = (
                sample.get("source_tcp") == "ok"
                and sample.get("http_status") == expected["http_status"]
            )
        else:
            valid = sample.get("source_tcp") == "ok" and sample.get("http_status") == 200
        samples.append(sample)
        if valid:
            facts.update(sample)
            facts["observer_samples"] = samples
            return facts, True
        if number < 2:
            time.sleep(0.5)
    facts.update(samples[-1])
    facts["observer_samples"] = samples
    return facts, False


def _cli_argv(project: str, name: str, expected: dict, *, binary: Path | None = None) -> list[str]:
    prefix = [str(binary)] if binary else [sys.executable, "-m", "dockroute"]
    if name == "manual_check":
        return [
            *prefix,
            "check",
            expected["source_service"],
            f"{expected['target_host']}:{expected['target_port']}",
            "--project",
            project,
            "--format",
            "json",
            "--probe",
        ]
    return [
        *prefix,
        "doctor",
        "--project",
        project,
        "--format",
        "json",
        *(["--probe"] if name == "automatic_active" else []),
    ]


def _remove_during_probe_once(
    inspector, project: str, expected: dict, argv: list[str], run_dir: Path, trial: int
) -> tuple[dict, bool]:
    """After a source helper is leased, remove only the verified owned source."""
    control = run_dir / f"probe-control-{trial}"
    control.mkdir()
    command = [*argv, "--_benchmark-control", str(control)]
    began = time.monotonic()
    try:
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError:
        return {"valid_json": False, "observed_code": "NO_VALID_REPORT", "elapsed_ms": 0}, False
    injected = False
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline and child.poll() is None:
        lease_path = control / "lease.json"
        try:
            lease = json.loads(lease_path.read_text(encoding="utf-8"))
            if lease.get("project") == project and lease.get("helpers"):
                source = _containers(inspector, project).get(expected["source_service"])
                if source is None:
                    break
                live = inspector.client.containers.get(source.id)
                labels = (live.attrs.get("Config") or {}).get("Labels") or {}
                if (
                    labels.get("com.docker.compose.project") != project
                    or labels.get("com.docker.compose.service") != expected["source_service"]
                ):
                    break
                live.remove(force=True)
                injected = True
                break
        except (OSError, ValueError, json.JSONDecodeError, DockerUnavailable):
            pass
        time.sleep(0.02)
    try:
        stdout, stderr = child.communicate(timeout=150)
    except subprocess.TimeoutExpired:
        child.kill()
        stdout, stderr = child.communicate(timeout=10)
    raw = _save(run_dir, f"automatic_active-trial-{trial}", stdout, stderr)
    duration = round((time.monotonic() - began) * 1000, 3)
    try:
        report = json.loads(stdout)
        matching = [
            finding
            for finding in report.get("findings", [])
            if finding.get("source") == expected["source_service"]
            and finding.get("destination") == expected["target_host"]
            and finding.get("port") == expected["target_port"]
        ]
        if len(matching) != 1:
            raise ValueError
        finding = matching[0]
        track = {
            "argv": command,
            "exit_code": child.returncode,
            "elapsed_ms": duration,
            "raw": raw,
            "valid_json": True,
            "target_discovered": True,
            "observed_code": finding.get("code"),
            "status": finding.get("status"),
            "confidence": finding.get("confidence"),
            "verification": finding.get("verification"),
            "explanation": finding.get("explanation", ""),
            "observations": finding.get("observations", []),
            "evidence_kinds": [e.get("kind") for e in finding.get("intention_evidence", [])],
            "probe_state": (finding.get("probe") or {}).get("state"),
            "probe_cleanup": (finding.get("probe") or {}).get("cleanup"),
            "configuration_modified": report.get("configuration_modified"),
        }
    except (ValueError, TypeError, KeyError):
        track = {
            "argv": command,
            "exit_code": child.returncode,
            "elapsed_ms": duration,
            "raw": raw,
            "valid_json": False,
            "observed_code": "NO_VALID_REPORT",
        }
    return track, injected


def _remove_during_probe(
    inspector, project: str, expected: dict, argv: list[str], run_dir: Path
) -> tuple[dict, bool]:
    """Retry a pre-lease helper failure, retaining every attempted injection."""
    trials = []
    for number in range(1, 4):
        track, injected = _remove_during_probe_once(
            inspector, project, expected, argv, run_dir, number
        )
        trials.append(
            {
                "trial": number,
                "injected": injected,
                "probe_state": track.get("probe_state"),
                "valid_json": track.get("valid_json"),
                "raw": track.get("raw"),
            }
        )
        if injected or track.get("probe_state") not in {
            "HELPER_EXECUTION_FAILED",
            "HELPER_START_FAILED",
        }:
            break
        if track.get("probe_cleanup") not in {None, "complete", "not_needed"}:
            break
    track["injection_trials"] = trials
    return track, injected


def _owned_counts(inspector, project: str) -> dict:
    api = inspector.client.api
    try:
        return {
            "containers": len(
                api.containers(all=True, filters={"label": f"com.docker.compose.project={project}"})
            ),
            "helpers": len(
                api.containers(all=True, filters={"label": f"io.dockroute.project={project}"})
            ),
            "networks": len(
                api.networks(filters={"label": f"com.docker.compose.project={project}"})
            ),
        }
    except Exception:
        return {"inspection_unavailable": True}


def _cleanup(inspector, project: str, compose: list[str], run_dir: Path) -> tuple[str, dict]:
    command = _command([*compose, "down", "--timeout", "5"], run_dir, "compose-down", timeout=45)
    remaining = _owned_counts(inspector, project)
    empty = remaining == {
        "containers": 0,
        "helpers": 0,
        "networks": 0,
    }
    return ("complete" if empty else "failed"), {
        "command": {k: v for k, v in command.items() if k != "stdout_text"},
        "remaining_owned_resources": remaining,
        "command_completed_successfully": command["exit_code"] == 0,
    }


def _fingerprint(inspector, identifiers: list[str]) -> dict:
    """Hash immutable Docker configuration without serializing environment data."""
    output: dict[str, str | None] = {}
    for identifier in identifiers:
        try:
            attrs = inspector.client.api.inspect_container(identifier)
            stable = {key: attrs.get(key) for key in ("Config", "HostConfig")}
            output[identifier] = hashlib.sha256(
                json.dumps(stable, sort_keys=True, default=str).encode()
            ).hexdigest()
        except Exception:
            output[identifier] = None
    return output


def _source_revision() -> dict:
    paths = [
        *(
            path.relative_to(ROOT).as_posix()
            for path in sorted((ROOT / "src/dockroute").rglob("*.py"))
        ),
        "scripts/benchmark_accuracy.py",
        "pyproject.toml",
    ]
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        revision, status = "unknown", ""
    return {
        "git_revision": revision or "unknown",
        "dirty": bool(status),
        "source_files_sha256": {path: _sha(ROOT / path) for path in paths},
    }


def run_attempt(
    inspector,
    scenario: Path,
    expected: dict,
    number: int,
    raw_root: Path,
    *,
    binary: Path | None,
    allow_fixed_ports: bool,
) -> dict:
    project = "dra-" + uuid.uuid4().hex[:12]
    run_dir = raw_root / scenario.name / f"run-{number:02d}-{project}"
    run_dir.mkdir(parents=True, exist_ok=False)
    result: dict = {
        "scenario": scenario.name,
        "run": number,
        "project": project,
        "ground_truth_fault": expected["ground_truth_fault"],
        "root_cause_code": expected.get("root_cause_code"),
        "expected": expected,
        "behavior_validated": False,
        "failure_classification": None,
        "status": "failed",
        "cleanup": "not_needed",
        "tracks": {},
        "raw_directory": run_dir.relative_to(ROOT).as_posix(),
        "definition_sha256": {
            "compose": _sha(scenario / "compose.yaml"),
            "expected": _sha(scenario / "expected.yaml"),
        },
    }
    original = ["docker", "compose", "-p", project, "-f", str(scenario / "compose.yaml")]
    normalized = _command(
        [*original, "config", "--format", "json"], run_dir, "compose-config", timeout=30
    )
    result["normalization"] = {k: v for k, v in normalized.items() if k != "stdout_text"}
    if normalized["exit_code"] != 0:
        result["failure_classification"] = "compose_parse_or_interpolation_failure"
        return result
    try:
        config = json.loads(normalized["stdout_text"])
        validate_fixture(config, allow_fixed_ports=allow_fixed_ports, project=project)
        if any(
            service.get("image") != FIXTURE_IMAGE for service in config.get("services", {}).values()
        ):
            raise FixtureSafetyError("accuracy fixtures must use the pinned image")
    except (ValueError, TypeError, KeyError, FixtureSafetyError):
        result["failure_classification"] = "unsafe_or_invalid_fixture"
        return result
    frozen = run_dir / "compose.normalized.json"
    frozen.write_text(json.dumps(config), encoding="utf-8")
    result["normalized_config_sha256"] = _sha(frozen)
    compose = ["docker", "compose", "-p", project, "-f", str(frozen)]
    preexisting = _owned_counts(inspector, project)
    if preexisting != {"containers": 0, "helpers": 0, "networks": 0}:
        result["failure_classification"] = "project_collision_or_inspection_failure"
        return result
    result["cleanup"] = "pending"
    try:
        startup = _command(
            [*compose, "up", "-d", "--pull", "never", "--no-build"],
            run_dir,
            "compose-up",
            timeout=120,
        )
        result["startup"] = {k: v for k, v in startup.items() if k != "stdout_text"}
        if startup["exit_code"] != 0:
            result["failure_classification"] = "compose_start_failure"
            return result
        containers = _await(inspector, project, expected)
        result["initial_service_states"] = {
            service: {"state": c.state, "health": c.health, "restarts": c.restart_count}
            for service, c in containers.items()
        }
        behavior, valid = _behavior(inspector, project, expected, containers)
        result["runtime_observation"] = behavior
        result["behavior_validated"] = valid
        if not valid:
            result["failure_classification"] = "fixture_behavior_mismatch"
            return result
        identifiers = [c.id for c in containers.values()]
        before = _fingerprint(inspector, identifiers)
        static = _track_command(
            _cli_argv(project, "automatic_static", expected, binary=binary),
            run_dir,
            "automatic_static",
            expected,
        )
        result["tracks"]["automatic_static"] = static
        if expected["runtime_kind"] == "recovery":
            old_start = containers[expected["destination_service"]].started_at
            restarted = _command(
                [*compose, "restart", expected["destination_service"]],
                run_dir,
                "compose-restart",
                timeout=45,
            )
            result["restart_command"] = {k: v for k, v in restarted.items() if k != "stdout_text"}
            recovered = _await(inspector, project, expected)
            after_start = recovered.get(expected["destination_service"])
            recovery_behavior, recovery_valid = _behavior(inspector, project, expected, recovered)
            result["recovery_observation"] = recovery_behavior
            result["behavior_validated"] = bool(
                restarted["exit_code"] == 0
                and recovery_valid
                and after_start
                and after_start.started_at != old_start
            )
            if not result["behavior_validated"]:
                result["failure_classification"] = "recovery_not_validated"
                return result
        active_argv = _cli_argv(project, "automatic_active", expected, binary=binary)
        if expected["runtime_kind"] == "disappearing_source":
            active, injected = _remove_during_probe(
                inspector, project, expected, active_argv, run_dir
            )
            result["race_injection_confirmed"] = injected
            result["behavior_validated"] = injected
            if not injected:
                result["failure_classification"] = "race_injection_not_observed"
        else:
            active = _track_command(active_argv, run_dir, "automatic_active", expected)
        result["tracks"]["automatic_active"] = active
        if expected.get("manual_codes"):
            result["tracks"]["manual_check"] = _track_command(
                _cli_argv(project, "manual_check", expected, binary=binary),
                run_dir,
                "manual_check",
                expected,
            )
        after = _fingerprint(inspector, identifiers)
        result["configuration_unchanged"] = all(
            before[key] == value and value is not None
            for key, value in after.items()
            if not (expected["runtime_kind"] == "disappearing_source" and value is None)
        )
        for name, track in result["tracks"].items():
            track["grade"] = grade_track(
                expected, name, track, result.get("recovery_observation", behavior)
            )
        if result["failure_classification"] is None:
            if any(
                t["grade"] in {"failed", "execution_failure"} for t in result["tracks"].values()
            ):
                result["failure_classification"] = "diagnostic_mismatch_or_execution_failure"
            elif expected.get("root_cause_code") and any(
                t["grade"] == "abstained" for t in result["tracks"].values()
            ):
                result["failure_classification"] = "root_cause_abstention"
        result["status"] = (
            "passed"
            if result["failure_classification"] is None and result["configuration_unchanged"]
            else "failed"
        )
        if not result["configuration_unchanged"] and result["failure_classification"] is None:
            result["failure_classification"] = "configuration_changed"
        return result
    except Exception as error:
        result["failure_classification"] = "runner_exception"
        result["runner_exception_type"] = type(error).__name__
        return result
    finally:
        result["cleanup"], result["cleanup_details"] = _cleanup(
            inspector, project, compose, run_dir
        )
        if result["cleanup"] != "complete":
            result["status"] = "failed"
            result["failure_classification"] = "owned_resource_cleanup_failure"
        elif not result["cleanup_details"]["command_completed_successfully"]:
            result["status"] = "failed"
            result["failure_classification"] = (
                result["failure_classification"] or "cleanup_command_timeout_or_error"
            )


def _write_report(path: Path, report: dict) -> None:
    report["metrics"] = compute_metrics(report["attempts"])
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _load_scenarios(root: Path, requested: str | None) -> list[tuple[Path, dict]]:
    scenarios = []
    for path in sorted(root.glob("*/expected.yaml")):
        if requested and path.parent.name != requested:
            continue
        compose = path.parent / "compose.yaml"
        if not compose.is_file():
            continue
        expected = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(expected, dict) or expected.get("scenario") != path.parent.name:
            raise ValueError("Scenario definition does not match its directory")
        required = {
            "ground_truth_fault",
            "runtime_kind",
            "source_service",
            "destination_service",
            "target_host",
            "target_port",
            "static_codes",
            "active_codes",
            "expected_exit",
            "required_evidence",
            "cleanup",
        }
        if not required <= expected.keys():
            raise ValueError("Scenario definition is incomplete")
        scenarios.append((path.parent, expected))
    if not scenarios:
        raise ValueError("No selected accuracy scenarios found")
    return scenarios


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenarios", type=Path, default=ROOT / "scenarios-accuracy")
    parser.add_argument("--scenario", help="Run exactly one scenario directory")
    parser.add_argument(
        "--runs", type=int, default=10, help="Repetitions per scenario (default: 10)"
    )
    parser.add_argument("--allow-fixed-ports", action="store_true")
    parser.add_argument("--binary", type=Path, help="Optional tested DockRoute executable")
    parser.add_argument(
        "--output", type=Path, help="New report filename; existing files are refused"
    )
    args = parser.parse_args(argv)
    if not 1 <= args.runs <= 100:
        parser.error("--runs must be between 1 and 100")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    output = args.output or ROOT / "outputs" / f"accuracy-benchmark-{run_id}.json"
    output = output.resolve()
    if output.exists():
        parser.error("--output already exists; choose a new path to preserve prior evidence")
    raw_root = ROOT / "work" / "accuracy-raw" / run_id
    raw_root.mkdir(parents=True, exist_ok=False)
    try:
        scenarios = _load_scenarios(args.scenarios, args.scenario)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    report: dict = {
        "schema_version": "dockroute.accuracy-benchmark/1.0",
        "suite": "expanded-compose-diagnostic-accuracy",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "host": platform.platform(),
        "source": _source_revision(),
        "versions": {"dockroute": None, "evaluator": __version__, "docker": None, "compose": None},
        "exact_invocation": [
            sys.executable,
            str(Path(__file__).resolve()),
            *(argv if argv is not None else sys.argv[1:]),
        ],
        "scenario_definitions": [
            {
                "scenario": path.name,
                "expected": expected,
                "compose_sha256": _sha(path / "compose.yaml"),
                "expected_sha256": _sha(path / "expected.yaml"),
            }
            for path, expected in scenarios
        ],
        "historical_six_results_preserved_separately": "outputs/benchmark.json",
        "raw_root": raw_root.relative_to(ROOT).as_posix(),
        "attempts": [],
        "status": "running",
    }
    report["tested_cli"] = _cli_identity(args.binary.resolve() if args.binary else None, raw_root)
    report["versions"]["dockroute"] = report["tested_cli"]["version"]
    if not report["tested_cli"]["verified"]:
        report["status"] = "failed"
        report["prerequisite_failure"] = "cli_identity_failure"
        _write_report(output, report)
        return 1
    version = _command(
        ["docker", "compose", "version", "--short"], raw_root, "compose-version", timeout=15
    )
    report["compose_version_command"] = {k: v for k, v in version.items() if k != "stdout_text"}
    if version["exit_code"] == 0:
        report["versions"]["compose"] = version["stdout_text"].strip()
    inspector = None
    try:
        inspector = connect(timeout=10)
        report["versions"]["docker"] = inspector.version().get("Version")
        if not report["versions"]["compose"]:
            raise DockerUnavailable("Docker Compose CLI is unavailable")
        try:
            image = inspector.client.images.get(FIXTURE_IMAGE)
            report["fixture_image"] = {"reference": FIXTURE_IMAGE, "image_id": image.id}
        except Exception:
            report["image_prerequisite"] = (
                "pinned Python fixture image is unavailable locally; no pull attempted"
            )
            raise DockerUnavailable("Fixture image unavailable locally") from None
        for scenario, expected in scenarios:
            for number in range(1, args.runs + 1):
                print(f"{scenario.name} run {number}/{args.runs}", flush=True)
                attempt = run_attempt(
                    inspector,
                    scenario,
                    expected,
                    number,
                    raw_root,
                    binary=args.binary.resolve() if args.binary else None,
                    allow_fixed_ports=args.allow_fixed_ports,
                )
                report["attempts"].append(attempt)
                _write_report(output, report)
        report["status"] = (
            "passed" if all(a["status"] == "passed" for a in report["attempts"]) else "failed"
        )
    except DockerUnavailable:
        report["status"] = "unverified"
        for scenario, expected in scenarios:
            for number in range(1, args.runs + 1):
                report["attempts"].append(
                    {
                        "scenario": scenario.name,
                        "run": number,
                        "expected": expected,
                        "root_cause_code": expected.get("root_cause_code"),
                        "behavior_validated": False,
                        "cleanup": "not_needed",
                        "tracks": {},
                        "status": "unverified",
                        "failure_classification": "docker_unavailable_or_image_missing",
                    }
                )
    except KeyboardInterrupt:
        report["status"] = "cancelled"
    finally:
        if inspector:
            inspector.close()
        _write_report(output, report)
        print(f"Accuracy report: {output} ({report['status']})", flush=True)
    return 0 if report["status"] == "passed" else 3 if report["status"] == "unverified" else 1


if __name__ == "__main__":
    raise SystemExit(main())
