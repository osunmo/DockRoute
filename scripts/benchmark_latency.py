"""Measure one settled scenario06 project with interleaved, sequential attempts.

Example (before streaming is implemented):
    python scripts/benchmark_latency.py --conditions poll,poll-unlimited,floor

Each invocation produces one scheduling dataset. ``--schedule conditional`` skips
unnecessary destination helpers; benchmark attempts themselves never overlap. Reports
retain every sanitized sample, including failures and discarded warm-ups.
"""

import argparse
import hashlib
import json
import math
import os
import re
import stat
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Allow direct execution from a checkout without installing the package.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from docker.errors import DockerException, NotFound  # noqa: E402

from dockroute import __version__  # noqa: E402
from dockroute.benchmark import (  # noqa: E402
    FixtureSafetyError,
    _observe,
    validate_behavior,
    validate_fixture,
)
from dockroute.docker import DockerUnavailable, connect  # noqa: E402

CONDITIONS = ("poll", "stream", "poll-unlimited", "floor")
AVAILABLE_CONDITIONS = ("poll", "poll-unlimited", "floor")
READY_METRICS = ("host_ready_ms", "vm_startup_ms", "observation_overhead_ms")
IMAGE = "python:3.12-alpine"
OWNER_LABEL = "io.dockroute.latency.owner"
ROLES = {"source", "destination", "host", "project"}
STAGES = {
    "image_availability",
    "worker_script",
    "namespace",
    "resolver_snapshot",
    "create",
    "attach",
    "start",
    "worker_startup",
    "execution",
    "logs",
    "result_parsing",
    "cleanup",
    "ready_inspection",
    "exit_inspection",
    "listener_inspection",
    "listener_skipped",
    "engine_prerequisite",
    "timing_inspect",
    "inspection",
    "benchmark_control",
}
WORKER_METRICS = {
    "import_ms",
    "ready_ms",
    "wall_ts",
    "execution_ms",
    "dns_ms",
    "tcp_ms",
    "host_ready_ms",
    "vm_startup_ms",
    "observation_overhead_ms",
    "polls",
    "empty_polls",
    "reloads",
    "http_requests",
}
REQUEST_PATHS = {
    "/_ping",
    "/version",
    "/info",
    "/containers/json",
    "/containers/create",
    "/containers/{id}",
    "/containers/{id}/json",
    "/containers/{id}/start",
    "/containers/{id}/logs",
    "/containers/{id}/attach",
    "/containers/{id}/wait",
    "/containers/{id}/stop",
    "/containers/{id}/kill",
    "/containers/{id}/archive",
    "/images/{id}/json",
    "/images/{image}/json",
    "/networks/{id}",
    "/networks",
    "/images/json",
    "/other",
}
BOUNDARY_ERRORS = (OSError, ValueError, RuntimeError, subprocess.SubprocessError, DockerException)


def _command(arguments, *, timeout=180, env=None):
    return subprocess.run(
        arguments, capture_output=True, text=True, timeout=timeout, env=env, check=False
    )


def _seconds(text):
    value = float(text)
    if not math.isfinite(value) or not 0.1 <= value <= 60:
        raise argparse.ArgumentTypeError("deadline must be between 0.1 and 60 seconds")
    return value


def _nonnegative_seconds(text):
    value = float(text)
    if not math.isfinite(value) or not 0 <= value <= 60:
        raise argparse.ArgumentTypeError("settle duration must be between 0 and 60 seconds")
    return value


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--conditions",
        default=",".join(AVAILABLE_CONDITIONS),
        help="CSV subset: poll,poll-unlimited,floor; streaming was not enabled by the measured gate",
    )
    parser.add_argument(
        "--runs", type=int, default=20, help="Measured rounds per condition (at least 20)"
    )
    parser.add_argument(
        "--warmups", type=int, default=3, help="Discarded rounds per condition (at least 3)"
    )
    parser.add_argument(
        "--binary", type=Path, help="Measure this executable instead of the source CLI"
    )
    parser.add_argument("--schedule", choices=("sequential", "conditional"), default="conditional")
    parser.add_argument("--startup-timeout", type=_seconds, default=15.0)
    parser.add_argument("--api-timeout", type=_seconds, default=5.0)
    parser.add_argument("--timeout", type=_seconds, default=5.0)
    parser.add_argument(
        "--dns-timeout",
        type=_seconds,
        default=None,
        help="Optional newer CLI deadline; omitted in the initial instrumentation experiment",
    )
    parser.add_argument("--connect-timeout", type=_seconds, default=None)
    parser.add_argument("--health-timeout", type=_seconds, default=60.0)
    parser.add_argument(
        "--settle-seconds",
        type=_nonnegative_seconds,
        default=3.0,
        help="Continuously healthy settling interval before attempts",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "benchmarks"
        / ("latency-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"),
    )
    args = parser.parse_args(argv)
    args.conditions = tuple(part.strip() for part in args.conditions.split(","))
    if (
        not args.conditions
        or len(set(args.conditions)) != len(args.conditions)
        or any(c not in CONDITIONS for c in args.conditions)
    ):
        parser.error(
            "conditions must be a nonempty, unique subset of poll,stream,poll-unlimited,floor"
        )
    if args.runs < 20 or args.warmups < 3:
        parser.error("use at least 20 measured rounds and 3 discarded warm-up rounds")
    if "stream" in args.conditions:
        parser.error("stream observation is unavailable; the measured streaming gate was not met")
    if args.dns_timeout is not None and args.dns_timeout > args.timeout:
        parser.error("DNS deadline cannot exceed the execution deadline")
    if args.connect_timeout is not None and args.connect_timeout > args.timeout:
        parser.error("connect deadline cannot exceed the execution deadline")
    return args


def condition_order(conditions, rounds):
    """Rotate the first condition each round to balance drift and order effects."""
    for round_index in range(rounds):
        offset = round_index % len(conditions)
        for condition in (*conditions[offset:], *conditions[:offset]):
            yield round_index, condition


def _number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def distribution(values):
    values = sorted(values)
    if not values or any(not _number(value) for value in values):
        raise ValueError("a distribution requires finite nonnegative samples")

    def quantile(fraction):
        position = (len(values) - 1) * fraction
        lower = math.floor(position)
        upper = math.ceil(position)
        return values[lower] + (values[upper] - values[lower]) * (position - lower)

    summary = {
        "n": len(values),
        "median": statistics.median(values),
        "iqr": quantile(0.75) - quantile(0.25),
        "min": values[0],
        "max": values[-1],
    }
    if len(values) >= 40:
        summary["p95"] = values[math.ceil(len(values) * 0.95) - 1]
    return summary


def summarize(samples, conditions):
    summaries = {}
    for condition in conditions:
        selected = [sample for sample in samples if sample["condition"] == condition]
        measured = [s for s in selected if not s["warmup"] and s["valid"]]
        keys = sorted({key for sample in measured for key in sample.get("metrics", {})})
        required = (
            {"wall_ms"}
            if condition == "floor"
            else {"source.worker_startup." + key for key in READY_METRICS}
        )
        required.update(
            key for sample in selected for key in sample.get("required_timing_metrics", ())
        )
        counts = {
            key: sum(_number(sample.get("metrics", {}).get(key)) for sample in measured)
            for key in sorted(required)
        }
        summaries[condition] = {
            "warmups_discarded": sum(s["warmup"] for s in selected),
            "failed": sum(not s["valid"] for s in selected),
            "measured_valid": len(measured),
            "required_metric_counts": counts,
            "timing_coverage_complete": all(count >= 20 for count in counts.values()),
            "metrics": {
                key: distribution(
                    [s["metrics"][key] for s in measured if _number(s.get("metrics", {}).get(key))]
                )
                for key in keys
                if any(_number(s.get("metrics", {}).get(key)) for s in measured)
            },
        }
    return summaries


def condition_environment(condition):
    environment = os.environ.copy()
    # A user's inherited debug override must never contaminate other conditions.
    environment.pop("DOCKROUTE_HELPER_CPUS", None)
    if condition == "poll-unlimited":
        environment["DOCKROUTE_HELPER_CPUS"] = "0"
    environment["PYTHONPATH"] = os.pathsep.join(
        filter(None, (str(ROOT / "src"), environment.get("PYTHONPATH")))
    )
    return environment


def probe_command(args, project, condition, *, control=None):
    command = [str(args.binary.resolve())] if args.binary else [sys.executable, "-m", "dockroute"]
    command.extend(
        [
            "doctor",
            "--project",
            project,
            "--probe",
            "--timing",
            "--observe",
            "stream" if condition == "stream" else "poll",
            "--schedule",
            args.schedule,
            "--format",
            "json",
            "--startup-timeout",
            str(args.startup_timeout),
            "--api-timeout",
            str(args.api_timeout),
            "--timeout",
            str(args.timeout),
        ]
    )
    for flag, value in (
        ("--dns-timeout", args.dns_timeout),
        ("--connect-timeout", args.connect_timeout),
    ):
        if value is not None:
            command.extend([flag, str(value)])
    if control is not None:
        command.extend(["--_benchmark-control", str(control)])
    return command


def extract_probe_sample(report):
    """Project reports onto timing fields; never retain bodies or arbitrary values."""
    sample: dict = {
        "valid": False,
        "error": "invalid_probe_evidence",
        "metrics": {},
        "timings": {"stages": [], "requests": [], "worker": []},
        "required_timing_metrics": ["source.worker_startup." + key for key in READY_METRICS],
        "timing_complete": False,
    }
    if not isinstance(report, dict):
        return sample
    timings = report.get("timings")
    if not isinstance(timings, dict) or not _number(timings.get("total_ms")):
        sample["error"] = "missing_or_invalid_timings"
        return sample
    sample["metrics"]["total_ms"] = timings["total_ms"]
    sample["timings"]["total_ms"] = timings["total_ms"]
    for stage in timings.get("stages", []):
        if (
            not isinstance(stage, dict)
            or stage.get("role") not in ROLES
            or stage.get("stage") not in STAGES
        ):
            continue
        if not all(_number(stage.get(key)) for key in ("count", "total_ms", "max_ms")):
            continue
        sample["timings"]["stages"].append(
            {key: stage[key] for key in ("role", "stage", "count", "total_ms", "max_ms")}
        )
        sample["metrics"][stage["role"] + "." + stage["stage"] + ".elapsed_ms"] = stage["total_ms"]
    for request in timings.get("requests", []):
        if (
            not isinstance(request, dict)
            or request.get("role") not in ROLES
            or request.get("stage") not in STAGES
        ):
            continue
        if request.get("path") not in REQUEST_PATHS or request.get("method") not in {
            "GET",
            "POST",
            "DELETE",
            "HEAD",
            "PUT",
        }:
            continue
        if all(_number(request.get(key)) for key in ("count", "total_ms", "max_ms")):
            projected = {
                key: request[key]
                for key in ("role", "stage", "method", "path", "count", "total_ms", "max_ms")
            }
            counts = request.get("status_counts")
            if isinstance(counts, dict):
                projected["status_counts"] = {
                    status: count
                    for status, count in counts.items()
                    if isinstance(status, str)
                    and re.fullmatch(r"[1-5][0-9]{2}", status)
                    and isinstance(count, int)
                    and not isinstance(count, bool)
                    and count >= 0
                }
            sample["timings"]["requests"].append(projected)
    findings = report.get("findings")
    if not isinstance(findings, list) or not findings:
        return sample
    probes = []
    for finding in findings:
        if not isinstance(finding, dict):
            return sample
        probe = finding.get("probe")
        if not isinstance(probe, dict):
            return sample
        probes.append(probe)
        execution = probe.get("execution_id")
        if isinstance(execution, str) and re.fullmatch(r"[0-9a-f]{32}", execution):
            sample.setdefault("probe_execution_ids", []).append(execution)
        for trace in probe.get("trace", []):
            if (
                not isinstance(trace, dict)
                or trace.get("role") not in ROLES
                or trace.get("stage") not in STAGES
            ):
                continue
            values = trace.get("timings")
            if not isinstance(values, dict):
                continue
            projected = {
                key: value
                for key, value in values.items()
                if key in WORKER_METRICS and (value is None or _number(value))
            }
            if projected:
                sample["timings"]["worker"].append(
                    {"role": trace["role"], "stage": trace["stage"], **projected}
                )
                sample["metrics"].update(
                    {
                        trace["role"] + "." + trace["stage"] + "." + key: value
                        for key, value in projected.items()
                        if key != "wall_ts" and _number(value)
                    }
                )
    services = report.get("services")
    healthy = (
        isinstance(services, list)
        and len(services) == 2
        and {s.get("service") for s in services if isinstance(s, dict)} == {"app", "api"}
        and all(isinstance(s, dict) and s.get("health") == "healthy" for s in services)
    )
    sample["valid"] = bool(
        healthy
        and not report.get("error")
        and report.get("status") == "REACHABLE"
        and all(
            f.get("code") == "TCP_REACHABLE" and f.get("status") == "REACHABLE" for f in findings
        )
        and all(
            p.get("dns") == "ok"
            and p.get("tcp") == "ok"
            and p.get("state") == "SUCCESS"
            and p.get("cleanup") in {"complete", "not_needed"}
            for p in probes
        )
        and bool(sample["timings"]["stages"])
    )
    if sample["valid"]:
        sample["error"] = None
    destination_requested = (
        any(
            stage["role"] == "destination" and stage["stage"] == "worker_startup"
            for stage in sample["timings"]["stages"]
        )
        or any(
            trace["role"] == "destination" and trace["stage"] == "worker_startup"
            for trace in sample["timings"]["worker"]
        )
        or any(p.get("listener_state") == "SUCCESS" for p in probes)
    )
    if destination_requested:
        sample["required_timing_metrics"].extend(
            "destination.worker_startup." + key for key in READY_METRICS
        )
    sample["timing_complete"] = all(
        _number(sample["metrics"].get(key)) for key in sample["required_timing_metrics"]
    )
    if sample["valid"] and not sample["timing_complete"]:
        sample.update(valid=False, error="incomplete_ready_timings")
    return sample


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate lease key")
        result[key] = value
    return result


def _invalid_json_constant(value):
    raise ValueError("nonfinite lease value")


def _lease_record(directory, project):
    path = directory / "lease.json"
    for candidate, expected in ((directory, stat.S_ISDIR), (path, stat.S_ISREG)):
        attributes = candidate.lstat()
        if not expected(attributes.st_mode) or getattr(
            attributes, "st_file_attributes", 0
        ) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024):
            raise ValueError("lease path is not a private regular path")
    with path.open("rb") as handle:
        content = handle.read(65537)
    if len(content) > 65536:
        raise ValueError("lease exceeds byte limit")
    lease = json.loads(
        content, object_pairs_hook=_unique_json_pairs, parse_constant=_invalid_json_constant
    )
    if (
        not isinstance(lease, dict)
        or set(lease) != {"execution_id", "project", "helpers"}
        or lease["project"] != project
    ):
        raise ValueError("invalid lease root")
    execution = lease["execution_id"]
    helpers = lease["helpers"]
    if (
        not isinstance(execution, str)
        or not re.fullmatch(r"[0-9a-f]{32}", execution)
        or not isinstance(helpers, list)
        or len(helpers) > 2
    ):
        raise ValueError("invalid execution or helper count")
    names = set()
    for helper in helpers:
        if not isinstance(helper, dict) or set(helper) != {"name", "labels"}:
            raise ValueError("invalid helper intent")
        labels = helper["labels"]
        if not isinstance(labels, dict) or set(labels) != {
            "io.dockroute.helper",
            "io.dockroute.project",
            "io.dockroute.run",
            "io.dockroute.execution",
        }:
            raise ValueError("invalid ownership keys")
        run = labels["io.dockroute.run"]
        if (
            not isinstance(run, str)
            or not re.fullmatch(r"[0-9a-f]{32}", run)
            or labels["io.dockroute.helper"] != "true"
            or labels["io.dockroute.project"] != project
            or labels["io.dockroute.execution"] != execution
        ):
            raise ValueError("invalid helper ownership")
        if helper["name"] != "dockroute-probe-" + run or helper["name"] in names:
            raise ValueError("invalid or duplicate helper name")
        names.add(helper["name"])
    return lease


def _matches_lease(attrs, helper):
    if (
        not isinstance(attrs, dict)
        or attrs.get("Name") != "/" + helper["name"]
        or not isinstance(attrs.get("Id"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", attrs["Id"])
    ):
        return False
    config = attrs.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    return isinstance(labels, dict) and all(
        labels.get(key) == value for key, value in helper["labels"].items()
    )


def recover_leased_helpers(
    inspector, directory, project, *, hard_killed=False, allow_missing=False
):
    """Reconcile only validated private intents after the known child has exited."""
    result: dict = {"cleanup": "failed", "lease_status": "invalid"}
    try:
        lease = _lease_record(directory, project)
    except FileNotFoundError:
        result["lease_status"] = "missing"
        if allow_missing:
            try:
                if _resources(inspector, project)["helpers"] == 0:
                    result["cleanup"] = "uncertain" if hard_killed else "complete"
            except BOUNDARY_ERRORS:
                pass
        return result
    except (UnicodeError, RecursionError, TypeError, *BOUNDARY_ERRORS):
        return result
    result.update(
        lease_status="valid",
        probe_execution_ids=[lease["execution_id"]],
        leased_helper_names=[h["name"] for h in lease["helpers"]],
    )
    api = inspector.client.api
    deadline = time.monotonic() + 2.5
    try:
        while True:
            present = []
            # Inspect every intent first: a foreign second helper forbids all deletion.
            for helper in lease["helpers"]:
                try:
                    attrs = api.inspect_container(helper["name"])
                except NotFound:
                    continue
                if not _matches_lease(attrs, helper):
                    return result
                present.append((helper, attrs["Id"]))
            for helper, identifier in present:
                try:
                    api.remove_container(identifier, force=True)
                except NotFound:
                    pass
                for identity in (identifier, helper["name"]):
                    try:
                        api.inspect_container(identity)
                    except NotFound:
                        continue
                    return result
            if not hard_killed:
                result["cleanup"] = "complete"
                return result
            if time.monotonic() >= deadline:
                # A killed create request can still complete later in the daemon.
                result["cleanup"] = "uncertain"
                return result
            time.sleep(0.2)
    except (TypeError, *BOUNDARY_ERRORS):
        return result


def probe_sample(args, inspector, project, condition, sample):
    """Give the exact child a private cancel channel and time to run its finally."""
    sample.update(valid=False, error="probe_command_or_report_failed", metrics={})
    control_parent = ROOT / "work"
    control_parent.mkdir(parents=True, exist_ok=True)
    interrupted = False
    child = None
    hard_killed = False
    with tempfile.TemporaryDirectory(prefix="dockroute-control-", dir=control_parent) as directory:
        control = Path(directory).absolute()
        command = probe_command(args, project, condition, control=control)
        started = time.perf_counter()
        stdout = ""
        try:
            group = (
                {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
                if sys.platform == "win32"
                else {"start_new_session": True}
            )
            child = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                env=condition_environment(condition),
                **group,
            )
            try:
                stdout, _ = child.communicate(
                    timeout=max(180, 4 * (args.startup_timeout + args.api_timeout + args.timeout))
                )
            except (KeyboardInterrupt, subprocess.TimeoutExpired) as event:
                interrupted = isinstance(event, KeyboardInterrupt)
                sample["cancellation_requested"] = True
                try:
                    (control / "cancel").write_text("cancel\n", encoding="utf-8")
                except OSError:
                    # Failure to publish cancellation still requires waiting/reaping this child.
                    sample["cancel_channel_failed"] = True
                try:
                    stdout, _ = child.communicate(timeout=max(15, args.api_timeout * 3 + 5))
                except (KeyboardInterrupt, subprocess.TimeoutExpired):
                    child.kill()  # Only the exact process object this attempt created.
                    hard_killed = True
                    sample["child_killed"] = True
                    try:
                        stdout, _ = child.communicate(timeout=5)
                    except (KeyboardInterrupt, subprocess.TimeoutExpired):
                        sample["child_exit_unconfirmed"] = True
                sample["error"] = "cancelled" if interrupted else "probe_outer_timeout"
            sample["exit_code"] = child.returncode
            failure = sample["error"] if sample.get("cancellation_requested") else None
            if stdout:
                sample.update(extract_probe_sample(json.loads(stdout)))
            if failure:
                sample.update(valid=False, error=failure)
            elif child.returncode != 0:
                sample.update(valid=False, error="probe_exit_failure")
        except BOUNDARY_ERRORS:
            sample.update(valid=False, error="probe_command_or_report_failed")
        finally:
            sample["metrics"]["wall_ms"] = (time.perf_counter() - started) * 1000
            recovered = time.perf_counter()
            if sample.get("child_exit_unconfirmed") or (
                child is not None and child.returncode is None
            ):
                sample["cleanup"] = "uncertain"
            else:
                recovery = recover_leased_helpers(
                    inspector,
                    control,
                    project,
                    hard_killed=hard_killed,
                    allow_missing=not sample["valid"],
                )
                sample.update(recovery)
                if recovery["lease_status"] == "missing" and sample["valid"]:
                    sample.update(valid=False, error="missing_control_lease")
                if recovery["cleanup"] != "complete":
                    sample["valid"] = False
            sample["parent_cleanup_ms"] = (time.perf_counter() - recovered) * 1000
        if interrupted:
            raise KeyboardInterrupt


def _floor_cleanup(inspector, name, owner, *, interrupted=False):
    deadline = time.monotonic() + 2.5
    while True:
        try:
            attrs = inspector.client.api.inspect_container(name)
        except NotFound:
            attrs = None
        except BOUNDARY_ERRORS:
            return "failed"
        if attrs is not None:
            config = attrs.get("Config") if isinstance(attrs, dict) else None
            labels = config.get("Labels") if isinstance(config, dict) else None
            if not isinstance(labels, dict) or labels.get(OWNER_LABEL) != owner:
                return "ownership_unconfirmed"
            try:
                try:
                    inspector.client.api.remove_container(attrs["Id"], force=True)
                except NotFound:
                    pass  # Engine auto-removal may race the owned remove request.
                try:
                    inspector.client.api.inspect_container(name)
                except NotFound:
                    pass
                else:
                    return "failed"
            except (KeyError, *BOUNDARY_ERRORS):
                return "failed"
        if not interrupted:
            return "complete"
        if time.monotonic() >= deadline:
            # Killing docker run does not cancel an in-flight Engine create.
            return "uncertain"
        time.sleep(0.2)


def floor_sample(args, inspector, owner, *, sample=None):
    name = "dockroute-latency-floor-" + uuid.uuid4().hex
    if sample is None:
        sample = {}
    sample.update(valid=False, error="floor_failed", metrics={}, floor_name=name)
    started = time.perf_counter()
    interrupted = False
    try:
        result = _command(
            [
                "docker",
                "run",
                "--rm",
                "--pull",
                "never",
                "--name",
                name,
                "--label",
                OWNER_LABEL + "=" + owner,
                IMAGE,
                "true",
            ],
            timeout=180,
            env=condition_environment("floor"),
        )
        sample["exit_code"] = result.returncode
        sample["valid"] = result.returncode == 0
        sample["error"] = None if sample["valid"] else "floor_failed"
    except BOUNDARY_ERRORS as exc:
        interrupted = isinstance(exc, subprocess.TimeoutExpired)
        sample["error"] = "floor_command_failed"
    except KeyboardInterrupt:
        interrupted = True
        sample["error"] = "cancelled"
        raise
    finally:
        sample["metrics"]["wall_ms"] = (time.perf_counter() - started) * 1000
        recovered = time.perf_counter()
        sample["cleanup"] = _floor_cleanup(inspector, name, owner, interrupted=interrupted)
        sample["parent_cleanup_ms"] = (time.perf_counter() - recovered) * 1000
        if sample["cleanup"] != "complete":
            sample["valid"] = False
            if sample["error"] is None:
                sample["error"] = "floor_cleanup_uncertain"
    return sample


def _resources(inspector, project):
    api = inspector.client.api
    return {
        "containers": len(
            api.containers(all=True, filters={"label": ["com.docker.compose.project=" + project]})
        ),
        "networks": len(api.networks(filters={"label": ["com.docker.compose.project=" + project]})),
        "helpers": len(
            api.containers(
                all=True,
                filters={"label": ["io.dockroute.helper=true", "io.dockroute.project=" + project]},
            )
        ),
    }


def _healthy(snapshot):
    return (
        len(snapshot) == 2
        and {c.service for c in snapshot} == {"app", "api"}
        and all(c.state == "running" and c.health == "healthy" for c in snapshot)
    )


def _settle(inspector, project, args):
    deadline = time.monotonic() + args.health_timeout
    stable_since = None
    previous = None
    while time.monotonic() < deadline:
        snapshot = inspector.snapshot(project)
        current = tuple(sorted((c.service, c.id, c.restart_count) for c in snapshot))
        if _healthy(snapshot):
            if stable_since is None or current != previous:
                stable_since = time.monotonic()
            if time.monotonic() - stable_since >= args.settle_seconds:
                return
        else:
            stable_since = None
        previous = current
        time.sleep(0.25)
    raise RuntimeError("fixture_not_settled")


def _metadata(inspector, args):
    engine = inspector.version()
    api = inspector.client.api
    info = api.info()
    image = api.inspect_image(IMAGE)  # Read-only: an absent image is never pulled.
    composed = _command(
        ["docker", "compose", "version", "--short"], timeout=20, env=condition_environment("poll")
    )
    if composed.returncode:
        raise DockerUnavailable("Compose unavailable")
    version_pattern = r"[0-9A-Za-z.+_-]{1,80}"
    compose_version = composed.stdout.strip()
    kernel = str(info.get("KernelVersion", "")).lower()
    desktop = "docker desktop" in str(info.get("OperatingSystem", "")).lower()
    backend = (
        "wsl2"
        if desktop and "wsl2" in kernel
        else "hyper-v"
        if desktop and sys.platform == "win32" and "linuxkit" in kernel
        else "unknown"
    )
    metadata: dict = {
        "date": datetime.now(timezone.utc).isoformat(),
        "dockroute": __version__,
        "engine": engine.get("Version")
        if re.fullmatch(version_pattern, str(engine.get("Version", "")))
        else "unknown",
        "compose": compose_version if re.fullmatch(version_pattern, compose_version) else "unknown",
        "desktop_detected": desktop,
        "desktop_backend": backend,
        "desktop_backend_basis": "engine_kernel" if backend != "unknown" else "unavailable",
        "image": IMAGE,
        "image_id": None,
        "image_digests": [],
        "tool": "binary" if args.binary else "source",
        "tool_revision": None,
    }
    if re.fullmatch(r"sha256:[0-9a-f]{64}", str(image.get("Id", ""))):
        metadata["image_id"] = image["Id"]
    metadata["image_digests"] = [
        digest
        for digest in image.get("RepoDigests", [])
        if re.fullmatch(r"(?:[a-z0-9._/-]+)?@sha256:[0-9a-f]{64}", digest)
    ]
    if args.binary:
        metadata["tool_sha256"] = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    else:
        source = hashlib.sha256()
        for path in sorted((ROOT / "src" / "dockroute").glob("*.py")):
            source.update(path.name.encode())
            source.update(path.read_bytes())
        metadata["tool_sha256"] = source.hexdigest()
    try:
        revision = _command(["git", "rev-parse", "HEAD"], timeout=10).stdout.strip()
        if re.fullmatch(r"[0-9a-f]{40,64}", revision):
            metadata["tool_revision"] = revision
    except BOUNDARY_ERRORS:
        pass
    return metadata


def run_benchmark(args, inspector, report):
    scenario = ROOT / "scenarios" / "06-healthy-control"
    project = "dockroute-latency-" + uuid.uuid4().hex[:20]
    owner = uuid.uuid4().hex
    report.update(project=project, owner=owner)
    if any(_resources(inspector, project).values()):
        raise FixtureSafetyError("fresh_project_collision")
    compose = ["docker", "compose", "-p", project, "-f", str(scenario / "compose.yaml")]
    environment = condition_environment("poll")
    configured = _command([*compose, "config", "--format", "json"], timeout=30, env=environment)
    if configured.returncode:
        raise RuntimeError("fixture_config_failed")
    config = json.loads(configured.stdout)
    validate_fixture(config, project=project)
    report["fixture_sha256"] = hashlib.sha256((scenario / "compose.yaml").read_bytes()).hexdigest()
    expected = {
        "intended_edge": {
            "source_service": "app",
            "destination_service": "api",
            "destination_port": 8000,
        },
        "observed_config": {"env_name": "UPSTREAM_URL"},
    }
    with tempfile.TemporaryDirectory(prefix="dockroute-latency-") as directory:
        frozen = Path(directory) / "compose.json"
        frozen.write_text(json.dumps(config), encoding="utf-8")
        compose = ["docker", "compose", "-p", project, "-f", str(frozen)]
        report["cleanup"] = "pending"
        try:
            started = time.perf_counter()
            try:
                up = _command([*compose, "up", "-d", "--pull", "never"], env=environment)
            finally:
                report["compose"]["setup_ms"] = (time.perf_counter() - started) * 1000
            if up.returncode:
                raise RuntimeError("fixture_setup_failed")
            started = time.perf_counter()
            try:
                _settle(inspector, project, args)
            finally:
                report["compose"]["settle_ms"] = (time.perf_counter() - started) * 1000
            started = time.perf_counter()
            observed = _observe(inspector, project, expected)
            report["compose"]["validation_ms"] = (time.perf_counter() - started) * 1000
            report["behavior_validated"] = validate_behavior("TCP_REACHABLE", observed)
            if not report["behavior_validated"]:
                raise RuntimeError("fixture_behavior_failed")
            for round_index, condition in condition_order(
                args.conditions, args.warmups + args.runs
            ):
                sample = {
                    "condition": condition,
                    "round": round_index,
                    "warmup": round_index < args.warmups,
                    "valid": False,
                    "metrics": {},
                }
                report["samples"].append(sample)
                print(
                    f"Round {round_index + 1}/{args.warmups + args.runs}: {condition} ({'warm-up' if sample['warmup'] else 'measured'})",
                    flush=True,
                )
                if not _healthy(inspector.snapshot(project)):
                    sample["error"] = "fixture_not_healthy"
                    continue
                if condition == "floor":
                    floor_sample(args, inspector, owner, sample=sample)
                    if sample["cleanup"] != "complete":
                        raise RuntimeError("floor_cleanup_uncertain")
                else:
                    probe_sample(args, inspector, project, condition, sample)
                    if sample["cleanup"] != "complete":
                        raise RuntimeError("probe_cleanup_uncertain")
                if any(_resources(inspector, project)[key] for key in ("helpers",)):
                    sample.update(valid=False, error="probe_cleanup_leak")
                    raise RuntimeError("probe_cleanup_leak")
            report["status"] = "passed" if all(s["valid"] for s in report["samples"]) else "failed"
        finally:
            started = time.perf_counter()
            try:
                down = _command([*compose, "down", "--timeout", "5"], timeout=60, env=environment)
                remaining = _resources(inspector, project)
                report["remaining_owned_resources"] = remaining
                attempts_clean = all(
                    s.get("cleanup") == "complete" for s in report["samples"] if "cleanup" in s
                )
                report["cleanup"] = (
                    "complete"
                    if down.returncode == 0 and not any(remaining.values()) and attempts_clean
                    else "failed"
                )
            except BOUNDARY_ERRORS:
                report["cleanup"] = "failed"
            finally:
                report["compose"]["teardown_ms"] = (time.perf_counter() - started) * 1000
            if report["cleanup"] != "complete":
                report.update(status="failed", error="cleanup_uncertain")


def render_markdown(report):
    metadata = report.get("metadata", {})
    lines = [
        "# DockRoute controlled probe latency",
        "",
        f"Status: **{report['status']}**; cleanup: **{report['cleanup']}**.",
        "",
        f"Date: {metadata.get('date', report['generated_at'])}. Engine: {metadata.get('engine', 'unknown')}; Compose: {metadata.get('compose', 'unknown')}; Desktop backend: {metadata.get('desktop_backend', 'unknown')}.",
        "",
        "One scenario06 fixture; rotated conditions; attempts run sequentially. Warm-ups and errors remain in JSON but are excluded from measured distributions.",
        "",
        "IQR uses linear interpolation at the 25th and 75th percentiles. p95 uses nearest rank and is shown only when n >= 40. Request elapsed time ends at response headers; streaming body time is excluded. Initial Engine version negotiation and ping occur before the collector is attached and are excluded from request summaries; CLI wall time includes them. VM startup derives from worker/daemon clocks; StartedAt precedes exec, and observation overhead is a qualified estimate.",
        "",
        "| Condition | Metric | n | Median | IQR | Min | Max | p95 (n >= 40) |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for condition, summary in report["summary"].items():
        for metric, values in summary["metrics"].items():
            lines.append(
                f"| {condition} | {metric} | {values['n']} | {values['median']:.3f} | {values['iqr']:.3f} | {values['min']:.3f} | {values['max']:.3f} | {values['p95']:.3f} |"
                if "p95" in values
                else f"| {condition} | {metric} | {values['n']} | {values['median']:.3f} | {values['iqr']:.3f} | {values['min']:.3f} | {values['max']:.3f} | — |"
            )
    lines.extend(
        [
            "",
            "Durations are milliseconds; polls/reloads/http_requests are counts.",
            "",
            f"Scheduling within each probe: `{report['flags']['schedule']}`. CLI flags: `{json.dumps(report['flags'], sort_keys=True)}`.",
            "",
            f"Compose timings, excluded from attempts: `{json.dumps(report['compose'], sort_keys=True)}`.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv=None):
    args = parse_args(argv)
    report: dict = {
        "schema_version": "1.0",
        "suite": "controlled-scenario06-latency",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "failed",
        "cleanup": "not_needed",
        "behavior_validated": False,
        "flags": {
            key: getattr(args, key)
            for key in (
                "conditions",
                "runs",
                "warmups",
                "schedule",
                "startup_timeout",
                "api_timeout",
                "timeout",
                "dns_timeout",
                "connect_timeout",
                "health_timeout",
                "settle_seconds",
            )
        },
        "compose": {},
        "samples": [],
        "summary": {},
    }
    inspector = None
    exit_code = 1
    try:
        inspector = connect(timeout=args.api_timeout)
        report["metadata"] = _metadata(inspector, args)
        run_benchmark(args, inspector, report)
        exit_code = 0 if report["status"] == "passed" else 1
    except DockerUnavailable:
        report.update(status="unavailable", error="engine_or_compose_unavailable")
        exit_code = 3
    except KeyboardInterrupt:
        report.update(status="cancelled", error="cancelled")
        exit_code = 130
    except BOUNDARY_ERRORS:
        report.update(status="failed", error=report.get("error", "benchmark_boundary_failed"))
    finally:
        if inspector:
            inspector.close()
        report["summary"] = summarize(report["samples"], args.conditions)
        report["timing_suitable"] = report["status"] == "passed" and all(
            summary["timing_coverage_complete"] for summary in report["summary"].values()
        )
        if report["status"] == "passed" and not report["timing_suitable"]:
            report.update(status="failed", error="incomplete_timing_coverage")
            exit_code = 1
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8"
        )
        args.output.with_suffix(".md").write_text(render_markdown(report), encoding="utf-8")
        print(f"Latency report: {args.output} ({report['status']})", flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
