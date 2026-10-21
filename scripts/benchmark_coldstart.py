"""Compare fresh CLI processes sequentially; warm launches do not flush OS caches.

Default: five source/binary variants, --version, --help, static and active scenario06.
Each combination has three discarded warm-ups followed by twenty measured launches.
Use --cases version,help to measure without contacting Docker Engine.
"""

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import benchmark_latency as latency  # noqa: E402

connect = latency.connect
VARIANTS = (
    "old-onefile",
    "old-source",
    "optimized-source",
    "optimized-onefile",
    "optimized-onedir",
)
CASES = ("version", "help", "static", "active")
ERRORS = (UnicodeError, TypeError, RecursionError, *latency.BOUNDARY_ERRORS)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variants", default=",".join(VARIANTS))
    parser.add_argument("--cases", default=",".join(CASES))
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument(
        "--old-onefile", type=Path, default=ROOT / "work/coldstart-baseline/dockroute.exe"
    )
    parser.add_argument("--old-source", type=Path, default=ROOT / "work/coldstart-baseline/source")
    parser.add_argument("--optimized-source", type=Path, default=ROOT / "src")
    parser.add_argument(
        "--optimized-onefile", type=Path, default=ROOT / "outputs/coldstart-onefile/dockroute.exe"
    )
    parser.add_argument(
        "--optimized-onedir",
        type=Path,
        default=ROOT / "outputs/coldstart-onedir/dockroute/dockroute.exe",
    )
    parser.add_argument("--startup-timeout", type=latency._seconds, default=30.0)
    parser.add_argument("--api-timeout", type=latency._seconds, default=20.0)
    parser.add_argument("--timeout", type=latency._seconds, default=5.0)
    parser.add_argument("--dns-timeout", type=latency._seconds, default=2.0)
    parser.add_argument("--connect-timeout", type=latency._seconds, default=1.0)
    parser.add_argument("--schedule", choices=("conditional", "sequential"), default="conditional")
    parser.add_argument("--health-timeout", type=latency._seconds, default=60.0)
    parser.add_argument("--settle-seconds", type=latency._nonnegative_seconds, default=3.0)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "benchmarks"
        / ("coldstart-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"),
    )
    args = parser.parse_args(argv)
    for name, allowed in (("variants", VARIANTS), ("cases", CASES)):
        selected = tuple(part.strip() for part in getattr(args, name).split(","))
        if (
            not selected
            or len(set(selected)) != len(selected)
            or any(x not in allowed for x in selected)
        ):
            parser.error(name + " must be a nonempty unique subset of " + ",".join(allowed))
        setattr(args, name, selected)
    if args.runs < 20 or args.warmups < 3:
        parser.error("use at least 20 measured rounds and 3 discarded warm-ups per combination")
    if max(args.dns_timeout, args.connect_timeout) > args.timeout:
        parser.error("DNS/connect deadlines cannot exceed execution deadline")
    return args


def source_path(args, variant):
    path = getattr(args, variant.replace("-", "_")).resolve()
    return path / "src" if (path / "src/dockroute").is_dir() else path


def variant_environment(args, variant):
    environment = os.environ.copy()
    environment.pop("DOCKROUTE_HELPER_CPUS", None)
    environment.pop("PYTHONPATH", None)
    if variant.endswith("source"):
        environment["PYTHONPATH"] = str(source_path(args, variant))
    return environment


def variant_command(args, variant, case, project=None, *, control=None):
    command = (
        [str(args.python.resolve()), "-m", "dockroute"]
        if variant.endswith("source")
        else [str(getattr(args, variant.replace("-", "_")).resolve())]
    )
    if case in {"version", "help"}:
        return [*command, "--" + case]
    command.extend(
        [
            "doctor",
            "--project",
            project,
            "--format",
            "json",
            "--api-timeout",
            str(args.api_timeout),
            "--timing",
        ]
    )
    if case == "active":
        command.extend(
            [
                "--probe",
                "--observe",
                "poll",
                "--schedule",
                args.schedule,
                "--startup-timeout",
                str(args.startup_timeout),
                "--timeout",
                str(args.timeout),
                "--dns-timeout",
                str(args.dns_timeout),
                "--connect-timeout",
                str(args.connect_timeout),
            ]
        )
        if control is not None:
            command.extend(["--_benchmark-control", str(control)])
    return command


def attempt_order(variants, cases, rounds):
    for round_index in range(rounds):
        offset = round_index % len(variants)
        for case in cases:
            for variant in (*variants[offset:], *variants[:offset]):
                yield round_index, case, variant


def summarize(samples, variants, cases):
    result: dict = {}
    for case in cases:
        result[case] = {}
        for variant in variants:
            selected = [s for s in samples if s["case"] == case and s["variant"] == variant]
            measured = [s for s in selected if not s["warmup"] and s["valid"]]
            required = {"wall_ms"}
            if case in {"static", "active"}:
                required.add("report_total_ms")
            if case == "active":
                required.update("source.worker_startup." + key for key in latency.READY_METRICS)
                required.update(
                    key for s in selected for key in s.get("required_timing_metrics", ())
                )
            counts = {
                key: sum(latency._number(s.get("metrics", {}).get(key)) for s in measured)
                for key in sorted(required)
            }
            keys = sorted({key for s in measured for key in s.get("metrics", {})})
            result[case][variant] = {
                "warmups_discarded": sum(s["warmup"] for s in selected),
                "failed": sum(not s["valid"] for s in selected),
                "measured_valid": len(measured),
                "required_metric_counts": counts,
                "timing_coverage_complete": all(n >= 20 for n in counts.values()),
                "metrics": {
                    key: latency.distribution(
                        [
                            s["metrics"][key]
                            for s in measured
                            if latency._number(s.get("metrics", {}).get(key))
                        ]
                    )
                    for key in keys
                    if any(latency._number(s.get("metrics", {}).get(key)) for s in measured)
                },
            }
    return result


def _file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def variant_metadata(args):
    """Validate every selected artifact before connecting to Engine or creating fixtures."""
    result = {}
    for variant in args.variants:
        if variant.endswith("source"):
            if not args.python.is_file():
                raise ValueError("source_python_missing")
            package = source_path(args, variant) / "dockroute"
            if not (package / "__init__.py").is_file():
                raise ValueError("source_package_missing")
            files = sorted(package.rglob("*.py"))
            digest = hashlib.sha256()
            for path in files:
                digest.update(path.relative_to(package).as_posix().encode())
                digest.update(bytes.fromhex(_file_hash(path)))
            result[variant] = {
                "kind": "source",
                "source_sha256": digest.hexdigest(),
                "source_files": len(files),
                "python_sha256": _file_hash(args.python),
            }
        else:
            path = getattr(args, variant.replace("-", "_")).resolve()
            if not path.is_file():
                raise ValueError("binary_missing")
            result[variant] = {"kind": "binary", "binary_sha256": _file_hash(path)}
            if variant == "optimized-onedir":
                digest = hashlib.sha256()
                for member in sorted(path.parent.rglob("*")):
                    if member.is_file():
                        digest.update(member.relative_to(path.parent).as_posix().encode())
                        digest.update(bytes.fromhex(_file_hash(member)))
                result[variant]["distribution_sha256"] = digest.hexdigest()
    return result


def diagnosis_signature(report):
    """Hash diagnostic facts; replace only known resource identities, never service facts."""
    replacements = {}
    project = report.get("project")
    if isinstance(project, str) and len(project) >= 8:
        replacements[project] = "{project}"
    services = report.get("services", [])
    for service in services:
        label = service["service"]
        for key in ("container_id", "container_name"):
            value = service.get(key)
            if isinstance(value, str) and len(value) >= 5 and value not in {"app", "api"}:
                replacements[value] = "{" + label + "." + key + "}"
        for index, network in enumerate(service.get("networks", [])):
            for key in ("id", "name"):
                value = network.get(key)
                if isinstance(value, str) and len(value) >= 5:
                    replacements[value] = "{network." + str(index) + "." + key + "}"

    def normalize(value):
        if isinstance(value, str):
            if len(value) > 8192:
                raise ValueError("oversized_diagnostic_fact")
            for original in sorted(replacements, key=len, reverse=True):
                value = value.replace(original, replacements[original])
            return value
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        return value

    finding_keys = (
        "code",
        "status",
        "source",
        "source_container",
        "destination",
        "destination_service",
        "port",
        "confidence",
        "verification",
        "explanation",
        "remediation",
        "observations",
        "intention_evidence",
    )
    probe_keys = (
        "state",
        "dns",
        "tcp",
        "resolver_files_match",
        "listener_state",
        "listener_addresses",
        "listener_verified",
        "listener_skipped",
        "listener_skip_reason",
        "cleanup",
    )
    findings = []
    for finding in report["findings"]:
        item = {key: finding.get(key) for key in finding_keys}
        probe = finding.get("probe")
        if isinstance(probe, dict):
            item["probe"] = {key: probe.get(key) for key in probe_keys}
        findings.append(item)
    facts = {
        "status": report["status"],
        "findings": findings,
        "services": [
            {
                key: service.get(key)
                for key in ("service", "state", "health", "restart_count", "networks", "ports")
            }
            for service in services
        ],
    }
    return hashlib.sha256(
        json.dumps(normalize(facts), sort_keys=True, allow_nan=False).encode()
    ).hexdigest()


def extract_result(case, exit_code, stdout):
    sample: dict = {"valid": False, "error": "invalid_child_evidence", "metrics": {}}
    if case == "version":
        match = re.fullmatch(r"DockRoute ([0-9A-Za-z.+_-]{1,80})\s*", stdout)
        sample["valid"] = exit_code == 0 and match is not None
        if match:
            sample["version"] = match[1]
    elif case == "help":
        sample["valid"] = (
            exit_code == 0
            and stdout.lstrip().startswith("usage:")
            and "doctor" in stdout
            and "check" in stdout
        )
    else:
        report = json.loads(
            stdout,
            object_pairs_hook=latency._unique_json_pairs,
            parse_constant=latency._invalid_json_constant,
        )
        if not isinstance(report, dict):
            return sample
        timings = report.get("timings")
        if isinstance(timings, dict) and latency._number(timings.get("total_ms")):
            sample["metrics"]["report_total_ms"] = timings["total_ms"]
        else:
            return sample
        findings = report.get("findings")
        services = report.get("services")
        if (
            not isinstance(findings, list)
            or len(findings) != 1
            or not isinstance(findings[0], dict)
        ):
            return sample
        healthy = (
            isinstance(services, list)
            and len(services) == 2
            and all(isinstance(s, dict) and s.get("health") == "healthy" for s in services)
            and {s.get("service") for s in services} == {"app", "api"}
        )
        finding = findings[0]
        expected = (
            ("UNKNOWN", "NO_STATIC_ISSUES_FOUND", "low", "static", 2)
            if case == "static"
            else ("TCP_REACHABLE", "REACHABLE", "high", "active", 0)
        )
        valid = (
            healthy
            and not report.get("error")
            and (
                finding.get("code"),
                finding.get("status"),
                finding.get("confidence"),
                finding.get("verification"),
                exit_code,
            )
            == expected
            and report.get("status") == expected[1]
        )
        for name in ("observations", "intention_evidence"):
            evidence = finding.get(name)
            valid = (
                valid
                and isinstance(evidence, list)
                and bool(evidence)
                and all(
                    isinstance(e, dict)
                    and set(e) == {"kind", "detail"}
                    and isinstance(e["kind"], str)
                    and isinstance(e["detail"], str)
                    for e in evidence
                )
            )
        if case == "active":
            projected = latency.extract_probe_sample(report)
            valid = valid and projected["valid"]
            sample["timings"] = projected["timings"]
            sample["required_timing_metrics"] = projected.get("required_timing_metrics", [])
            sample["metrics"].update(
                {key: value for key, value in projected["metrics"].items() if key != "total_ms"}
            )
        else:
            valid = valid and finding.get("probe") is None
        sample["valid"] = bool(valid)
        if valid:
            sample["diagnostic_digest"] = diagnosis_signature(report)
            sample["diagnosis"] = {
                "code": expected[0],
                "status": expected[1],
                "confidence": expected[2],
                "verification": expected[3],
                "exit_code": exit_code,
            }
    if sample["valid"]:
        sample["error"] = None
    return sample


def _stop_child(args, child, control, case, sample):
    """Stop/reap the exact live child even when communication itself has failed."""
    sample["cancellation_requested"] = True
    interrupted, hard_killed, stdout = False, False, ""
    if case == "active":
        try:
            (control / "cancel").write_text("cancel\n", encoding="utf-8")
        except OSError:
            sample["cancel_channel_failed"] = True
    try:
        stdout, _ = child.communicate(
            timeout=max(15, args.api_timeout * 3 + 5) if case == "active" else 5
        )
        return stdout, hard_killed, interrupted
    except KeyboardInterrupt:
        interrupted = True
    except ERRORS:
        pass
    hard_killed = True
    sample["child_killed"] = True
    try:
        child.kill()
    except ERRORS:
        sample["child_kill_failed"] = True
    try:
        stdout, _ = child.communicate(timeout=5)
    except KeyboardInterrupt:
        interrupted = True
    except ERRORS:
        pass
    if child.returncode is None:
        try:
            child.wait(timeout=5)
        except KeyboardInterrupt:
            interrupted = True
        except ERRORS:
            pass
    if child.returncode is None:
        sample["child_exit_unconfirmed"] = True
    return stdout, hard_killed, interrupted


def run_attempt(args, inspector, project, variant, case, sample):
    sample.update(valid=False, error="child_command_or_report_failed", metrics={})
    interrupted, hard_killed, child = False, False, None
    ended = None
    stop_attempted = False
    control_parent = ROOT / "work"
    control_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="dockroute-coldstart-control-", dir=control_parent
    ) as directory:
        control = Path(directory).absolute()
        command = variant_command(args, variant, case, project, control=control)
        environment = variant_environment(args, variant)
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
                env=environment,
                **group,
            )
            try:
                stdout, _ = child.communicate(
                    timeout=max(180, 4 * (args.startup_timeout + args.api_timeout + args.timeout))
                    if case == "active"
                    else 180
                )
                ended = time.perf_counter()
            except (KeyboardInterrupt, subprocess.TimeoutExpired) as event:
                interrupted = isinstance(event, KeyboardInterrupt)
                stop_attempted = True
                stdout, hard_killed, during_stop = _stop_child(args, child, control, case, sample)
                interrupted = interrupted or during_stop
                ended = time.perf_counter()
                sample["error"] = "cancelled" if interrupted else "child_outer_timeout"
            sample["exit_code"] = child.returncode
            failure = sample["error"] if sample.get("cancellation_requested") else None
            if stdout:
                sample.update(extract_result(case, child.returncode, stdout))
            if failure:
                sample.update(valid=False, error=failure)
        except ERRORS:
            sample.update(valid=False, error="child_command_or_report_failed")
        finally:
            if child is not None and child.returncode is None and not stop_attempted:
                _, hard_killed, during_stop = _stop_child(args, child, control, case, sample)
                interrupted = interrupted or during_stop
                ended = time.perf_counter()
                sample["exit_code"] = child.returncode
            sample["metrics"]["wall_ms"] = (
                (ended if ended is not None else time.perf_counter()) - started
            ) * 1000
            recovered = time.perf_counter()
            if sample.get("child_exit_unconfirmed") or (
                child is not None and child.returncode is None
            ):
                sample.update(valid=False, cleanup="uncertain")
            elif case == "active":
                recovery = latency.recover_leased_helpers(
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
            else:
                sample["cleanup"] = "not_needed"
            sample["parent_cleanup_ms"] = (time.perf_counter() - recovered) * 1000
        if interrupted:
            raise KeyboardInterrupt


@contextmanager
def owned_fixture(args, inspector, report):
    project = "dockroute-coldstart-" + uuid.uuid4().hex[:20]
    report["project"] = project
    if any(latency._resources(inspector, project).values()):
        raise latency.FixtureSafetyError("fresh_project_collision")
    scenario = ROOT / "scenarios/06-healthy-control/compose.yaml"
    environment = latency.condition_environment("poll")
    original = ["docker", "compose", "-p", project, "-f", str(scenario)]
    configured = latency._command(
        [*original, "config", "--format", "json"], timeout=30, env=environment
    )
    if configured.returncode:
        raise RuntimeError("fixture_config_failed")
    config = json.loads(configured.stdout)
    latency.validate_fixture(config, project=project)
    report["fixture_sha256"] = _file_hash(scenario)
    with tempfile.TemporaryDirectory(prefix="dockroute-coldstart-fixture-") as directory:
        frozen = Path(directory) / "compose.json"
        frozen.write_text(json.dumps(config), encoding="utf-8")
        compose = ["docker", "compose", "-p", project, "-f", str(frozen)]
        report["cleanup"] = "pending"
        try:
            started = time.perf_counter()
            try:
                up = latency._command([*compose, "up", "-d", "--pull", "never"], env=environment)
            finally:
                report["compose"]["setup_ms"] = (time.perf_counter() - started) * 1000
            if up.returncode:
                raise RuntimeError("fixture_setup_failed")
            started = time.perf_counter()
            try:
                latency._settle(inspector, project, args)
            finally:
                report["compose"]["settle_ms"] = (time.perf_counter() - started) * 1000
            expected = {
                "intended_edge": {
                    "source_service": "app",
                    "destination_service": "api",
                    "destination_port": 8000,
                },
                "observed_config": {"env_name": "UPSTREAM_URL"},
            }
            started = time.perf_counter()
            report["behavior_validated"] = latency.validate_behavior(
                "TCP_REACHABLE", latency._observe(inspector, project, expected)
            )
            report["compose"]["validation_ms"] = (time.perf_counter() - started) * 1000
            if not report["behavior_validated"]:
                raise RuntimeError("fixture_behavior_failed")
            yield project
        finally:
            started = time.perf_counter()
            try:
                down = latency._command(
                    [*compose, "down", "--timeout", "5"], timeout=60, env=environment
                )
                remaining = latency._resources(inspector, project)
                report["remaining_owned_resources"] = remaining
                clean = all(
                    s.get("cleanup") in {"complete", "not_needed"} for s in report["samples"]
                )
                report["cleanup"] = (
                    "complete"
                    if down.returncode == 0 and not any(remaining.values()) and clean
                    else "failed"
                )
            except ERRORS:
                report["cleanup"] = "failed"
            finally:
                report["compose"]["teardown_ms"] = (time.perf_counter() - started) * 1000
            if report["cleanup"] != "complete":
                report.update(status="failed", error="cleanup_uncertain")


def run_samples(args, inspector, project, report):
    references: dict[str, str] = {}
    seen = set()
    for round_index, case, variant in attempt_order(
        args.variants, args.cases, args.warmups + args.runs
    ):
        sample = {
            "variant": variant,
            "case": case,
            "round": round_index,
            "warmup": round_index < args.warmups,
            "first_launch": variant not in seen,
            "valid": False,
            "metrics": {},
        }
        seen.add(variant)
        report["samples"].append(sample)
        print(f"Round {round_index + 1}/{args.warmups + args.runs}: {case} / {variant}", flush=True)
        if case in {"static", "active"} and not latency._healthy(inspector.snapshot(project)):
            sample.update(error="fixture_not_healthy", cleanup="not_needed")
        else:
            run_attempt(args, inspector, project, variant, case, sample)
        digest = sample.get("diagnostic_digest")
        if sample["valid"] and digest:
            references.setdefault(case, digest)
            sample["diagnostics_equivalent"] = references[case] == digest
            if not sample["diagnostics_equivalent"]:
                sample.update(valid=False, error="diagnostic_facts_changed")
        if sample.get("cleanup") not in {"complete", "not_needed"}:
            raise RuntimeError("attempt_cleanup_uncertain")
        if inspector is not None and latency._resources(inspector, project)["helpers"]:
            sample.update(valid=False, error="probe_cleanup_leak", cleanup="failed")
            raise RuntimeError("probe_cleanup_leak")
        write_report(args, report)
    report["diagnostic_reference_digests"] = references
    report["status"] = "passed" if all(s["valid"] for s in report["samples"]) else "failed"


def render_markdown(report):
    metadata = report.get("metadata", {})
    lines = [
        "# DockRoute CLI cold-start benchmark",
        "",
        f"Status: **{report['status']}**; cleanup: **{report['cleanup']}**.",
        "",
        f"UTC date: {report['generated_at']}; Engine: {metadata.get('engine', 'not required')}; Compose: {metadata.get('compose', 'not required')}; Desktop backend: {metadata.get('desktop_backend', 'not required')}.",
        "",
        "Each attempt starts a fresh process. The first recorded launch per variant remains in the raw warm-ups. Measured distributions follow three discarded warm-up rounds; Windows/filesystem caches are not flushed, so these are warmed sequential launches, not guaranteed cold-cache measurements.",
        "",
        "Full process wall_ms and the CLI's report_total_ms are separate clocks. Compose setup, settling, validation, teardown and parent recovery are excluded from attempt wall_ms. Raw child output/configuration is omitted; diagnostic evidence is compared using normalized hashes.",
        "",
        "| Case | Variant | Metric | n | Median ms | IQR | Min | Max |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for case, variants in report["summary"].items():
        for variant, summary in variants.items():
            for metric in ("wall_ms", "report_total_ms"):
                if metric in summary["metrics"]:
                    values = summary["metrics"][metric]
                    lines.append(
                        f"| {case} | {variant} | {metric} | {values['n']} | {values['median']:.3f} | {values['iqr']:.3f} | {values['min']:.3f} | {values['max']:.3f} |"
                    )
    return "\n".join(
        [
            *lines,
            "",
            "IQR uses linear interpolation. No p95 is reported below forty samples. Warm-ups and failures remain in JSON and are excluded from measured distributions.",
            "",
        ]
    )


def write_report(args, report):
    report["summary"] = summarize(report["samples"], args.variants, args.cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    os.replace(temporary, args.output)
    args.output.with_suffix(".md").write_text(render_markdown(report), encoding="utf-8")


def main(argv=None):
    args = parse_args(argv)
    report: dict = {
        "schema_version": "1.0",
        "suite": "controlled-cli-coldstart",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "failed",
        "cleanup": "not_needed",
        "behavior_validated": False,
        "compose": {},
        "samples": [],
        "summary": {},
        "flags": {
            key: getattr(args, key)
            for key in (
                "variants",
                "cases",
                "runs",
                "warmups",
                "startup_timeout",
                "api_timeout",
                "timeout",
                "dns_timeout",
                "connect_timeout",
                "schedule",
                "health_timeout",
                "settle_seconds",
            )
        },
    }
    inspector = None
    exit_code = 1
    try:
        dependencies = {}
        for name in ("docker", "pyinstaller", "PyYAML"):
            try:
                dependencies[name] = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                dependencies[name] = "not_installed"
        report["metadata"] = {
            "date": report["generated_at"],
            "python": sys.version.split()[0],
            "dependencies": dependencies,
            "dependency_scope": "parent_runtime",
        }
        report["variants"] = variant_metadata(args)
        report["status"] = "running"
        if {"static", "active"}.intersection(args.cases):
            inspector = connect(timeout=args.api_timeout)
            report["metadata"].update(latency._metadata(inspector, SimpleNamespace(binary=None)))
            with owned_fixture(args, inspector, report) as project:
                run_samples(args, inspector, project, report)
        else:
            report["metadata"]["engine_required"] = False
            run_samples(args, None, None, report)
        report["artifacts_unchanged"] = report["variants"] == variant_metadata(args)
        if not report["artifacts_unchanged"]:
            report.update(status="failed", error="artifacts_changed")
        exit_code = 0 if report["status"] == "passed" else 1
    except latency.DockerUnavailable:
        report.update(status="unavailable", error="engine_or_compose_unavailable")
        exit_code = 3
    except KeyboardInterrupt:
        report.update(status="cancelled", error="cancelled")
        exit_code = 130
    except ERRORS:
        report.update(status="failed", error=report.get("error", "benchmark_boundary_failed"))
    finally:
        if inspector is not None:
            try:
                inspector.close()
            except ERRORS:
                report.update(status="failed", error="inspector_close_failed")
                exit_code = 1
        write_report(args, report)
        print(f"Cold-start report: {args.output} ({report['status']})", flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
