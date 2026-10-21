"""Cold launches exercise the runner with subprocess and Docker boundary fakes."""

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_core import node
from test_latency_benchmark import FakeInspector, healthy_report

from dockroute.diagnostics import diagnose
from dockroute.models import Connection, Evidence, ProbeResult, ProbeTrace
from dockroute.reporting import make_report


def test_controlled_runner_is_available():
    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_coldstart.py"
    assert script.is_file(), "the controlled cold-start runner is missing"


@pytest.fixture
def coldstart():
    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_coldstart.py"
    assert script.is_file(), "the controlled cold-start runner is missing"
    spec = importlib.util.spec_from_file_location("coldstart_benchmark", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def diagnostic_report(case="active"):
    containers = [node(s, project="owned-project", health="healthy") for s in ("app", "api")]
    edge = Connection(
        "app-id",
        "app",
        "api",
        8000,
        evidence=(Evidence("environment", "UPSTREAM_URL targets api:8000"),),
    )
    worker = healthy_report()["findings"][0]["probe"]["trace"][0]["timings"]
    probe = (
        ProbeResult(
            dns="ok",
            tcp="ok",
            state="SUCCESS",
            dns_equivalent=True,
            listener_state="SKIPPED",
            listener_skipped=True,
            execution_id="a" * 32,
            trace=(ProbeTrace("source", "worker_startup", "SUCCESS", 2100, timings=worker),),
        )
        if case == "active"
        else None
    )
    return json.loads(
        json.dumps(
            make_report(
                "owned-project",
                containers,
                [diagnose(edge, containers, probe)],
                probe=case == "active",
                total_ms=3500,
                timing=True,
            )
        )
    )


def test_order_balances_every_variant_and_case_without_overlapping_rounds(coldstart):
    assert list(
        coldstart.attempt_order(("old-source", "optimized-source"), ("version", "active"), 2)
    ) == [
        (0, "version", "old-source"),
        (0, "version", "optimized-source"),
        (0, "active", "old-source"),
        (0, "active", "optimized-source"),
        (1, "version", "optimized-source"),
        (1, "version", "old-source"),
        (1, "active", "optimized-source"),
        (1, "active", "old-source"),
    ]


def test_summary_preserves_failures_discards_warmups_and_separates_report_clock(coldstart):
    samples = [
        {
            "variant": "old-source",
            "case": "active",
            "warmup": True,
            "valid": True,
            "metrics": {"wall_ms": 900},
        },
        {
            "variant": "old-source",
            "case": "active",
            "warmup": False,
            "valid": False,
            "metrics": {"wall_ms": 800},
        },
        {
            "variant": "old-source",
            "case": "active",
            "warmup": False,
            "valid": True,
            "metrics": {"wall_ms": 10, "report_total_ms": 2},
        },
        {
            "variant": "old-source",
            "case": "active",
            "warmup": False,
            "valid": True,
            "metrics": {"wall_ms": 20, "report_total_ms": 4},
        },
    ]
    summary = coldstart.summarize(samples, ("old-source",), ("active",))["active"]["old-source"]
    assert summary["warmups_discarded"] == 1 and summary["failed"] == 1
    assert summary["metrics"]["wall_ms"] == {"n": 2, "median": 15, "iqr": 5, "min": 10, "max": 20}
    assert summary["metrics"]["report_total_ms"]["median"] == 3


@pytest.mark.parametrize(
    "arguments",
    [
        ["--runs", "19"],
        ["--warmups", "2"],
        ["--variants", "old-source,old-source"],
        ["--cases", "other"],
    ],
)
def test_parser_refuses_uncontrolled_dataset(coldstart, arguments):
    with pytest.raises(SystemExit):
        coldstart.parse_args(arguments)


def test_source_snapshot_environment_excludes_current_source_and_cpu_override(
    coldstart, monkeypatch, tmp_path
):
    monkeypatch.setenv("DOCKROUTE_HELPER_CPUS", "0")
    monkeypatch.setenv("PYTHONPATH", "current-source-must-not-leak")
    args = coldstart.parse_args(["--old-source", str(tmp_path), "--python", sys.executable])
    environment = coldstart.variant_environment(args, "old-source")
    assert environment["PYTHONPATH"] == str(tmp_path.resolve())
    assert "DOCKROUTE_HELPER_CPUS" not in environment
    assert "PYTHONPATH" not in coldstart.variant_environment(args, "old-onefile")
    command = coldstart.variant_command(
        args, "old-source", "active", "owned-project", control=tmp_path
    )
    assert command[:4] == [str(Path(sys.executable).resolve()), "-m", "dockroute", "doctor"]
    assert command[command.index("--startup-timeout") + 1] == "30.0"
    assert command[command.index("--api-timeout") + 1] == "20.0"
    assert command[command.index("--dns-timeout") + 1] == "2.0"
    assert command[command.index("--connect-timeout") + 1] == "1.0"
    assert "--timing" in command and "--_benchmark-control" in command


@pytest.mark.parametrize(
    "case,exit_code,valid",
    [("static", 2, True), ("static", 0, False), ("active", 0, True), ("active", 2, False)],
)
def test_expected_diagnostic_exit_is_case_specific(coldstart, case, exit_code, valid):
    sample = coldstart.extract_result(case, exit_code, json.dumps(diagnostic_report(case)))
    assert sample["valid"] is valid
    assert sample["metrics"]["report_total_ms"] == 3500


def test_equivalence_ignores_resource_identity_but_detects_evidence_changes(coldstart):
    original = diagnostic_report()
    original["findings"][0]["observations"].append(
        {"kind": "identity", "detail": "app-id on owned-project_default"}
    )
    for service in original["services"]:
        service["networks"] = [{"id": "network-id", "name": "owned-project_default"}]
    renamed = copy.deepcopy(original)
    renamed["project"] = "another-project"
    next(s for s in renamed["services"] if s["service"] == "app").update(
        container_id="different-id", container_name="different-name"
    )
    for service in renamed["services"]:
        service["networks"] = [{"id": "different-network", "name": "another-project_default"}]
    renamed["findings"][0]["source_container"] = "different-id"
    renamed["findings"][0]["observations"][-1]["detail"] = "different-id on another-project_default"
    renamed["timings"]["total_ms"] = 123
    assert coldstart.diagnosis_signature(original) == coldstart.diagnosis_signature(renamed)
    renamed["findings"][0]["observations"][0]["detail"] = (
        "Source is running; health=healthy; restarts=1"
    )
    assert coldstart.diagnosis_signature(original) != coldstart.diagnosis_signature(renamed)


def test_projection_never_saves_raw_configuration_or_child_output(coldstart):
    report = diagnostic_report()
    report["private"] = "credential-secret"
    report["findings"][0]["observations"][0]["detail"] += " private-evidence-secret"
    sample = coldstart.extract_result("active", 0, json.dumps(report))
    assert sample["valid"]
    assert "secret" not in json.dumps(sample)


def test_signature_retains_actual_destination_service_attribution(coldstart):
    original = diagnostic_report()
    changed = copy.deepcopy(original)
    changed["findings"][0]["destination_service"] = None
    assert coldstart.diagnosis_signature(original) != coldstart.diagnosis_signature(changed)


@pytest.mark.parametrize("case", ["version", "help", "static", "active"])
def test_critical_coverage_uses_only_metrics_needed_by_each_case(coldstart, case):
    metrics = {"wall_ms": 10}
    if case in {"static", "active"}:
        metrics["report_total_ms"] = 2
    if case == "active":
        metrics.update(
            {
                "source.worker_startup." + key: 1
                for key in ("host_ready_ms", "vm_startup_ms", "observation_overhead_ms")
            }
        )
    samples = [
        {"variant": "old-source", "case": case, "warmup": False, "valid": True, "metrics": metrics}
        for _ in range(20)
    ]
    summary = coldstart.summarize(samples, ("old-source",), (case,))[case]["old-source"]
    assert summary["timing_coverage_complete"] is True
    assert summary["required_metric_counts"]["wall_ms"] == 20
    assert (
        len(summary["required_metric_counts"])
        == {"version": 1, "help": 1, "static": 2, "active": 5}[case]
    )


@pytest.mark.parametrize(
    "failure", [OSError("private failure"), UnicodeError("private decode failure")]
)
def test_live_child_is_stopped_and_reaped_after_communication_failure(
    coldstart, monkeypatch, tmp_path, failure
):
    inspector, _ = install_boundary(coldstart, monkeypatch, tmp_path)
    args = coldstart.parse_args(
        ["--variants", "old-source", "--old-source", str(tmp_path / "old-source")]
    )
    actions = []

    class Child:
        returncode = None

        def __init__(self, arguments, **kwargs):
            self.control = Path(arguments[arguments.index("--_benchmark-control") + 1])

        def communicate(self, **kwargs):
            if not actions:
                actions.append("failure")
                raise failure
            assert (self.control / "cancel").is_file()
            actions.append("reaped")
            self.returncode = 130
            return "", "private stderr"

        def kill(self):
            pytest.fail("cooperative failure recovery unnecessarily killed child")

    def recover(*args, **kwargs):
        actions.append("recovered")
        return {"cleanup": "complete", "lease_status": "valid"}

    monkeypatch.setattr(coldstart.subprocess, "Popen", Child)
    monkeypatch.setattr(coldstart.latency, "recover_leased_helpers", recover)
    sample = {}
    coldstart.run_attempt(args, inspector, "owned-project", "old-source", "active", sample)
    assert actions == ["failure", "reaped", "recovered"]
    assert not sample["valid"] and sample["cleanup"] == "complete"
    assert "private" not in json.dumps(sample)


def test_wall_clock_stops_before_parent_report_validation(coldstart, monkeypatch, tmp_path):
    install_boundary(coldstart, monkeypatch, tmp_path)
    args = coldstart.parse_args(
        ["--variants", "old-source", "--old-source", str(tmp_path / "old-source")]
    )
    now = [0.0]

    class Child:
        returncode = None

        def __init__(self, *args, **kwargs):
            pass

        def communicate(self, **kwargs):
            now[0] = 2.0
            self.returncode = 0
            return "DockRoute 0.3.0\n", ""

    original = coldstart.extract_result

    def extract(*args):
        now[0] = 8.0
        return original(*args)

    monkeypatch.setattr(coldstart.time, "perf_counter", lambda: now[0])
    monkeypatch.setattr(coldstart.subprocess, "Popen", Child)
    monkeypatch.setattr(coldstart, "extract_result", extract)
    sample = {}
    coldstart.run_attempt(args, None, None, "old-source", "version", sample)
    assert sample["metrics"]["wall_ms"] == 2000.0


def install_boundary(coldstart, monkeypatch, tmp_path):
    inspector = FakeInspector()
    calls = []
    for variant in ("old-source", "optimized-source"):
        package = tmp_path / variant / "dockroute"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("__version__ = '0.3.0'\n")

    def command(arguments, **kwargs):
        calls.append(arguments)
        if "config" in arguments:
            inspector.project = arguments[3]
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "services": {s: {"image": "python:3.12-alpine"} for s in ("app", "api")},
                        "networks": {"default": {"name": inspector.project + "_default"}},
                    }
                ),
            )
        if arguments[:3] == ["docker", "compose", "version"]:
            return SimpleNamespace(returncode=0, stdout="5.5.1\n")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    class Child:
        def __init__(self, arguments, **kwargs):
            calls.append(arguments)
            self.arguments = arguments
            self.returncode = None
            if "--_benchmark-control" in arguments:
                directory = Path(arguments[arguments.index("--_benchmark-control") + 1])
                (directory / "lease.json").write_text(
                    json.dumps(
                        {"execution_id": "a" * 32, "project": inspector.project, "helpers": []}
                    )
                )

        def communicate(self, **kwargs):
            case = "active" if "--probe" in self.arguments else "static"
            if "--version" in self.arguments:
                self.returncode = 0
                return "DockRoute 0.3.0\n", "private stderr"
            if "--help" in self.arguments:
                self.returncode = 0
                return "usage: dockroute {doctor,check}\n", "private stderr"
            self.returncode = 0 if case == "active" else 2
            return json.dumps(diagnostic_report(case)), "private stderr"

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(coldstart.latency, "_command", command)
    monkeypatch.setattr(coldstart, "connect", lambda **kwargs: inspector)
    monkeypatch.setattr(coldstart.subprocess, "Popen", Child)
    monkeypatch.setattr(
        coldstart.latency, "_observe", lambda *args: {"app_request": "ok", "source_tcp": "ok"}
    )
    monkeypatch.setattr(coldstart.latency.time, "sleep", lambda seconds: None)
    return inspector, calls


def test_version_and_help_need_no_engine(coldstart, monkeypatch, tmp_path):
    inspector, calls = install_boundary(coldstart, monkeypatch, tmp_path)
    monkeypatch.setattr(
        coldstart, "connect", lambda **kwargs: pytest.fail("version/help contacted Engine")
    )
    output = tmp_path / "simple.json"
    assert (
        coldstart.main(
            [
                "--variants",
                "old-source",
                "--cases",
                "version,help",
                "--old-source",
                str(tmp_path / "old-source"),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    report = json.loads(output.read_text())
    assert len(report["samples"]) == 46 and report["cleanup"] == "not_needed"
    assert not inspector.closed and not any(c[0] == "docker" for c in calls)
    assert report["samples"][0]["first_launch"] is True
    assert all(not s["first_launch"] for s in report["samples"][1:])


def test_diagnostic_dataset_owns_frozen_fixture_and_validates_all_combinations(
    coldstart, monkeypatch, tmp_path
):
    inspector, calls = install_boundary(coldstart, monkeypatch, tmp_path)
    output = tmp_path / "complete.json"
    assert (
        coldstart.main(
            [
                "--variants",
                "old-source,optimized-source",
                "--cases",
                "static,active",
                "--old-source",
                str(tmp_path / "old-source"),
                "--optimized-source",
                str(tmp_path / "optimized-source"),
                "--settle-seconds",
                "0",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    report = json.loads(output.read_text())
    assert report["status"] == "passed" and report["cleanup"] == "complete"
    assert len(report["samples"]) == 92 and sum(s["warmup"] for s in report["samples"]) == 12
    assert report["behavior_validated"] and inspector.closed
    assert all(
        report["summary"][case][variant]["metrics"]["wall_ms"]["n"] == 20
        for case in ("static", "active")
        for variant in ("old-source", "optimized-source")
    )
    compose = [c for c in calls if c[:2] == ["docker", "compose"] and "version" not in c]
    assert Path(compose[1][5]).name == "compose.json" and compose[-1][5] == compose[1][5]
    assert "down" in compose[-1] and "-v" not in compose[-1]
    assert set(report["compose"]) >= {"setup_ms", "settle_ms", "teardown_ms"}


def test_invalid_binary_fails_before_engine_or_fixture(coldstart, monkeypatch, tmp_path):
    monkeypatch.setattr(
        coldstart, "connect", lambda **kwargs: pytest.fail("invalid variant contacted Engine")
    )
    output = tmp_path / "missing.json"
    assert (
        coldstart.main(
            [
                "--variants",
                "old-onefile",
                "--old-onefile",
                str(tmp_path / "missing.exe"),
                "--output",
                str(output),
            ]
        )
        == 1
    )
    report = json.loads(output.read_text())
    assert report["samples"] == [] and report["cleanup"] == "not_needed"


def test_active_cancellation_publishes_marker_and_reuses_owned_recovery(
    coldstart, monkeypatch, tmp_path
):
    inspector, _ = install_boundary(coldstart, monkeypatch, tmp_path)
    args = coldstart.parse_args(
        ["--variants", "old-source", "--old-source", str(tmp_path / "old-source")]
    )
    observations = []

    class Child:
        returncode = None

        def __init__(self, arguments, **kwargs):
            self.control = Path(arguments[arguments.index("--_benchmark-control") + 1])

        def communicate(self, **kwargs):
            if not observations:
                observations.append("interrupt")
                raise KeyboardInterrupt
            assert (self.control / "cancel").is_file()
            self.returncode = 130
            return "", "private error"

        def kill(self):
            pytest.fail("cooperatively stopped child was killed")

    def recover(inspector, directory, project, **kwargs):
        observations.append("recovered")
        return {"cleanup": "complete", "lease_status": "valid"}

    monkeypatch.setattr(coldstart.subprocess, "Popen", Child)
    monkeypatch.setattr(coldstart.latency, "recover_leased_helpers", recover)
    sample = {}
    with pytest.raises(KeyboardInterrupt):
        coldstart.run_attempt(args, inspector, "owned-project", "old-source", "active", sample)
    assert sample["error"] == "cancelled" and sample["cleanup"] == "complete"
    assert sample["metrics"]["wall_ms"] >= 0 and observations == ["interrupt", "recovered"]


def test_communication_failure_kill_fallback_keeps_cleanup_uncertain(
    coldstart, monkeypatch, tmp_path
):
    inspector, _ = install_boundary(coldstart, monkeypatch, tmp_path)
    args = coldstart.parse_args(
        ["--variants", "old-source", "--old-source", str(tmp_path / "old-source")]
    )
    actions = []

    class Child:
        returncode = None

        def __init__(self, arguments, **kwargs):
            self.control = Path(arguments[arguments.index("--_benchmark-control") + 1])

        def communicate(self, **kwargs):
            if not actions:
                actions.append("io_failure")
                raise OSError("private failure")
            if actions[-1] != "killed":
                assert (self.control / "cancel").is_file()
                actions.append("grace_expired")
                raise subprocess.TimeoutExpired("known-child", 5)
            self.returncode = -9
            actions.append("reaped")
            return "", "private output"

        def kill(self):
            actions.append("killed")

    def recover(*args, **kwargs):
        assert kwargs["hard_killed"] is True
        actions.append("recovered")
        return {"cleanup": "uncertain", "lease_status": "valid"}

    monkeypatch.setattr(coldstart.subprocess, "Popen", Child)
    monkeypatch.setattr(coldstart.latency, "recover_leased_helpers", recover)
    sample = {}
    coldstart.run_attempt(args, inspector, "owned-project", "old-source", "active", sample)
    assert actions == ["io_failure", "grace_expired", "killed", "reaped", "recovered"]
    assert not sample["valid"] and sample["cleanup"] == "uncertain"


def test_main_saves_partial_cancelled_dataset_after_owned_teardown(
    coldstart, monkeypatch, tmp_path
):
    inspector, calls = install_boundary(coldstart, monkeypatch, tmp_path)

    def interrupt(args, inspector, project, variant, case, sample):
        sample.update(valid=False, error="cancelled", metrics={"wall_ms": 12}, cleanup="complete")
        raise KeyboardInterrupt

    monkeypatch.setattr(coldstart, "run_attempt", interrupt)
    output = tmp_path / "cancelled.json"
    assert (
        coldstart.main(
            [
                "--variants",
                "old-source",
                "--cases",
                "active",
                "--old-source",
                str(tmp_path / "old-source"),
                "--settle-seconds",
                "0",
                "--output",
                str(output),
            ]
        )
        == 130
    )
    report = json.loads(output.read_text())
    assert report["status"] == "cancelled" and report["cleanup"] == "complete"
    assert len(report["samples"]) == 1 and report["samples"][0]["metrics"]["wall_ms"] == 12
    assert inspector.closed and any("down" in c for c in calls)
