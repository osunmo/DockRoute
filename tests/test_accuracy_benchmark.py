"""Accuracy accounting keeps discovery, diagnosis and manual checks distinct."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def benchmark():
    path = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_accuracy.py"
    spec = importlib.util.spec_from_file_location("benchmark_accuracy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _track(code, *, discovered=True, valid=True, elapsed=100):
    return {
        "valid_json": valid,
        "elapsed_ms": elapsed,
        "target_discovered": discovered,
        "observed_code": code,
        "exit_code": 1
        if code not in {"UNKNOWN", "TCP_REACHABLE"}
        else 2
        if code == "UNKNOWN"
        else 0,
        "observations": [],
        "status": "UNKNOWN",
        "explanation": "Application protocol readiness was not tested.",
    }


def test_manual_check_does_not_raise_automatic_discovery_or_recall(benchmark):
    attempts = [
        {
            "scenario": "missing",
            "root_cause_code": "INVALID_SERVICE_HOSTNAME",
            "behavior_validated": True,
            "cleanup": "complete",
            "tracks": {
                "automatic_static": _track("UNKNOWN", discovered=False),
                "automatic_active": _track("UNKNOWN", discovered=False),
                "manual_check": _track("INVALID_SERVICE_HOSTNAME"),
            },
        },
        {
            "scenario": "working",
            "root_cause_code": None,
            "behavior_validated": True,
            "cleanup": "complete",
            "tracks": {
                "automatic_static": _track("UNKNOWN"),
                "automatic_active": _track("TCP_REACHABLE"),
                "manual_check": _track("TCP_REACHABLE"),
            },
        },
    ]
    metrics = benchmark.compute_metrics(attempts)
    auto = metrics["automatic_active"]
    manual = metrics["manual_check"]
    assert auto["root_cause_recall"] == 0.0
    assert auto["automatic_discovery_recall"] == 0.5
    assert manual["root_cause_recall"] == 1.0
    assert "automatic_discovery_recall" not in manual


def test_failures_and_abstentions_remain_in_denominators(benchmark):
    attempts = [
        {
            "scenario": "fault",
            "root_cause_code": "NETWORK_ISOLATION",
            "behavior_validated": True,
            "cleanup": "failed",
            "tracks": {"automatic_active": _track("UNKNOWN", valid=False)},
        },
        {
            "scenario": "control",
            "root_cause_code": None,
            "behavior_validated": True,
            "cleanup": "complete",
            "tracks": {"automatic_active": _track("INVALID_SERVICE_HOSTNAME")},
        },
    ]
    metrics = benchmark.compute_metrics(attempts)
    auto = metrics["automatic_active"]
    assert auto["root_cause_recall"] == 0.0
    assert auto["root_cause_precision"] == 0.0
    assert auto["control_false_positive_rate"] == 1.0
    assert auto["execution_coverage"] == 0.5
    assert metrics["cleanup_coverage"] == 0.5


def test_http_failure_control_requires_tcp_and_scope_disclaimer(benchmark):
    expected = {
        "runtime_kind": "http_error",
        "http_status": 503,
        "static_codes": ["UNKNOWN"],
        "active_codes": ["TCP_REACHABLE"],
        "expected_exit": {"static": 2, "active": 0},
        "required_evidence": ["probe"],
    }
    track = _track("TCP_REACHABLE")
    track.update(status="REACHABLE", observations=[{"kind": "probe"}])
    assert (
        benchmark.grade_track(
            expected, "automatic_active", track, {"http_status": 503, "source_tcp": "ok"}
        )
        == "passed"
    )
    track["explanation"] = "Everything is healthy."
    assert (
        benchmark.grade_track(
            expected, "automatic_active", track, {"http_status": 503, "source_tcp": "ok"}
        )
        == "failed"
    )
    track = _track("UNKNOWN")
    assert (
        benchmark.grade_track(
            {**expected, "accepted_uncertainty": ["UNKNOWN"]},
            "automatic_active",
            track,
            {"http_status": 503, "source_tcp": "ok"},
        )
        == "failed"
    )


def test_control_false_positive_rate_uses_executed_controls(benchmark):
    attempts = [
        {
            "root_cause_code": None,
            "behavior_validated": True,
            "tracks": {"automatic_active": _track("INVALID_SERVICE_HOSTNAME")},
        },
        {
            "root_cause_code": None,
            "behavior_validated": True,
            "tracks": {"automatic_active": _track("NO_VALID_REPORT", valid=False)},
        },
    ]
    metrics = benchmark.compute_metrics(attempts)["automatic_active"]
    assert metrics["control_false_positive_rate"] == 1.0
    assert metrics["control_valid_executions"] == 1
    assert metrics["control_cases"] == 2


def test_race_retry_keeps_unobserved_trial_and_uses_success(benchmark, monkeypatch, tmp_path):
    trials = iter(
        [
            ({"probe_state": "HELPER_EXECUTION_FAILED", "raw": {"stdout": "first"}}, False),
            ({"probe_state": "SOURCE_DISAPPEARED", "raw": {"stdout": "second"}}, True),
        ]
    )
    monkeypatch.setattr(benchmark, "_remove_during_probe_once", lambda *a, **kw: next(trials))
    track, injected = benchmark._remove_during_probe(
        object(), "owned", {"source_service": "app"}, ["dockroute"], tmp_path
    )
    assert injected is True
    assert track["probe_state"] == "SOURCE_DISAPPEARED"
    assert [trial["raw"]["stdout"] for trial in track["injection_trials"]] == [
        "first",
        "second",
    ]


def test_runtime_http_control_preserves_inconsistent_first_observation(benchmark, monkeypatch):
    samples = iter(
        [
            {"source_dns": "failed", "source_tcp": "timeout", "http_status": 500},
            {"source_dns": "ok", "source_tcp": "ok", "http_status": 500},
        ]
    )
    monkeypatch.setattr(benchmark, "_observe", lambda *_: next(samples))
    monkeypatch.setattr(benchmark.time, "sleep", lambda *_: None)
    source = SimpleNamespace(id="s", state="running", restart_count=0)
    destination = SimpleNamespace(id="d", state="running", restart_count=0)
    inspector = SimpleNamespace(
        client=SimpleNamespace(containers=SimpleNamespace(get=lambda *_: object()))
    )
    facts, valid = benchmark._behavior(
        inspector,
        "p",
        {
            "source_service": "app",
            "destination_service": "api",
            "runtime_kind": "http_error",
            "target_host": "api",
            "target_port": 8000,
            "http_status": 500,
        },
        {"app": source, "api": destination},
    )
    assert valid is True
    assert facts["source_tcp"] == "ok"
    assert len(facts["observer_samples"]) == 2
    assert facts["observer_samples"][0]["source_tcp"] == "timeout"


def test_cleanup_timeout_is_distinct_from_remaining_resources(benchmark, monkeypatch, tmp_path):
    monkeypatch.setattr(
        benchmark,
        "_command",
        lambda *_args, **_kwargs: {
            "exit_code": None,
            "timed_out": True,
            "raw": {},
            "elapsed_ms": 45000,
        },
    )
    monkeypatch.setattr(
        benchmark, "_owned_counts", lambda *_: {"containers": 0, "helpers": 0, "networks": 0}
    )
    status, detail = benchmark._cleanup(object(), "owned", ["docker", "compose"], tmp_path)
    assert status == "complete"
    assert detail["command_completed_successfully"] is False


def test_expanded_fixture_contracts_are_complete_and_image_pinned(benchmark):
    scenarios = benchmark._load_scenarios(
        Path(__file__).resolve().parents[1] / "scenarios-accuracy", None
    )
    assert len(scenarios) == 9
    assert {spec["runtime_kind"] for _, spec in scenarios} == {
        "missing_hostname",
        "wrong_port",
        "host_port_confusion",
        "http_error",
        "source_restart",
        "destination_restart",
        "disappearing_source",
        "recovery",
    }
    for directory, expected in scenarios:
        assert expected["expected_exit"]["static"] is not None
        assert expected["expected_exit"]["active"] is not None
        compose = directory.joinpath("compose.yaml").read_text(encoding="utf-8")
        assert compose.count(benchmark.FIXTURE_IMAGE) == 2
        assert "volumes:" not in compose
        assert "build:" not in compose


def test_source_fingerprint_covers_all_package_modules(benchmark):
    hashes = benchmark._source_revision()["source_files_sha256"]
    package_files = {
        path.relative_to(benchmark.ROOT).as_posix()
        for path in (benchmark.ROOT / "src" / "dockroute").rglob("*.py")
    }
    assert package_files <= set(hashes)
    assert "scripts/benchmark_accuracy.py" in hashes


def test_cli_identity_records_measured_binary_version_and_hash(benchmark, monkeypatch, tmp_path):
    binary = tmp_path / "cli"
    binary.write_bytes(b"tested executable")
    monkeypatch.setattr(
        benchmark,
        "_command",
        lambda *a, **kw: {"exit_code": 0, "stdout_text": "DockRoute 9.1.2\n", "raw": {}},
    )
    identity = benchmark._cli_identity(binary, tmp_path)
    assert identity["version"] == "9.1.2"
    assert identity["binary_sha256"] == benchmark._sha(binary)
    assert identity["verified"] is True
