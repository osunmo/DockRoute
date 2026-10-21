"""Controlled latency experiments exercise real runner logic with Docker boundary fakes."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from docker.errors import NotFound

from dockroute.models import Container


@pytest.fixture
def latency():
    script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_latency.py"
    assert script.is_file(), "the controlled latency benchmark runner is missing"
    spec = importlib.util.spec_from_file_location("latency_benchmark", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def healthy_report():
    return {
        "schema_version": "3.0",
        "status": "REACHABLE",
        "services": [
            {"service": "app", "health": "healthy"},
            {"service": "api", "health": "healthy"},
        ],
        "findings": [
            {
                "code": "TCP_REACHABLE",
                "status": "REACHABLE",
                "probe": {
                    "dns": "ok",
                    "tcp": "ok",
                    "state": "SUCCESS",
                    "cleanup": "complete",
                    "listener_state": "SKIPPED",
                    "execution_id": "a" * 32,
                    "trace": [
                        {
                            "role": "source",
                            "stage": "worker_startup",
                            "elapsed_ms": 2100.0,
                            "timings": {
                                "import_ms": 10.0,
                                "ready_ms": 11.0,
                                "host_ready_ms": 2100.0,
                                "vm_startup_ms": 40.0,
                                "observation_overhead_ms": 2060.0,
                                "polls": 2,
                                "empty_polls": 1,
                                "reloads": 1,
                                "http_requests": 5,
                            },
                        }
                    ],
                },
            }
        ],
        "timings": {
            "total_ms": 3500.0,
            "stages": [
                {
                    "role": "source",
                    "stage": "worker_startup",
                    "count": 1,
                    "total_ms": 2100.0,
                    "max_ms": 2100.0,
                }
            ],
            "requests": [
                {
                    "role": "source",
                    "stage": "worker_startup",
                    "method": "GET",
                    "path": "/containers/{id}/logs",
                    "count": 2,
                    "total_ms": 1900.0,
                    "max_ms": 1000.0,
                }
            ],
        },
    }


class FakeInspector:
    def __init__(self):
        self.started = False
        self.closed = False
        self.project = None
        self.floor = None
        self.removed = []
        self.queries = []
        self.helpers = {}
        self.client = SimpleNamespace(api=self)

    def containers(self, **kwargs):
        self.queries.append(kwargs)
        labels = kwargs.get("filters", {}).get("label", [])
        return [
            attrs
            for attrs in self.helpers.values()
            if all(
                (attrs.get("Config") or {}).get("Labels", {}).get(key) == value
                for key, value in (label.split("=", 1) for label in labels)
            )
        ]

    def networks(self, **kwargs):
        self.queries.append(kwargs)
        return []

    def snapshot(self, project):
        assert project == self.project
        return [
            Container(s + "-id", s + "-1", project, s, state="running", health="healthy")
            for s in ("app", "api")
        ]

    def inspect_container(self, name):
        if name in self.helpers:
            return self.helpers[name]
        for helper in self.helpers.values():
            if helper["Id"] == name:
                return helper
        if self.floor is None:
            raise NotFound("not found")
        return self.floor

    def remove_container(self, identifier, **kwargs):
        self.removed.append((identifier, kwargs))
        for name, helper in list(self.helpers.items()):
            if helper["Id"] == identifier:
                del self.helpers[name]
        self.floor = None

    def version(self):
        return {"Version": "29.8.1", "Os": "linux"}

    def info(self):
        return {
            "OperatingSystem": "Docker Desktop",
            "KernelVersion": "6.6.0-microsoft-standard-WSL2",
        }

    def inspect_image(self, name):
        return {"Id": "sha256:" + "c" * 64, "RepoDigests": ["python@sha256:" + "d" * 64]}

    def close(self):
        self.closed = True


@pytest.fixture
def boundary(latency, monkeypatch):
    inspector = FakeInspector()
    calls = []
    reports = []

    def command(arguments, **kwargs):
        calls.append((arguments, kwargs))
        if arguments[:3] == ["docker", "compose", "version"]:
            return SimpleNamespace(returncode=0, stdout="5.5.1\n")
        if "config" in arguments:
            inspector.project = arguments[3]
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "services": {
                            "app": {"image": "python:3.12-alpine"},
                            "api": {"image": "python:3.12-alpine"},
                        },
                        "networks": {"default": {"name": inspector.project + "_default"}},
                    }
                ),
            )
        if "up" in arguments:
            inspector.started = True
        if "down" in arguments:
            inspector.started = False
        if "doctor" in arguments:
            result = reports.pop(0) if reports else healthy_report()
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(result),
                stderr="private stderr must not enter report",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(latency, "_command", command)

    def child(arguments, **kwargs):
        control = Path(arguments[arguments.index("--_benchmark-control") + 1])
        project = arguments[arguments.index("--project") + 1]
        (control / "lease.json").write_text(json.dumps(owned_lease(project)), encoding="utf-8")
        result = command(arguments, **kwargs)
        return SimpleNamespace(
            returncode=result.returncode, communicate=lambda **kw: (result.stdout, result.stderr)
        )

    monkeypatch.setattr(latency.subprocess, "Popen", child)
    monkeypatch.setattr(latency, "connect", lambda **kwargs: inspector)
    monkeypatch.setattr(
        latency,
        "_observe",
        lambda *a: {"app_request": "ok", "source_tcp": "ok", "source_dns": "ok"},
    )
    monkeypatch.setattr(latency.time, "sleep", lambda seconds: None)
    return SimpleNamespace(module=latency, inspector=inspector, calls=calls, reports=reports)


def owned_lease(project="owned-project", execution="a" * 32, run="b" * 32):
    return {
        "execution_id": execution,
        "project": project,
        "helpers": [
            {
                "name": "dockroute-probe-" + run,
                "labels": {
                    "io.dockroute.helper": "true",
                    "io.dockroute.project": project,
                    "io.dockroute.run": run,
                    "io.dockroute.execution": execution,
                },
            }
        ],
    }


def owned_attrs(lease):
    helper = lease["helpers"][0]
    return {
        "Id": "c" * 64,
        "Name": "/" + helper["name"],
        "Config": {"Labels": helper["labels"].copy()},
    }


def test_statistics_use_linear_iqr_and_only_name_p95_with_forty_samples(latency):
    assert latency.distribution([1, 2, 3, 4]) == {
        "n": 4,
        "median": 2.5,
        "iqr": 1.5,
        "min": 1,
        "max": 4,
    }
    assert "p95" not in latency.distribution(range(20))
    assert latency.distribution(range(1, 41))["p95"] == 38


def test_conditions_rotate_and_each_round_contains_each_condition_once(latency):
    assert list(latency.condition_order(("poll", "poll-unlimited", "floor"), 3)) == [
        (0, "poll"),
        (0, "poll-unlimited"),
        (0, "floor"),
        (1, "poll-unlimited"),
        (1, "floor"),
        (1, "poll"),
        (2, "floor"),
        (2, "poll"),
        (2, "poll-unlimited"),
    ]


def test_statistics_discard_warmups_and_failures_but_preserve_sample_counts(latency):
    samples = [
        {"condition": "poll", "warmup": True, "valid": True, "metrics": {"wall_ms": 1000}},
        {"condition": "poll", "warmup": False, "valid": False, "metrics": {"wall_ms": 999}},
        {"condition": "poll", "warmup": False, "valid": True, "metrics": {"wall_ms": 10}},
        {"condition": "poll", "warmup": False, "valid": True, "metrics": {"wall_ms": 20}},
    ]
    summary = latency.summarize(samples, ("poll",))["poll"]
    assert summary["warmups_discarded"] == 1
    assert summary["failed"] == 1
    assert summary["metrics"]["wall_ms"] == {"n": 2, "median": 15, "iqr": 5, "min": 10, "max": 20}


@pytest.mark.parametrize(
    "arguments",
    [
        ["--runs", "19"],
        ["--warmups", "2"],
        ["--conditions", "poll,poll"],
        ["--conditions", "arbitrary"],
    ],
)
def test_parser_refuses_uncontrolled_experiment(latency, arguments):
    with pytest.raises(SystemExit):
        latency.parse_args(arguments)


def test_source_commands_and_cpu_override_are_condition_specific(latency, monkeypatch):
    monkeypatch.setenv("DOCKROUTE_HELPER_CPUS", "9")
    args = latency.parse_args(["--startup-timeout", "30", "--api-timeout", "20"])
    command = latency.probe_command(args, "owned-project", "poll-unlimited")
    assert command[:3] == [sys.executable, "-m", "dockroute"]
    assert command[3:12] == [
        "doctor",
        "--project",
        "owned-project",
        "--probe",
        "--timing",
        "--observe",
        "poll",
        "--schedule",
        "conditional",
    ]
    assert "--dns-timeout" not in command and "--connect-timeout" not in command
    assert latency.condition_environment("poll-unlimited")["DOCKROUTE_HELPER_CPUS"] == "0"
    assert "DOCKROUTE_HELPER_CPUS" not in latency.condition_environment("poll")
    assert "DOCKROUTE_HELPER_CPUS" not in latency.condition_environment("stream")
    final = latency.parse_args(
        [
            "--binary",
            "example.exe",
            "--dns-timeout",
            "2",
            "--connect-timeout",
            "1",
            "--schedule",
            "conditional",
        ]
    )
    command = latency.probe_command(final, "owned-project", "stream")
    assert command[0].endswith("example.exe") and "-m" not in command
    assert command[command.index("--schedule") + 1] == "conditional"
    assert command[command.index("--dns-timeout") + 1] == "2.0"


@pytest.mark.parametrize("failure", ["code", "tcp", "timings", "unhealthy", "nonfinite"])
def test_successful_exit_does_not_turn_missing_evidence_into_valid_sample(latency, failure):
    report = healthy_report()
    if failure == "code":
        report["findings"].append({"code": "UNKNOWN"})
    elif failure == "tcp":
        report["findings"][0]["probe"]["tcp"] = "unknown"
    elif failure == "timings":
        del report["timings"]
    elif failure == "unhealthy":
        report["services"][0]["health"] = "starting"
    else:
        report["timings"]["total_ms"] = float("nan")
    assert not latency.extract_probe_sample(report)["valid"]


def test_timing_projection_keeps_worker_costs_and_never_raw_configuration(latency):
    report = healthy_report()
    report["private"] = "credentials"
    trace = report["findings"][0]["probe"]["trace"][0]
    trace["helper_configuration"] = {"environment": {"SECRET": "private"}}
    trace["stderr"] = "private worker output"
    report["timings"]["requests"].append(
        {
            "role": "source",
            "stage": "worker_startup",
            "method": "GET",
            "path": "/containers/secret-name/logs?secret=value",
            "count": 1,
            "total_ms": 1,
            "max_ms": 1,
        }
    )
    sample = latency.extract_probe_sample(report)
    assert sample["valid"]
    assert sample["metrics"]["source.worker_startup.observation_overhead_ms"] == 2060
    assert sample["metrics"]["source.worker_startup.polls"] == 2
    assert sample["metrics"]["total_ms"] == 3500
    serialized = json.dumps(sample)
    assert all(
        secret not in serialized
        for secret in ("private", "credentials", "SECRET", "secret-name", "secret=value")
    )
    assert len(sample["timings"]["requests"]) == 1


def test_main_freezes_owned_fixture_interleaves_and_writes_both_reports(boundary, tmp_path):
    output = tmp_path / "samples.json"
    assert (
        boundary.module.main(
            [
                "--conditions",
                "poll,poll-unlimited,floor",
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
    assert len(report["samples"]) == 69
    assert sum(sample["warmup"] for sample in report["samples"]) == 9
    assert [sample["condition"] for sample in report["samples"][:6]] == [
        "poll",
        "poll-unlimited",
        "floor",
        "poll-unlimited",
        "floor",
        "poll",
    ]
    assert all(summary["metrics"]["wall_ms"]["n"] == 20 for summary in report["summary"].values())
    assert set(report["compose"]) >= {"setup_ms", "settle_ms", "teardown_ms"}
    assert report["metadata"]["engine"] == "29.8.1"
    assert report["metadata"]["desktop_backend"] == "wsl2"
    assert output.with_suffix(".md").is_file()
    compose_calls = [
        c for c, _ in boundary.calls if c[:2] == ["docker", "compose"] and "version" not in c
    ]
    assert compose_calls[0][5].endswith("06-healthy-control\\compose.yaml") or compose_calls[0][
        5
    ].endswith("06-healthy-control/compose.yaml")
    assert Path(compose_calls[1][5]).name == "compose.json"
    assert compose_calls[-1][5] == compose_calls[1][5]
    assert "down" in compose_calls[-1] and "-v" not in compose_calls[-1]
    floors = [c for c, _ in boundary.calls if c[:2] == ["docker", "run"]]
    assert len(floors) == 23
    assert all(
        "--rm" in c
        and c[c.index("--pull") + 1] == "never"
        and c[-2:] == ["python:3.12-alpine", "true"]
        for c in floors
    )
    assert len({c[c.index("--name") + 1] for c in floors}) == 23
    assert boundary.inspector.closed


def test_failed_samples_remain_raw_and_reduce_valid_count(boundary, tmp_path):
    boundary.reports.extend([healthy_report() for _ in range(3)])
    bad = healthy_report()
    bad["findings"][0]["probe"]["tcp"] = "refused"
    boundary.reports.append(bad)
    output = tmp_path / "failed.json"
    assert (
        boundary.module.main(
            ["--conditions", "poll", "--settle-seconds", "0", "--output", str(output)]
        )
        == 1
    )
    report = json.loads(output.read_text())
    assert len(report["samples"]) == 23
    assert not report["samples"][3]["valid"]
    assert report["summary"]["poll"]["metrics"]["wall_ms"]["n"] == 19
    assert report["cleanup"] == "complete"


def test_cleanup_failure_invalidates_dataset(boundary, monkeypatch, tmp_path):
    command = boundary.module._command

    def fail_down(arguments, **kwargs):
        if "down" in arguments:
            return SimpleNamespace(returncode=1, stdout="private failure")
        return command(arguments, **kwargs)

    monkeypatch.setattr(boundary.module, "_command", fail_down)
    output = tmp_path / "cleanup.json"
    assert (
        boundary.module.main(
            ["--conditions", "poll", "--settle-seconds", "0", "--output", str(output)]
        )
        == 1
    )
    report = json.loads(output.read_text())
    assert report["cleanup"] == "failed" and report["status"] == "failed"
    assert "private failure" not in output.read_text()


def test_floor_timeout_only_removes_helper_with_exact_runner_ownership(latency, monkeypatch):
    inspector = FakeInspector()
    args = latency.parse_args(["--conditions", "floor"])

    def timeout(arguments, **kwargs):
        label = arguments[arguments.index("--label") + 1]
        key, value = label.split("=", 1)
        inspector.floor = {"Id": "owned-floor-id", "Config": {"Labels": {key: value}}}
        raise subprocess.TimeoutExpired(arguments, 10)

    monkeypatch.setattr(latency, "_command", timeout)
    sample = latency.floor_sample(args, inspector, "run-owner")
    assert not sample["valid"] and sample["cleanup"] == "uncertain"
    assert inspector.removed == [("owned-floor-id", {"force": True})]

    def foreign(arguments, **kwargs):
        inspector.floor = {
            "Id": "foreign-id",
            "Config": {"Labels": {"io.dockroute.latency.owner": "someone-else"}},
        }
        raise subprocess.TimeoutExpired(arguments, 10)

    monkeypatch.setattr(latency, "_command", foreign)
    inspector.removed.clear()
    sample = latency.floor_sample(args, inspector, "run-owner")
    assert sample["cleanup"] == "ownership_unconfirmed"
    assert inspector.removed == []


def test_invalid_fixture_is_never_started(boundary, monkeypatch, tmp_path):
    command = boundary.module._command

    def unsafe(arguments, **kwargs):
        if "config" in arguments:
            boundary.inspector.project = arguments[3]
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {"services": {"app": {"image": "python:3.12-alpine", "privileged": True}}}
                ),
            )
        return command(arguments, **kwargs)

    monkeypatch.setattr(boundary.module, "_command", unsafe)
    output = tmp_path / "unsafe.json"
    assert boundary.module.main(["--conditions", "poll", "--output", str(output)]) == 1
    assert not boundary.inspector.started
    assert not any("up" in args for args, _ in boundary.calls)
    assert json.loads(output.read_text())["cleanup"] == "not_needed"


def test_new_timing_inspection_stage_is_retained(latency):
    report = healthy_report()
    report["timings"]["stages"].append(
        {"role": "source", "stage": "timing_inspect", "count": 1, "total_ms": 20.0, "max_ms": 20.0}
    )
    sample = latency.extract_probe_sample(report)
    assert sample["metrics"]["source.timing_inspect.elapsed_ms"] == 20


def test_cli_inspection_requests_keep_safe_http_status_counts(latency):
    report = healthy_report()
    report["timings"]["requests"].append(
        {
            "role": "project",
            "stage": "inspection",
            "method": "GET",
            "path": "/containers/json",
            "count": 3,
            "total_ms": 20,
            "max_ms": 10,
            "status_counts": {"200": 2, "404": 1, "private-value": 1, "500": False},
        }
    )
    sample = latency.extract_probe_sample(report)
    request = sample["timings"]["requests"][1]
    assert request["role"] == "project" and request["stage"] == "inspection"
    assert request["status_counts"] == {"200": 2, "404": 1}


def test_cancelled_floor_attempt_retains_wall_time_and_owned_cleanup(
    boundary, monkeypatch, tmp_path
):
    command = boundary.module._command

    def cancel_floor(arguments, **kwargs):
        if arguments[:2] == ["docker", "run"]:
            label = arguments[arguments.index("--label") + 1]
            key, value = label.split("=", 1)
            boundary.inspector.floor = {"Id": "owned-floor-id", "Config": {"Labels": {key: value}}}
            raise KeyboardInterrupt
        return command(arguments, **kwargs)

    monkeypatch.setattr(boundary.module, "_command", cancel_floor)
    output = tmp_path / "cancelled.json"
    assert (
        boundary.module.main(
            ["--conditions", "floor", "--settle-seconds", "0", "--output", str(output)]
        )
        == 130
    )
    report = json.loads(output.read_text())
    assert report["status"] == "cancelled" and report["cleanup"] == "failed"
    assert len(report["samples"]) == 1
    assert report["samples"][0]["error"] == "cancelled"
    assert report["samples"][0]["metrics"]["wall_ms"] >= 0
    assert boundary.inspector.removed == [("owned-floor-id", {"force": True})]


def test_floor_cleanup_uncertainty_cannot_be_reported_as_complete(boundary, monkeypatch, tmp_path):
    command = boundary.module._command

    def foreign_floor(arguments, **kwargs):
        if arguments[:2] == ["docker", "run"]:
            boundary.inspector.floor = {
                "Id": "foreign-floor-id",
                "Config": {"Labels": {"io.dockroute.latency.owner": "unrelated-owner"}},
            }
            return SimpleNamespace(returncode=1, stdout="private output")
        return command(arguments, **kwargs)

    monkeypatch.setattr(boundary.module, "_command", foreign_floor)
    output = tmp_path / "floor-cleanup.json"
    assert (
        boundary.module.main(
            ["--conditions", "floor", "--settle-seconds", "0", "--output", str(output)]
        )
        == 1
    )
    report = json.loads(output.read_text())
    assert report["cleanup"] == "failed" and report["status"] == "failed"
    assert boundary.inspector.removed == []


@pytest.mark.parametrize(
    "missing", ["trace", "host_ready_ms", "vm_startup_ms", "observation_overhead_ms"]
)
def test_missing_critical_ready_metrics_cannot_be_a_usable_sample(latency, missing):
    report = healthy_report()
    if missing == "trace":
        report["findings"][0]["probe"]["trace"] = []
    else:
        report["findings"][0]["probe"]["trace"][0]["timings"][missing] = None
    sample = latency.extract_probe_sample(report)
    assert not sample["valid"]
    assert not sample["timing_complete"]
    assert sample["error"] == "incomplete_ready_timings"
    if missing != "trace":
        assert sample["timings"]["worker"][0][missing] is None
        assert "source.worker_startup." + missing not in sample["metrics"]


def test_destination_metrics_are_required_only_when_its_helper_was_requested(latency):
    report = healthy_report()
    assert latency.extract_probe_sample(report)["valid"]
    report["timings"]["stages"].append(
        {"role": "destination", "stage": "worker_startup", "count": 1, "total_ms": 1, "max_ms": 1}
    )
    report["findings"][0]["probe"]["listener_state"] = "SUCCESS"
    sample = latency.extract_probe_sample(report)
    assert not sample["valid"]
    assert "destination.worker_startup.vm_startup_ms" in sample["required_timing_metrics"]


def test_summary_exposes_partial_readiness_coverage_without_zero_filling(latency):
    samples = []
    for index in range(20):
        sample = latency.extract_probe_sample(healthy_report())
        sample.update(condition="poll", warmup=False)
        samples.append(sample)
    del samples[-1]["metrics"]["source.worker_startup.observation_overhead_ms"]
    summary = latency.summarize(samples, ("poll",))["poll"]
    assert summary["metrics"]["source.worker_startup.observation_overhead_ms"]["n"] == 19
    assert summary["required_metric_counts"]["source.worker_startup.observation_overhead_ms"] == 19
    assert not summary["timing_coverage_complete"]


@pytest.mark.parametrize("event", ["timeout", "cancel"])
def test_probe_cooperative_cancellation_waits_for_child_cleanup(
    latency, monkeypatch, tmp_path, event
):
    inspector = FakeInspector()
    args = latency.parse_args(["--conditions", "poll"])
    calls = []

    class Child:
        returncode = None

        def __init__(self, arguments, **kwargs):
            self.control = Path(arguments[arguments.index("--_benchmark-control") + 1])
            self.lease = owned_lease()
            (self.control / "lease.json").write_text(json.dumps(self.lease), encoding="utf-8")
            inspector.helpers[self.lease["helpers"][0]["name"]] = owned_attrs(self.lease)
            calls.append((arguments, kwargs))

        def communicate(self, *, timeout):
            if not (self.control / "cancel").exists():
                if event == "cancel":
                    raise KeyboardInterrupt
                raise subprocess.TimeoutExpired(calls[0][0], timeout)
            inspector.helpers.clear()  # Real child finally owns the ordinary removal.
            self.returncode = 130
            return json.dumps(healthy_report()), "private stderr"

        def kill(self):
            pytest.fail("a cooperative child must get its cleanup grace before a kill")

    monkeypatch.setattr(latency.subprocess, "Popen", Child)
    sample = {"metrics": {}}
    if event == "cancel":
        with pytest.raises(KeyboardInterrupt):
            latency.probe_sample(args, inspector, "owned-project", "poll", sample)
    else:
        latency.probe_sample(args, inspector, "owned-project", "poll", sample)
    assert sample["error"] == ("cancelled" if event == "cancel" else "probe_outer_timeout")
    assert not sample["valid"] and sample["cleanup"] == "complete"
    assert sample["metrics"]["wall_ms"] >= 0
    assert sample["timings"]["total_ms"] == 3500
    assert sample["cancellation_requested"]
    assert sample["probe_execution_ids"] == ["a" * 32]
    assert inspector.removed == []


def test_hard_kill_recovers_only_exact_lease_and_never_claims_certainty(latency, monkeypatch):
    inspector = FakeInspector()
    args = latency.parse_args(["--conditions", "poll"])
    events = []

    class Child:
        returncode = None

        def __init__(self, arguments, **kwargs):
            self.control = Path(arguments[arguments.index("--_benchmark-control") + 1])
            self.lease = owned_lease()
            (self.control / "lease.json").write_text(json.dumps(self.lease), encoding="utf-8")
            inspector.helpers[self.lease["helpers"][0]["name"]] = owned_attrs(self.lease)

        def communicate(self, *, timeout):
            events.append("communicate")
            if self.returncode is None:
                raise subprocess.TimeoutExpired("private command", timeout)
            return "", ""

        def kill(self):
            assert (self.control / "cancel").exists()
            events.append("kill")
            self.returncode = -9

    monkeypatch.setattr(latency.subprocess, "Popen", Child)
    clock = iter(range(100))
    monkeypatch.setattr(latency.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(latency.time, "sleep", lambda duration: None)
    sample = {"metrics": {}}
    latency.probe_sample(args, inspector, "owned-project", "poll", sample)
    assert events[:3] == ["communicate", "communicate", "kill"]
    assert sample["cleanup"] == "uncertain" and sample["child_killed"]
    assert inspector.removed == [("c" * 64, {"force": True})]
    assert not inspector.helpers


@pytest.mark.parametrize(
    "invalid",
    [
        "foreign_project",
        "foreign_execution",
        "wrong_name",
        "extra_key",
        "duplicate_key",
        "partial_json",
        "too_many_helpers",
        "oversize",
    ],
)
def test_invalid_lease_never_authorizes_any_removal(latency, tmp_path, invalid):
    inspector = FakeInspector()
    lease = owned_lease()
    inspector.helpers[lease["helpers"][0]["name"]] = owned_attrs(lease)
    if invalid == "foreign_project":
        lease["project"] = "another-project"
    elif invalid == "foreign_execution":
        lease["helpers"][0]["labels"]["io.dockroute.execution"] = "d" * 32
    elif invalid == "wrong_name":
        lease["helpers"][0]["name"] = "foreign-container"
    elif invalid == "extra_key":
        lease["private"] = "must not be serialized"
    elif invalid == "too_many_helpers":
        lease["helpers"] *= 3
    content = json.dumps(lease)
    if invalid == "duplicate_key":
        content = content.replace('"execution_id":', '"execution_id": "d", "execution_id":', 1)
    elif invalid == "partial_json":
        content = '{"execution_id":'
    elif invalid == "oversize":
        content += " " * 65537
    (tmp_path / "lease.json").write_text(content, encoding="utf-8")
    result = latency.recover_leased_helpers(inspector, tmp_path, "owned-project")
    assert result["cleanup"] == "failed"
    assert inspector.removed == []


def test_foreign_second_helper_prevents_deletion_of_first(latency, tmp_path):
    inspector = FakeInspector()
    lease = owned_lease()
    second = owned_lease(run="d" * 32)["helpers"][0]
    lease["helpers"].append(second)
    inspector.helpers[lease["helpers"][0]["name"]] = owned_attrs(lease)
    foreign = {
        "Id": "e" * 64,
        "Name": "/" + second["name"],
        "Config": {"Labels": {**second["labels"], "io.dockroute.execution": "f" * 32}},
    }
    inspector.helpers[second["name"]] = foreign
    (tmp_path / "lease.json").write_text(json.dumps(lease), encoding="utf-8")
    assert (
        latency.recover_leased_helpers(inspector, tmp_path, "owned-project")["cleanup"] == "failed"
    )
    assert inspector.removed == []


def test_missing_success_lease_is_failed_and_stream_is_unavailable(boundary, monkeypatch, tmp_path):
    assert boundary.module.parse_args([]).conditions == ("poll", "poll-unlimited", "floor")
    with pytest.raises(SystemExit):
        boundary.module.parse_args(["--conditions", "stream"])

    def unleased(arguments, **kwargs):
        return SimpleNamespace(
            returncode=0, communicate=lambda **kw: (json.dumps(healthy_report()), "")
        )

    monkeypatch.setattr(boundary.module.subprocess, "Popen", unleased)
    output = tmp_path / "unleased.json"
    assert (
        boundary.module.main(
            ["--conditions", "poll", "--settle-seconds", "0", "--output", str(output)]
        )
        == 1
    )
    report = json.loads(output.read_text())
    assert not report["samples"][0]["valid"]
    assert report["samples"][0]["error"] == "missing_control_lease"
    assert report["cleanup"] == "failed"


def test_failed_cancel_marker_still_waits_then_reaps_known_child(latency, monkeypatch):
    inspector = FakeInspector()
    args = latency.parse_args(["--conditions", "poll"])
    events = []

    class Child:
        returncode = None

        def __init__(self, arguments, **kwargs):
            directory = Path(arguments[arguments.index("--_benchmark-control") + 1])
            lease = owned_lease()
            (directory / "lease.json").write_text(json.dumps(lease), encoding="utf-8")

        def communicate(self, *, timeout):
            events.append("wait")
            if self.returncode is None:
                raise subprocess.TimeoutExpired("owned command", timeout)
            return "", ""

        def kill(self):
            events.append("kill")
            self.returncode = -9

    original = Path.write_text

    def denied_marker(path, data, **kwargs):
        if path.name == "cancel":
            raise PermissionError("private marker unavailable")
        return original(path, data, **kwargs)

    monkeypatch.setattr(Path, "write_text", denied_marker)
    monkeypatch.setattr(latency.subprocess, "Popen", Child)
    clock = iter(range(100))
    monkeypatch.setattr(latency.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(latency.time, "sleep", lambda duration: None)
    sample = {"metrics": {}}
    latency.probe_sample(args, inspector, "owned-project", "poll", sample)
    assert events[:3] == ["wait", "wait", "kill"]
    assert sample["cancel_channel_failed"] and sample["child_killed"]
    assert sample["cleanup"] == "uncertain"
    assert "private marker unavailable" not in json.dumps(sample)


def test_hard_kill_recovery_checks_for_delayed_creation(latency, monkeypatch, tmp_path):
    inspector = FakeInspector()
    lease = owned_lease()
    (tmp_path / "lease.json").write_text(json.dumps(lease), encoding="utf-8")
    original = inspector.inspect_container
    checks = []

    def delayed(identity):
        if identity == lease["helpers"][0]["name"]:
            checks.append(identity)
            if len(checks) == 2:
                inspector.helpers[identity] = owned_attrs(lease)
        return original(identity)

    monkeypatch.setattr(inspector, "inspect_container", delayed)
    clock = iter(range(100))
    monkeypatch.setattr(latency.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(latency.time, "sleep", lambda duration: None)
    result = latency.recover_leased_helpers(inspector, tmp_path, "owned-project", hard_killed=True)
    assert len(checks) >= 3
    assert inspector.removed == [("c" * 64, {"force": True})]
    assert result["cleanup"] == "uncertain"


def test_runner_advertises_only_implemented_schedules(latency):
    assert latency.parse_args([]).schedule == "conditional"
    assert latency.parse_args(["--schedule", "sequential"]).schedule == "sequential"
    with pytest.raises(SystemExit):
        latency.parse_args(["--schedule", "concurrent"])


def test_interrupted_floor_reconciles_late_owned_creation_but_remains_uncertain(
    latency, monkeypatch
):
    inspector = FakeInspector()
    args = latency.parse_args(["--conditions", "floor"])
    ownership = {}
    checks = []

    def interrupted(arguments, **kwargs):
        label = arguments[arguments.index("--label") + 1]
        key, value = label.split("=", 1)
        ownership.update(key=key, value=value)
        raise subprocess.TimeoutExpired(arguments, 10)

    original = inspector.inspect_container

    def delayed(name):
        checks.append(name)
        if len(checks) == 2:
            inspector.floor = {
                "Id": "owned-late-floor",
                "Config": {"Labels": {ownership["key"]: ownership["value"]}},
            }
        return original(name)

    monkeypatch.setattr(latency, "_command", interrupted)
    monkeypatch.setattr(inspector, "inspect_container", delayed)
    clock = iter(range(100))
    monkeypatch.setattr(latency.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(latency.time, "sleep", lambda duration: None)
    sample = latency.floor_sample(args, inspector, "run-owner")
    assert inspector.removed == [("owned-late-floor", {"force": True})]
    assert len(checks) >= 3
    assert not sample["valid"] and sample["cleanup"] == "uncertain"


def test_floor_remove_racing_auto_remove_is_already_absent(latency, monkeypatch):
    inspector = FakeInspector()
    inspector.floor = {
        "Id": "owned-floor",
        "Config": {"Labels": {"io.dockroute.latency.owner": "run-owner"}},
    }

    def auto_removed(identifier, **kwargs):
        inspector.floor = None
        raise NotFound("already automatically removed")

    monkeypatch.setattr(inspector, "remove_container", auto_removed)
    assert latency._floor_cleanup(inspector, "owned-name", "run-owner") == "complete"
