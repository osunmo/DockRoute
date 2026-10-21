import json

import pytest

from dockroute.benchmark import FixtureSafetyError, main, validate_behavior, validate_fixture
from dockroute.docker import DockerUnavailable


def test_benchmark_refuses_shared_resources_and_fixed_ports_by_default():
    base = {"services": {"app": {"image": "python:3.12-alpine"}}, "networks": {"default": {}}}
    validate_fixture(base)
    for config in (
        {**base, "volumes": {"data": {}}},
        {**base, "networks": {"shared": {"external": True}}},
        {"services": {"app": {"image": "python:3.12-alpine", "volumes": ["/prod:/data"]}}},
        {"services": {"app": {"image": "python:3.12-alpine", "network_mode": "host"}}},
        {
            "services": {
                "app": {
                    "image": "python:3.12-alpine",
                    "ports": [{"target": 8000, "published": "18000", "host_ip": "127.0.0.1"}],
                }
            }
        },
    ):
        with pytest.raises(FixtureSafetyError):
            validate_fixture(config)
    fixed = {
        "services": {
            "app": {
                "image": "python:3.12-alpine",
                "ports": [{"target": 8000, "published": "18000", "host_ip": "127.0.0.1"}],
            }
        }
    }
    validate_fixture(fixed, allow_fixed_ports=True)


def test_fixture_labels_do_not_count_without_independent_behavior():
    observations = {
        "app_request": "failed",
        "source_dns": "ok",
        "source_tcp": "refused",
        "listener_addresses": ["127.0.0.1"],
        "listener_verified": True,
        "shared_networks": ["main"],
        "target_host": "api",
        "target_port": 8000,
        "matched_destination": True,
        "port_mapping_match": False,
    }
    assert validate_behavior("LOOPBACK_ONLY_LISTENER", observations)
    assert not validate_behavior("TCP_REACHABLE", observations)
    assert not validate_behavior("NETWORK_ISOLATION", observations)
    assert not validate_behavior(
        "LOOPBACK_ONLY_LISTENER", {**observations, "listener_addresses": []}
    )


def test_unavailable_engine_writes_machine_readable_skips(tmp_path, monkeypatch):
    import dockroute.benchmark as benchmark

    def unavailable(**kw):
        raise DockerUnavailable("unavailable")

    monkeypatch.setattr(benchmark, "connect", unavailable)
    output = tmp_path / "report.json"
    assert main(["--output", str(output)]) == 3
    data = json.loads(output.read_text())
    assert data["status"] == "unavailable"
    assert len(data["results"]) == 6
    assert all(r["status"] == "skipped" and not r["behavior_validated"] for r in data["results"])
    assert {"docker", "compose", "dockroute"} <= set(data["versions"])


@pytest.mark.parametrize("observer_fails", [False, True])
def test_runner_cleans_its_own_frozen_project_even_when_validation_fails(
    monkeypatch, observer_fails
):
    from pathlib import Path
    from types import SimpleNamespace

    from test_core import node

    import dockroute.benchmark as benchmark

    calls = []

    def command(arguments, **kwargs):
        calls.append(arguments)
        config = {"services": {"app": {"image": "python:3.12-alpine"}}, "networks": {}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(config))

    monkeypatch.setattr(benchmark, "_command", command)

    def observe(*args):
        if observer_fails:
            raise RuntimeError("observer failed")
        return {"app_request": "failed", "source_tcp": "refused"}

    monkeypatch.setattr(benchmark, "_observe", observe)
    monkeypatch.setattr(
        benchmark,
        "_diagnose",
        lambda *a, **kw: {
            "exit_code": 0,
            "report": {"findings": [{"source": "app", "port": 8000, "code": "TCP_REACHABLE"}]},
        },
    )
    inspector = SimpleNamespace(
        client=SimpleNamespace(api=SimpleNamespace(containers=lambda **kw: [])),
        snapshot=lambda p: [node("app", health="healthy"), node("api", health="healthy")],
    )
    result = benchmark.run_scenario(inspector, Path("scenarios/06-healthy-control"))
    assert result["status"] == "failed" and not result["behavior_validated"]
    assert result["cleanup"] == "complete"
    assert "down" in calls[-1] and "-v" not in calls[-1]
    assert calls[-1][3] == result["project"] and result["project"].startswith("dockroute-test-")
    assert Path(calls[1][5]).name == "compose.json"
