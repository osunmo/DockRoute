"""Opt-in real Docker tests. Synthetic labels are graded only after runtime validation."""

import os
from pathlib import Path

import pytest

from dockroute.benchmark import run_scenario
from dockroute.docker import DockerUnavailable, connect


@pytest.mark.integration
@pytest.mark.parametrize(
    "scenario", sorted(p.parent.name for p in Path("scenarios").glob("*/expected.yaml"))
)
def test_live_scenario(scenario):
    if os.environ.get("DOCKROUTE_INTEGRATION") != "1":
        pytest.skip("Set DOCKROUTE_INTEGRATION=1 to create isolated synthetic fixture projects")
    if scenario.startswith("03-") and os.environ.get("DOCKROUTE_ALLOW_FIXED_PORTS") != "1":
        pytest.skip("Port 18000 fixture requires DOCKROUTE_ALLOW_FIXED_PORTS=1")
    try:
        inspector = connect(timeout=10)
    except DockerUnavailable:
        pytest.skip("Docker Engine unavailable; fixture runtime behavior unverified")
    try:
        result = run_scenario(
            inspector,
            Path("scenarios") / scenario,
            allow_fixed_ports=os.environ.get("DOCKROUTE_ALLOW_FIXED_PORTS") == "1",
        )
        assert result["behavior_validated"], result
        assert result["status"] == "passed", result
        assert result["cleanup"] == "complete", result
    finally:
        inspector.close()
