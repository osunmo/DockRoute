import json
import tomllib
from pathlib import Path

import jsonschema
import pytest
from test_core import node

from dockroute import __version__
from dockroute.diagnostics import diagnose
from dockroute.models import Connection, ProbeResult
from dockroute.reporting import make_report, render_terminal, report_exit_code


def test_tcp_success_has_an_explicit_transport_code_and_major_schema():
    containers = [node("app"), node("api")]
    finding = diagnose(
        Connection("app-id", "app", "api", 8000),
        containers,
        ProbeResult(dns="ok", tcp="ok", dns_equivalent=True),
    )
    report = make_report("shop", containers, [finding], probe=True)
    assert finding.code == "TCP_REACHABLE"
    assert report["schema_version"] == "3.0"
    assert report["status"] == "REACHABLE"
    assert report_exit_code(report) == 0
    assert "Application protocol readiness was not tested" in render_terminal(report)
    report = json.loads(json.dumps(report))
    schema = json.loads(Path("docs/report.schema.json").read_text())
    jsonschema.validate(report, schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            {**report, "findings": [{**report["findings"][0], "code": "HEALTHY"}]}, schema
        )


def test_release_version_matches_package_metadata():
    metadata = tomllib.loads(Path("pyproject.toml").read_text())
    assert __version__ == metadata["project"]["version"] == "0.4.0"
