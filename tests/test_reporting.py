import json

from test_core import node

from dockroute.diagnostics import diagnose
from dockroute.models import Connection
from dockroute.reporting import make_report, render_json, render_terminal, report_exit_code


def test_timing_report_preserves_findings_and_summarizes_stage_data():
    from dockroute.models import ProbeResult, ProbeTrace

    containers = [node("app"), node("api")]
    edge = Connection("app-id", "app", "api", 8000)
    probe = ProbeResult(
        dns="ok",
        tcp="ok",
        dns_equivalent=True,
        trace=(
            ProbeTrace(
                "source", "worker_startup", "SUCCESS", 1000, timings={"host_ready_ms": 1000}
            ),
            ProbeTrace("destination", "worker_startup", "SUCCESS", 2000),
        ),
    )
    report = make_report(
        "shop", containers, [diagnose(edge, containers, probe)], total_ms=3500, timing=True
    )
    assert report["schema_version"] == "3.0"
    assert report["timings"]["total_ms"] == 3500
    assert report["timings"]["stages"] == [
        {
            "role": "destination",
            "stage": "worker_startup",
            "count": 1,
            "total_ms": 2000,
            "max_ms": 2000,
        },
        {"role": "source", "stage": "worker_startup", "count": 1, "total_ms": 1000, "max_ms": 1000},
    ]
    assert report["findings"][0]["code"] == "TCP_REACHABLE"
    terminal = render_terminal(report, verbose=True)
    assert "Elapsed: 3500" in terminal and "STAGE TIMINGS" in terminal


def test_json_schema_is_versioned_and_does_not_serialize_raw_config():
    app = node(
        "app", env={"PASSWORD": "never-print", "UPSTREAM_URL": "http://u:never-print@api:8000/a"}
    )
    edge = Connection(app.id, "app", "api", 8000)
    report = make_report("shop", [app, node("api")], [diagnose(edge, [app, node("api")])])
    text = render_json(report)
    data = json.loads(text)
    assert data["schema_version"] == "3.0"
    assert data["findings"][0]["code"] == "UNKNOWN"
    assert "never-print" not in text
    assert "env" not in data["services"][0]
    assert report_exit_code(report) == 2
    assert "No application configuration was modified" in render_terminal(report)


def test_no_edges_is_unknown_not_a_healthy_project():
    report = make_report("shop", [node("api")], [])
    assert report_exit_code(report) == 2
    assert "No intended connections" in render_terminal(report)
