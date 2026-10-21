from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_core import node
from test_probes import FakeClient

from dockroute.compose import ProjectError, select_project
from dockroute.diagnostics import diagnose
from dockroute.discovery import discover
from dockroute.models import Connection, Port, ProbeResult
from dockroute.probes import ProbeCleanupError, Prober
from dockroute.reporting import make_report, render_json, render_terminal


def test_nearest_compose_file_prevents_unrelated_parent_selection(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "compose.yaml").write_text("services: {}\n")
    parent = replace(node("parent", project="parent"), working_dir=str(tmp_path))
    with pytest.raises(ProjectError):
        select_project([parent], cwd=nested)


@pytest.mark.parametrize(
    "key", ["DB_PASS", "API_KEY", "DB_PWD", "ACCESS_KEY", "CREDENTIAL", "AUTH", "SESSION_COOKIE"]
)
def test_secret_shaped_credentials_never_become_reported_endpoints(key):
    app = node("app", env={key: "review-secret:1234", "API_URL": "http://api:8000"})
    edges = discover([app, node("api")])
    findings = [diagnose(e, [app, node("api")]) for e in edges]
    report = make_report("shop", [app, node("api")], findings)
    assert "review-secret" not in render_json(report)
    assert "review-secret" not in render_terminal(report)


def test_runtime_listener_defeats_contradicted_host_port_hypothesis():
    app = node("app")
    api = node("api", ports=(Port(8000, "tcp", 18000, "127.0.0.1"),))
    probe = ProbeResult(
        dns="ok",
        tcp="timeout",
        dns_equivalent=True,
        listener_addresses=("0.0.0.0",),
        listener_verified=True,
    )
    assert (
        diagnose(Connection(app.id, "app", "api", 18000), [app, api], probe).code
        == "CONNECTION_TIMEOUT"
    )


class AmbiguousCreate(FakeClient):
    def __init__(self, recoverable=True):
        super().__init__()
        self.recoverable = recoverable
        self.orphans = {}

    def create(self, image, **config):
        helper = SimpleNamespace(
            id="orphan-id",
            attrs={"Config": {"Labels": config["labels"]}},
            remove=lambda **kw: self.removed.append("orphan-id"),
        )
        self.orphans[config["name"]] = helper
        raise TimeoutError("response lost after successful daemon-side create")

    def get(self, identifier):
        if identifier.startswith("dockroute-probe-"):
            if not self.recoverable:
                raise TimeoutError()
            return self.orphans[identifier]
        return super().get(identifier)


def test_ambiguous_create_failure_recovers_only_its_labeled_helper():
    client = AmbiguousCreate()
    result = Prober(client, "shop").check(
        Connection("app-id", "app", "api", 8000), [node("app"), node("api")]
    )
    assert result.tcp == "unknown"
    assert client.removed == ["orphan-id"]


def test_unresolved_create_cleanup_is_an_error():
    client = AmbiguousCreate(False)
    with pytest.raises(ProbeCleanupError):
        Prober(client, "shop").check(
            Connection("app-id", "app", "api", 8000), [node("app"), node("api")]
        )
    assert not client.removed


def test_native_archive_separator_is_supported():
    from scripts.build_binary import read_worker

    for key in ("dockroute/_probe_worker.py", "dockroute\\_probe_worker.py"):
        reader = SimpleNamespace(
            toc={key: {}}, extract=lambda name: b"def inspect_listeners(port): pass"
        )
        assert b"def inspect_listeners" in read_worker(reader)
