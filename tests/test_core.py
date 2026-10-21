from pathlib import Path

import pytest

from dockroute.compose import ProjectError, parse_labels, select_project
from dockroute.diagnostics import diagnose
from dockroute.discovery import discover, parse_endpoint
from dockroute.models import Connection, Container, Network, Port, ProbeResult
from dockroute.safety import safe_endpoint


def node(
    service,
    *,
    project="shop",
    networks=("main",),
    env=None,
    health="none",
    ports=(),
    depends=(),
    healthcheck=(),
    network_mode="",
    extra_hosts=(),
):
    return Container(
        id=service + "-id",
        name=service + "-1",
        project=project,
        service=service,
        state="running",
        health=health,
        networks={n: Network(n, n + "-id", (service,), ("172.20.0.2",)) for n in networks},
        env=env or {},
        ports=tuple(ports),
        depends_on=tuple(depends),
        healthcheck=tuple(healthcheck),
        network_mode=network_mode,
        extra_hosts=tuple(extra_hosts),
    )


def test_compose_labels_ignore_oneoffs_and_parse_dependencies():
    assert parse_labels({"com.docker.compose.project": "shop"}) is None
    labels = {
        "com.docker.compose.project": "shop",
        "com.docker.compose.service": "app",
        "com.docker.compose.depends_on": "db:service_healthy:false,cache:service_started:false",
    }
    assert parse_labels(labels).depends_on == ("cache", "db")
    assert parse_labels({**labels, "com.docker.compose.oneoff": "True"}) is None


def test_selection_never_chooses_unrelated_single_project(tmp_path):
    with pytest.raises(ProjectError, match="--project"):
        select_project([node("db")], cwd=tmp_path)


def test_selection_explicit_and_ambiguous(tmp_path):
    from dataclasses import replace

    a = replace(node("a"), working_dir=str(tmp_path))
    b = replace(node("b", project="other"), working_dir=str(tmp_path))
    assert select_project([a, b], requested="shop", cwd=tmp_path) == "shop"
    with pytest.raises(ProjectError, match="ambiguous"):
        select_project([a, b], cwd=tmp_path)
    with pytest.raises(ProjectError, match="not found"):
        select_project([a], requested="missing", cwd=tmp_path)


def test_selection_compose_file_and_windows_paths(tmp_path):
    from dataclasses import replace

    (tmp_path / "compose.yaml").write_text("name: shop\nservices: {}\n")
    assert select_project([node("app")], cwd=tmp_path) == "shop"
    c = replace(node("app"), working_dir="C:\\Work\\Shop")
    assert select_project([c], cwd=Path("c:/work/shop/sub")) == "shop"


@pytest.mark.parametrize(
    "value,want",
    [
        ("postgres://alice:secret@db:5432/app?token=secret", ("db", 5432)),
        ("https://api/path", ("api", 443)),
        ("cache:6379", ("cache", 6379)),
        ("http://[::1]:8000", ("::1", 8000)),
        ("http://api:99999", None),
        ("password-only", None),
        ("http://api:bad", None),
        ("file:///etc/passwd", None),
    ],
)
def test_endpoint_parser_never_retains_credentials(value, want):
    assert parse_endpoint(value) == want
    assert "secret" not in safe_endpoint(value)


def test_discovery_urls_pairs_supporting_dependencies_and_healthchecks():
    app = node(
        "app",
        env={
            "DATABASE_URL": "postgres://u:p@db:5432/x",
            "REDIS_HOST": "cache",
            "REDIS_PORT": "6379",
            "PASSWORD": "not-a-host",
        },
        depends=("db", "cache", "other"),
        healthcheck=("CMD", "curl", "http://db:5432/secret?password=p"),
    )
    edges = discover([app, node("db"), node("cache"), node("other")])
    assert [(e.host, e.port) for e in edges if e.port] == [("cache", 6379), ("db", 5432)]
    db = next(e for e in edges if e.host == "db")
    assert {e.kind for e in db.evidence} >= {"environment", "depends_on", "healthcheck"}
    assert "u:p" not in repr(edges)
    assert next(e for e in edges if e.host == "other").port is None


def test_local_healthcheck_does_not_invent_wrong_localhost():
    edges = discover([node("api", healthcheck=("CMD", "curl", "http://localhost:8000"))])
    assert edges == []


@pytest.mark.parametrize(
    "setup,edge,code",
    [
        (
            [node("app", networks=("front",)), node("api", networks=("back",))],
            Connection("app-id", "app", "api", 8000),
            "NETWORK_ISOLATION",
        ),
        (
            [node("app", depends=("api",)), node("api")],
            Connection("app-id", "app", "localhost", 8000),
            "WRONG_LOCALHOST",
        ),
        (
            [node("app"), node("api", ports=(Port(8000, "tcp", 18000, "127.0.0.1"),))],
            Connection("app-id", "app", "api", 18000),
            "HOST_PORT_INSTEAD_OF_CONTAINER_PORT",
        ),
        (
            [node("app", depends=("api",)), node("api")],
            Connection("app-id", "app", "api-backend", 8000),
            "INVALID_SERVICE_HOSTNAME",
        ),
        (
            [node("app"), node("api", health="unhealthy")],
            Connection("app-id", "app", "api", 8000),
            "SERVICE_UNHEALTHY",
        ),
        (
            [node("app"), node("api", health="healthy")],
            Connection("app-id", "app", "api", 8000),
            "UNKNOWN",
        ),
        ([node("app")], Connection("app-id", "app", "localhost", 8000), "UNKNOWN"),
        ([node("app")], Connection("app-id", "app", "example.com", 443), "UNKNOWN"),
    ],
)
def test_evidence_based_static_classification(setup, edge, code):
    result = diagnose(edge, setup)
    assert result.code == code
    assert result.verification == "static"
    assert result.explanation and result.remediation and result.observations


def test_active_listener_requires_destination_evidence_and_success_is_healthy():
    edge = Connection("app-id", "app", "api", 8000)
    containers = [node("app"), node("api")]
    assert (
        diagnose(edge, containers, ProbeResult(tcp="refused", dns="ok", dns_equivalent=True)).code
        == "CONNECTION_REFUSED"
    )
    p = ProbeResult(
        tcp="refused", dns="ok", listener_addresses=("127.0.0.1",), listener_verified=True
    )
    f = diagnose(edge, containers, p)
    assert f.code == "LOOPBACK_ONLY_LISTENER" and f.verification == "active"
    assert (
        diagnose(edge, containers, ProbeResult(tcp="ok", dns="ok", dns_equivalent=True)).code
        == "TCP_REACHABLE"
    )
    assert (
        diagnose(edge, containers, ProbeResult(tcp="timeout", dns="ok", dns_equivalent=True)).code
        == "CONNECTION_TIMEOUT"
    )
    assert (
        diagnose(edge, containers, ProbeResult(dns="failed", dns_equivalent=True)).code
        == "DNS_FAILURE"
    )
    assert (
        diagnose(edge, containers, ProbeResult(dns="failed", dns_equivalent=False)).code
        == "UNKNOWN"
    )


def test_aliases_are_scoped_to_network_and_collisions_are_unknown():
    from dataclasses import replace

    api = replace(node("api"), networks={"main": Network("main", "main-id", ("upstream",), ())})
    edge = Connection("app-id", "app", "upstream", 8000)
    assert diagnose(edge, [node("app"), api]).code == "UNKNOWN"
    other = replace(node("other"), networks=api.networks)
    f = diagnose(edge, [node("app"), api, other])
    assert f.code == "UNKNOWN" and "ambiguous" in f.explanation.lower()


def test_host_network_localhost_is_not_wrong_localhost():
    c = node("app", depends=("api",), network_mode="host")
    assert (
        diagnose(Connection(c.id, c.service, "localhost", 8000), [c, node("api")]).code == "UNKNOWN"
    )
