from dataclasses import replace

import pytest
from test_core import node

from dockroute.diagnostics import diagnose
from dockroute.discovery import discover, parse_endpoint
from dockroute.models import Connection, ProbeResult


def test_zero_port_is_invalid_even_with_scheme_default():
    assert parse_endpoint("http://api:0") is None


def test_hosts_override_prevents_false_topology_diagnosis():
    app = node("app", networks=("front",), extra_hosts=("api:10.0.0.2",))
    assert (
        diagnose(
            Connection(app.id, "app", "api", 8000), [app, node("api", networks=("back",))]
        ).code
        == "UNKNOWN"
    )


@pytest.mark.parametrize("which", ["source", "destination"])
def test_stopped_containers_do_not_imply_network_isolation(which):
    app, api = node("app", networks=()), node("api", networks=())
    if which == "source":
        app = replace(app, state="exited")
    else:
        api = replace(api, state="exited")
    assert diagnose(Connection(app.id, "app", "api", 8000), [app, api]).code == "UNKNOWN"


@pytest.mark.parametrize(
    "tcp,code",
    [("ok", "TCP_REACHABLE"), ("refused", "CONNECTION_REFUSED"), ("timeout", "CONNECTION_TIMEOUT")],
)
def test_explicit_external_probe_reports_measured_outcome(tcp, code):
    edge = Connection("app-id", "app", "example.com", 443, explicit=True)
    assert (
        diagnose(edge, [node("app")], ProbeResult(dns="ok", tcp=tcp, dns_equivalent=True)).code
        == code
    )


def test_successful_local_connection_is_not_wrong_localhost():
    edge = Connection("app-id", "app", "localhost", 8000, explicit=True)
    assert (
        diagnose(
            edge,
            [node("app", depends=("api",)), node("api")],
            ProbeResult(dns="ok", tcp="ok", dns_equivalent=True),
        ).code
        == "TCP_REACHABLE"
    )


def test_helper_resolver_mismatch_does_not_prove_source_success():
    edge = Connection("app-id", "app", "api", 8000)
    assert (
        diagnose(
            edge, [node("app"), node("api")], ProbeResult(dns="ok", tcp="ok", dns_equivalent=False)
        ).code
        == "UNKNOWN"
    )


def test_loopback_and_typo_edges_use_dependency_as_support_not_extra_fake_edges():
    for host in ("localhost", "api-backend"):
        edges = discover(
            [
                node("app", env={"UPSTREAM_URL": f"http://{host}:8000"}, depends=("api",)),
                node("api"),
            ]
        )
        assert len(edges) == 1
        assert {e.kind for e in edges[0].evidence} >= {"environment", "depends_on"}


def test_command_embedded_in_url_text_is_not_an_environment_endpoint():
    assert parse_endpoint("prefix http://api:8000 suffix") is None
