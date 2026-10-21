"""Scheduling must preserve diagnoses while eliminating irrelevant helpers."""

import json

import pytest
from test_core import node
from test_probe_v02 import StageClient

from dockroute.diagnostics import diagnose
from dockroute.models import Connection, Port
from dockroute.probes import Prober
from dockroute.reporting import make_report, render_terminal


class ObservationClient(StageClient):
    def __init__(self, *, dns="ok", tcp="ok", equivalent=True, listeners=("0.0.0.0",)):
        super().__init__()
        self.observations = (dns, tcp, equivalent, listeners)

    def create(self, image, **config):
        helper = super().create(image, **config)
        mode = json.loads(config["command"][-1])["mode"]
        dns, tcp, equivalent, listeners = self.observations
        source = {
            "state": "DNS_FAILURE"
            if dns != "ok"
            else "TCP_REFUSED"
            if tcp == "refused"
            else "TCP_TIMEOUT"
            if tcp == "timeout"
            else "SUCCESS",
            "dns": dns,
            "tcp": tcp,
            "addresses": ["172.20.0.2"] if dns == "ok" else [],
            "dns_equivalent": equivalent,
        }
        destination = {
            "state": "SUCCESS",
            "listener_addresses": list(listeners),
            "listener_verified": True,
        }
        output = (
            json.dumps({"event": "ready", "worker_schema": "1"})
            + "\n"
            + json.dumps(
                {
                    "event": "result",
                    "worker_schema": "1",
                    **(source if mode == "connect" else destination),
                }
            )
            + "\n"
        ).encode()
        helper.logs = lambda **kw: output if kw.get("stdout") else b""
        return helper


@pytest.mark.parametrize(
    "source,destination,host,port,observations,expected,skipped",
    [
        (
            node("app", networks=("front",)),
            node("api", networks=("back",)),
            "api",
            8000,
            {"dns": "failed", "tcp": "unknown"},
            ("NETWORK_ISOLATION", "high"),
            True,
        ),
        (
            node("app", depends=("api",)),
            node("api"),
            "127.0.0.1",
            8000,
            {},
            ("WRONG_LOCALHOST", "medium"),
            False,
        ),
        (
            node("app"),
            node("api", ports=(Port(8000, host=18000),)),
            "api",
            18000,
            {"tcp": "refused", "listeners": ()},
            ("HOST_PORT_INSTEAD_OF_CONTAINER_PORT", "medium"),
            False,
        ),
        (
            node("app"),
            node("api"),
            "api",
            8000,
            {"tcp": "refused", "listeners": ("127.0.0.1",)},
            ("LOOPBACK_ONLY_LISTENER", "high"),
            False,
        ),
        (
            node("app", depends=("api",)),
            node("api"),
            "apix",
            8000,
            {},
            ("INVALID_SERVICE_HOSTNAME", "medium"),
            False,
        ),
        (
            node("app"),
            node("api", health="healthy"),
            "api",
            8000,
            {},
            ("TCP_REACHABLE", "high"),
            True,
        ),
        (
            node("app"),
            node("api", health="unhealthy"),
            "api",
            8000,
            {},
            ("SERVICE_UNHEALTHY", "high"),
            True,
        ),
        (
            node("app"),
            node("api", ports=(Port(8000, host=18000),)),
            "api",
            18000,
            {"equivalent": False},
            ("UNKNOWN", "low"),
            False,
        ),
        (
            node("app"),
            node("api", ports=(Port(8000, host=18000),)),
            "api",
            18000,
            {"dns": "failed", "tcp": "unknown"},
            ("DNS_FAILURE", "high"),
            False,
        ),
        (
            node("app"),
            node("api"),
            "api",
            8000,
            {"tcp": "timeout", "listeners": ("127.0.0.1",)},
            ("LOOPBACK_ONLY_LISTENER", "high"),
            False,
        ),
    ],
)
def test_policy_preserves_classification(
    source, destination, host, port, observations, expected, skipped
):
    edge = Connection(source.id, source.service, host, port)
    containers = [source, destination]
    for policy in ("sequential", "conditional"):
        client = ObservationClient(**observations)
        result = Prober(client, "shop", schedule=policy).check(edge, containers)
        finding = diagnose(edge, containers, result)
        assert (finding.code, finding.confidence) == expected
        assert result.listener_skipped is (skipped and policy == "conditional")
        assert len(client.created) == len(client.removed)
        if result.listener_skipped:
            assert len(client.created) == 1
            assert result.listener_state == "UNKNOWN" and not result.listener_verified
            assert result.listener_skip_reason
            step = next(t for t in result.trace if t.stage == "listener_skipped")
            assert step.state == "SKIPPED" and step.elapsed_ms >= 0
            report = make_report("shop", containers, [finding], probe=True)
            assert result.listener_skip_reason in render_terminal(report)
        elif host == "api":
            assert len(client.created) == 2


def test_conditional_is_the_default():
    client = ObservationClient()
    result = Prober(client, "shop").check(
        Connection("app-id", "app", "api", 8000), [node("app"), node("api")]
    )
    assert result.listener_skipped
    assert len(client.created) == len(client.removed) == 1
