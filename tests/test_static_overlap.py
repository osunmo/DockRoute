"""Static analysis may run concurrently; Docker lifecycle/cancellation stays on main."""

import threading
from types import SimpleNamespace

import pytest
from test_core import node

from dockroute import cli
from dockroute.diagnostics import diagnose
from dockroute.models import ProbeResult


@pytest.mark.parametrize("cancel", [False, True])
def test_static_analysis_overlaps_main_thread_probe_and_joins_on_cancel(
    monkeypatch, capsys, cancel
):
    import dockroute.probes as probes

    main_thread = threading.get_ident()
    static_started, helper_started, static_finished = (threading.Event() for _ in range(3))
    containers = [node("app", env={"UPSTREAM_URL": "http://api:8000"}), node("api")]
    inspector = SimpleNamespace(
        client=object(),
        identities=lambda: containers,
        snapshot=lambda project: containers,
        version=lambda: {"Version": "test", "Os": "linux"},
        close=lambda: None,
    )
    monkeypatch.setattr(cli, "connect", lambda **kw: inspector)
    monkeypatch.delenv("DOCKROUTE_HELPER_CPUS", raising=False)

    def analyze(edge, selected, probe=None):
        if probe is None:
            assert threading.get_ident() != main_thread
            static_started.set()
            assert helper_started.wait(2)
            static_finished.set()
        return diagnose(edge, selected, probe)

    class MainThreadProber:
        def __init__(self, *args, **kwargs):
            pass

        def check(self, edge, selected, *, static_finding=None):
            assert threading.get_ident() == main_thread
            helper_started.set()
            assert static_started.wait(2)
            assert callable(static_finding)
            if cancel:
                raise KeyboardInterrupt()
            assert static_finding().code == "UNKNOWN"
            return ProbeResult(dns="ok", tcp="ok", dns_equivalent=True, state="SUCCESS")

        def close(self):
            pass

    monkeypatch.setattr(cli, "diagnose", analyze)
    monkeypatch.setattr(probes, "Prober", MainThreadProber)
    assert cli.main(["doctor", "--project", "shop", "--probe", "--format", "json"]) == (
        130 if cancel else 0
    )
    assert static_finished.is_set()
    assert not any(t.name.startswith("dockroute-static") for t in threading.enumerate())
    assert ("CANCELLED" if cancel else "TCP_REACHABLE") in capsys.readouterr().out
