import json
import signal
import socket
import time

import pytest

from dockroute import _probe_worker as worker
from dockroute.probe_protocol import decode_worker_output


def network(monkeypatch, dns_elapsed=0, connect_elapsed=0, failure=None):
    class Clock:
        now = 0.0

    clock = Clock()
    monkeypatch.setattr(worker.time, "monotonic", lambda: clock.now)

    def resolve(*args, **kwargs):
        clock.now += dns_elapsed
        if failure is not None:
            raise socket.gaierror(failure, "resolver failure")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8000))]

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, value):
            self.timeout = value

        def connect(self, address):
            if connect_elapsed > self.timeout:
                clock.now += self.timeout
                raise TimeoutError()
            clock.now += connect_elapsed

    monkeypatch.setattr(worker.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(
        worker, "_resolve_in_child", lambda host, port, deadline: resolve(host, port)
    )
    monkeypatch.setattr(worker.socket, "socket", lambda *args: Connection())
    return clock


def payload(**changes):
    return {
        "mode": "connect",
        "host": "api",
        "port": 8000,
        "timeout": 5,
        "dns_timeout": 2,
        "connect_timeout": 1,
        **changes,
    }


def test_dns_phase_deadline_is_shorter_than_total_and_never_definite_failure(monkeypatch):
    network(monkeypatch, dns_elapsed=3)
    result = worker.run(payload())
    assert result["state"] == "DNS_FAILURE" and result["dns"] == "timeout"
    assert result["tcp"] == "unknown" and result["timeout_stage"] == "dns"
    assert "tcp_ms" not in result


def test_explicit_short_dns_deadline_is_used(monkeypatch):
    network(monkeypatch, dns_elapsed=0.2)
    assert worker.run(payload(dns_timeout=0.1))["dns"] == "timeout"


def test_shorter_total_deadline_dominates_larger_dns_budget(monkeypatch):
    network(monkeypatch, dns_elapsed=0.2)
    result = worker.run(payload(timeout=0.1))
    assert result["dns"] == "timeout" and result["timeout_stage"] == "dns"


@pytest.mark.parametrize("error", [socket.EAI_AGAIN, socket.EAI_NONAME])
def test_immediate_lookup_failure_does_not_claim_an_expired_deadline(monkeypatch, error):
    network(monkeypatch, failure=error)
    result = worker.run(payload())
    assert result["state"] == "DNS_FAILURE" and result["dns"] == "failed"
    assert result["tcp"] == "unknown"
    assert "timeout_stage" not in result


def test_connect_deadline_is_bounded_by_explicit_per_attempt_budget(monkeypatch):
    network(monkeypatch, connect_elapsed=1.5)
    result = worker.run(payload())
    assert result["state"] == "TCP_TIMEOUT" and result["tcp"] == "timeout"
    assert result["timeout_stage"] == "tcp"


def test_dns_time_consumes_the_shared_total_execution_budget(monkeypatch):
    clock = network(monkeypatch, dns_elapsed=0.4, connect_elapsed=0.2)
    result = worker.run(payload(timeout=0.5))
    assert result["tcp"] == "timeout" and result["timeout_stage"] == "tcp"
    assert clock.now == pytest.approx(0.5)


def test_private_execution_deadline_includes_pre_dns_work_and_is_not_serialized(monkeypatch):
    clock = network(monkeypatch, connect_elapsed=0.2)
    clock.now = 0.4
    observations = {
        "dns": "unknown",
        "tcp": "unknown",
        "addresses": [],
        "_execution_deadline": 0.5,
    }
    # Direct local tests do not own the production Linux signal watchdog.
    result = worker.run(payload(), observations=observations)
    assert result["tcp"] == "timeout" and clock.now == pytest.approx(0.5)
    assert "_execution_deadline" not in result


def test_dns_timeout_exception_is_recorded_by_direct_probe(monkeypatch):
    def expired(*args, **kwargs):
        raise TimeoutError()

    monkeypatch.setattr(worker.socket, "getaddrinfo", expired)
    result = worker.run(payload())
    assert result["dns"] == "timeout" and result["state"] == "DNS_FAILURE"
    assert result["timeout_stage"] == "dns" and result["dns_ms"] >= 0


def test_worker_total_watchdog_uses_the_execution_ceiling(monkeypatch, capsys):
    timer = {"seconds": None}

    def arm(kind, seconds):
        timer["seconds"] = seconds

    def expired(parameters, observations):
        assert timer["seconds"] <= 0.100001
        raise TimeoutError()

    monkeypatch.setattr(worker.signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(worker.signal, "ITIMER_REAL", 0, raising=False)
    monkeypatch.setattr(worker.signal, "signal", lambda *args: None)
    monkeypatch.setattr(worker.signal, "setitimer", arm, raising=False)
    monkeypatch.setattr(worker, "run", expired)
    monkeypatch.setattr(worker.sys, "argv", ["worker", json.dumps(payload(timeout=0.1))])
    worker.main()
    result = decode_worker_output(capsys.readouterr().out.encode(), "connect")
    assert result["state"] == "HELPER_TIMEOUT" and result["timeout_stage"] == "execution"
    assert "_execution_deadline" not in result
    assert timer["seconds"] == 0


def test_dns_phase_alarm_restores_remaining_total_and_finally_disarms(monkeypatch, capsys):
    network(monkeypatch, dns_elapsed=0.25)
    armed = []
    monkeypatch.setattr(worker.signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(worker.signal, "ITIMER_REAL", 0, raising=False)
    monkeypatch.setattr(worker.signal, "signal", lambda *args: None)
    monkeypatch.setattr(
        worker.signal, "setitimer", lambda kind, seconds: armed.append(seconds), raising=False
    )
    monkeypatch.setattr(worker.sys, "argv", ["worker", json.dumps(payload())])
    worker.main()
    result = decode_worker_output(capsys.readouterr().out.encode(), "connect")
    assert result["state"] == "SUCCESS"
    assert armed == [5, 2, 4.75, 0]
    assert "_watchdog" not in result and "_execution_deadline" not in result


@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="Production helper uses Linux SIGALRM")
def test_linux_dns_alarm_interrupts_a_stalled_lookup_before_total_deadline(monkeypatch, capsys):
    def stalled(*args, **kwargs):
        time.sleep(0.3)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8000))]

    monkeypatch.setattr(worker.socket, "getaddrinfo", stalled)
    monkeypatch.setattr(worker.sys, "argv", ["worker", json.dumps(payload(dns_timeout=0.02))])
    started = time.monotonic()
    worker.main()
    assert time.monotonic() - started < 0.2
    result = decode_worker_output(capsys.readouterr().out.encode(), "connect")
    assert result["dns"] == "timeout" and result["timeout_stage"] == "dns"
