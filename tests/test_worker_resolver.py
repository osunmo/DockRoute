import ctypes
import json
import os
import socket
import sys
import time
from types import SimpleNamespace

import pytest

from dockroute import _probe_worker as worker


def packet(**changes):
    return json.dumps(
        {
            "status": "ok",
            "records": [[socket.AF_INET, socket.SOCK_STREAM, 6, ["127.0.0.1", 8000]]],
            **changes,
        }
    ).encode()


def test_private_dns_transport_restores_ipv4_and_ipv6_sockaddr_tuples():
    encoded = packet(
        records=[
            [socket.AF_INET, socket.SOCK_STREAM, 6, ["127.0.0.1", 8000]],
            [socket.AF_INET6, socket.SOCK_STREAM, 6, ["fe80::1", 8000, 0, 2]],
        ]
    )
    assert worker._decode_dns_response(encoded, 8000) == [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8000)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1", 8000, 0, 2)),
    ]


@pytest.mark.parametrize(
    "changes",
    [
        {"private_environment": "secret"},
        {"status": "secret"},
        {"records": "secret"},
        {"records": [[True, 1, 6, ["127.0.0.1", 8000]]]},
        {"records": [[socket.AF_INET, 1, 6, ["127.00.0.1", 8000]]]},
        {"records": [[socket.AF_INET, 1, 6, ["127.0.0.1", 9000]]]},
        {"records": [[socket.AF_INET, 1, 6, ["127.0.0.1", 8000, 0]]]},
        {"records": [[socket.AF_INET6, 1, 6, ["::1", 8000, 0, -1]]]},
        {"records": [[socket.AF_INET, 1, 6, ["127.0.0.1", 8000]]] * 65},
    ],
)
def test_private_dns_transport_rejects_malformed_data_without_echoing_it(changes):
    with pytest.raises(ValueError) as exc:
        worker._decode_dns_response(packet(**changes), 8000)
    assert "secret" not in str(exc.value)


@pytest.mark.parametrize("category", ["EAI_AGAIN", "EAI_NONAME"])
def test_private_dns_error_enums_preserve_generic_lookup_failures(category):
    encoded = json.dumps({"status": "gaierror", "category": category}).encode()
    with pytest.raises(socket.gaierror) as exc:
        worker._decode_dns_response(encoded, 8000)
    assert exc.value.errno == getattr(socket, category)
    assert "expired" not in str(exc.value) and "NXDOMAIN" not in str(exc.value)


def test_private_dns_pipe_reads_partial_chunks_through_eof(monkeypatch):
    encoded = packet()
    chunks = iter([encoded[:7], encoded[7:29], encoded[29:], b""])
    api = SimpleNamespace(read=lambda descriptor, count: next(chunks))
    selector = SimpleNamespace(select=lambda *args: ([123], [], []))
    monkeypatch.setattr(worker.time, "monotonic", lambda: 0)
    records = worker._read_dns_response(123, 1, api, selector, 8000)
    assert records[0][4] == ("127.0.0.1", 8000)


def test_private_dns_pipe_has_a_hard_byte_limit(monkeypatch):
    api = SimpleNamespace(read=lambda descriptor, count: b"x" * 65537)
    selector = SimpleNamespace(select=lambda *args: ([123], [], []))
    monkeypatch.setattr(worker.time, "monotonic", lambda: 0)
    with pytest.raises(ValueError):
        worker._read_dns_response(123, 1, api, selector, 8000)


def test_private_dns_pipe_rejects_truncated_eof(monkeypatch):
    chunks = iter([b'{"status"', b""])
    api = SimpleNamespace(read=lambda descriptor, count: next(chunks))
    selector = SimpleNamespace(select=lambda *args: ([123], [], []))
    monkeypatch.setattr(worker.time, "monotonic", lambda: 0)
    with pytest.raises(ValueError):
        worker._read_dns_response(123, 1, api, selector, 8000)


def test_private_dns_pipe_stall_is_an_absolute_deadline_timeout(monkeypatch):
    clock = SimpleNamespace(now=0)

    def wait(readers, writers, errors, budget):
        clock.now += budget
        return [], [], []

    api = SimpleNamespace(read=lambda *args: pytest.fail("unreadable pipe must not be read"))
    selector = SimpleNamespace(select=wait)
    monkeypatch.setattr(worker.time, "monotonic", lambda: clock.now)
    with pytest.raises(TimeoutError):
        worker._read_dns_response(123, 0.05, api, selector, 8000)
    assert clock.now == 0.05


def test_production_watchdog_resolves_in_isolation_instead_of_parent_libc(monkeypatch):
    def isolated(host, port, deadline):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8000))]

    def direct(*args, **kwargs):
        pytest.fail("production parent must not call libc getaddrinfo")

    monkeypatch.setattr(worker, "_resolve_in_child", isolated, raising=False)
    monkeypatch.setattr(worker, "_arm_deadline", lambda deadline: None)
    monkeypatch.setattr(worker.socket, "getaddrinfo", direct)
    result = worker.tcp_check(
        "api", 8000, 5, [], {"dns": "unknown", "tcp": "unknown", "addresses": [], "_watchdog": True}
    )
    assert result["dns"] == "ok" and result["tcp"] == "blocked"


linux_only = pytest.mark.skipif(sys.platform != "linux", reason="Linux helper resolver isolation")


def track_children(monkeypatch):
    children = []
    fork = os.fork

    def tracked():
        child = fork()
        if child:
            children.append(child)
        return child

    monkeypatch.setattr(os, "fork", tracked)
    return children


def assert_reaped(children):
    assert len(children) == 1
    with pytest.raises(ChildProcessError):
        os.waitpid(children[0], os.WNOHANG)


@linux_only
def test_linux_resolver_child_kills_and_reaps_a_blocked_c_call(monkeypatch):
    libc = ctypes.CDLL(None)

    def blocked(*args, **kwargs):
        libc.sleep(2)
        return []

    children = track_children(monkeypatch)
    monkeypatch.setattr(worker.socket, "getaddrinfo", blocked)
    descriptors = set(os.listdir("/proc/self/fd"))
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        worker._resolve_in_child("api", 8000, started + 0.05)
    assert time.monotonic() - started < 0.5
    assert_reaped(children)
    assert set(os.listdir("/proc/self/fd")) == descriptors


@linux_only
@pytest.mark.parametrize("failure", [KeyboardInterrupt, OSError])
def test_linux_resolver_child_is_reaped_after_cancel_or_transport_error(monkeypatch, failure):
    libc = ctypes.CDLL(None)

    def blocked(*args, **kwargs):
        libc.sleep(2)
        return []

    def interrupted(*args):
        raise failure()

    children = track_children(monkeypatch)
    monkeypatch.setattr(worker.socket, "getaddrinfo", blocked)
    monkeypatch.setattr(worker, "_read_dns_response", interrupted)
    descriptors = set(os.listdir("/proc/self/fd"))
    with pytest.raises(failure):
        worker._resolve_in_child("api", 8000, time.monotonic() + 5)
    assert_reaped(children)
    assert set(os.listdir("/proc/self/fd")) == descriptors


@linux_only
def test_linux_resolver_success_restores_records_and_reaps_its_child(monkeypatch):
    children = track_children(monkeypatch)
    records = worker._resolve_in_child("127.0.0.1", 8000, time.monotonic() + 1)
    assert records and all(record[4] == ("127.0.0.1", 8000) for record in records)
    assert_reaped(children)


@linux_only
@pytest.mark.parametrize("code", [socket.EAI_AGAIN, socket.EAI_NONAME])
def test_linux_resolver_child_never_forwards_raw_lookup_errors(monkeypatch, code):
    def failed(*args, **kwargs):
        raise socket.gaierror(code, "secret resolver configuration")

    children = track_children(monkeypatch)
    monkeypatch.setattr(worker.socket, "getaddrinfo", failed)
    with pytest.raises(socket.gaierror) as exc:
        worker._resolve_in_child("api", 8000, time.monotonic() + 1)
    assert exc.value.errno == code and "secret" not in str(exc.value)
    assert_reaped(children)
