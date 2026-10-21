import json
import socket
import subprocess
import sys

import pytest

from dockroute import _probe_worker as worker


def test_isolated_worker_imports_exclude_path_and_ip_utilities():
    bootstrap = """
import sys
filename = sys.argv[1]
with open(filename, encoding='utf-8') as source:
    namespace = {'__name__': 'isolated_worker'}
    exec(compile(source.read(), filename, 'exec'), namespace)
print(namespace['json'].dumps(sorted(
    {'pathlib', 'ipaddress', 'urllib.parse'} & set(sys.modules)
)))
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", bootstrap, worker.__file__],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert json.loads(completed.stdout) == []


class RefusedSocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def settimeout(self, value):
        pass

    def connect(self, address):
        raise ConnectionRefusedError()


def use_addresses(monkeypatch, *addresses):
    records = [
        (
            socket.AF_INET6 if ":" in address else socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (address, 8000, 0, 0) if ":" in address else (address, 8000),
        )
        for address in addresses
    ]
    monkeypatch.setattr(worker.socket, "getaddrinfo", lambda *args, **kwargs: records)
    monkeypatch.setattr(worker.socket, "socket", lambda *args: RefusedSocket())


@pytest.mark.parametrize(
    "resolved,allowed",
    [
        ("127.0.0.1", "127.0.0.1"),
        ("2001:db8::1", "2001:0DB8:0000:0000:0000:0000:0000:0001"),
        ("::ffff:192.0.2.1", "::FFFF:C000:201"),
        ("fe80::1%eth0", "FE80:0:0:0:0:0:0:1%eth0"),
        ("127.0.0.1", 2130706433),
        ("::1:0:0:0:1", (1 << 64) | 1),
        ("127.0.0.1", b"\x7f\x00\x00\x01"),
    ],
)
def test_allowed_ip_normalization_keeps_address_equivalence(monkeypatch, resolved, allowed):
    use_addresses(monkeypatch, resolved)
    result = worker.run(
        {"mode": "connect", "host": "api", "port": 8000, "timeout": 1, "allowed_ips": [allowed]}
    )
    assert result["dns"] == "ok" and result["tcp"] == "refused"
    assert result["state"] == "TCP_REFUSED"


@pytest.mark.parametrize(
    "resolved,allowed",
    [
        ("::ffff:192.0.2.1", "192.0.2.1"),
        ("fe80::1%eth0", "fe80::1%eth1"),
        ("fe80::1%eth0", "fe80::1"),
        ("fe80::1%01", "fe80::1%1"),
    ],
)
def test_distinct_families_and_ipv6_scopes_remain_blocked(monkeypatch, resolved, allowed):
    use_addresses(monkeypatch, resolved)
    result = worker.tcp_check("api", 8000, 1, [allowed])
    assert result["tcp"] == "blocked"


@pytest.mark.parametrize(
    "invalid",
    [
        "127.000.0.1",
        "01.2.3.4",
        "::ffff:192.0.002.1",
        "127.0.0.1/32",
        "::1/128",
        "fe80::1%",
        "fe80::1%eth0%eth1",
        " 127.0.0.1",
        "１２７.0.0.1",
        -1,
        2**128,
        b"123",
    ],
)
def test_invalid_allowed_addresses_keep_value_error_failure(monkeypatch, invalid):
    use_addresses(monkeypatch, "127.0.0.1")
    with pytest.raises(ValueError):
        worker.tcp_check("api", 8000, 1, [invalid])


def test_invalid_resolved_address_keeps_value_error_failure(monkeypatch):
    use_addresses(monkeypatch, "127.00.0.1")
    with pytest.raises(ValueError):
        worker.tcp_check("api", 8000, 1)


def test_canonical_duplicate_addresses_are_attempted_once(monkeypatch):
    use_addresses(monkeypatch, "::ffff:192.0.2.1", "::FFFF:C000:201")
    attempts = 0

    class FirstRefusedSocket(RefusedSocket):
        def connect(self, address):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise ConnectionRefusedError()

    monkeypatch.setattr(worker.socket, "socket", lambda *args: FirstRefusedSocket())
    result = worker.tcp_check("api", 8000, 1, ["::ffff:c000:201"])
    assert result["tcp"] == "refused"


def test_string_resolver_directory_preserves_utf8_crlf_without_writes(monkeypatch, tmp_path):
    files = {"hosts": "127.0.0.1 localhost # café\r\n", "resolv.conf": "nameserver 127.0.0.11\r\n"}
    for name, contents in files.items():
        (tmp_path / name).write_bytes(contents.encode())
    use_addresses(monkeypatch, "127.0.0.1")
    payload = {"mode": "connect", "host": "api", "port": 8000, "timeout": 1, "dns_files": files}
    result = worker.run(payload, resolver_dir=str(tmp_path))
    assert result["dns_equivalent"] is True
    assert {name: (tmp_path / name).read_bytes() for name in files} == {
        name: contents.encode() for name, contents in files.items()
    }


def test_string_proc_directory_keeps_verified_listener_observations(tmp_path):
    (tmp_path / "tcp").write_text("header\n 0: 0100007F:1F40 00000000:0000 0A\n")
    (tmp_path / "tcp6").write_text("header\n")
    assert worker.inspect_listeners(8000, str(tmp_path)) == (["127.0.0.1"], True)
