"""Unit tests for active socket connection probe and Windows named pipe guidance."""

import socket
import threading
from unittest.mock import patch

import pytest
from docker.errors import DockerException

from dockroute.cli import main
from dockroute.docker import (
    DockerUnavailable,
    connect,
    diagnose_socket_access,
    diagnoseSocketAccess,
)
from dockroute.endpoints import (
    NPIPE_GUIDANCE,
    UnsupportedSchemeError,
    parse_endpoint,
    validate_endpoint_scheme,
)


def test_npipe_endpoint_raises_unsupported_scheme():
    with pytest.raises(UnsupportedSchemeError) as exc_info:
        validate_endpoint_scheme("npipe:////./pipe/docker_engine")
    assert "Windows Docker named pipes ('npipe://') are not directly supported" in str(
        exc_info.value
    )
    assert "tcp://host.docker.internal:2375" in str(exc_info.value)
    assert "/var/run/docker.sock" in str(exc_info.value)


def test_raw_pipe_path_raises_unsupported_scheme():
    with pytest.raises(UnsupportedSchemeError) as exc_info:
        validate_endpoint_scheme(r"\\.\pipe\docker_engine")
    assert NPIPE_GUIDANCE in str(exc_info.value)

    with pytest.raises(UnsupportedSchemeError) as exc_info2:
        validate_endpoint_scheme("//./pipe/docker_engine")
    assert NPIPE_GUIDANCE in str(exc_info2.value)


def test_parse_endpoint_with_npipe():
    with pytest.raises(UnsupportedSchemeError) as exc_info:
        parse_endpoint("npipe:////./pipe/docker_engine")
    assert NPIPE_GUIDANCE in str(exc_info.value)


def test_diagnose_socket_access_npipe_env(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "npipe:////./pipe/docker_engine")
    msg = diagnose_socket_access()
    assert msg == NPIPE_GUIDANCE


def test_diagnose_socket_access_npipe_argument():
    # Calling directly with npipe:// argument even if DOCKER_HOST is unset
    msg = diagnose_socket_access("npipe:////./pipe/docker_engine")
    assert msg == NPIPE_GUIDANCE

    msg2 = diagnose_socket_access(r"\\.\pipe\docker_engine")
    assert msg2 == NPIPE_GUIDANCE


def test_connect_with_npipe_docker_host(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "npipe:////./pipe/docker_engine")
    with pytest.raises(DockerUnavailable) as exc_info:
        connect()
    assert "Windows Docker named pipes ('npipe://') are not directly supported" in str(
        exc_info.value
    )


def test_connect_with_raw_pipe_docker_host(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", r"\\.\pipe\docker_engine")
    with pytest.raises(DockerUnavailable) as exc_info:
        connect()
    assert "Windows Docker named pipes ('npipe://') are not directly supported" in str(
        exc_info.value
    )


def test_diagnose_socket_access_nonexistent():
    msg = diagnose_socket_access("/nonexistent/path/to/docker.sock")
    assert msg is not None
    assert "not found" in msg.lower()


def test_diagnose_socket_access_strips_unix_scheme():
    msg = diagnose_socket_access("unix:///nonexistent/path/to/docker.sock")
    assert msg is not None
    assert "/nonexistent/path/to/docker.sock" in msg
    assert "unix://" not in msg


def test_diagnose_socket_access_not_a_socket(tmp_path):
    regular_file = tmp_path / "not_a_socket.sock"
    regular_file.write_text("hello")
    msg = diagnose_socket_access(str(regular_file))
    assert msg is not None
    assert "not a valid unix socket" in msg.lower()


@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="AF_UNIX required for Unix socket tests",
)
def test_diagnose_socket_access_connection_refused(tmp_path):
    sock_path = str(tmp_path / "test.sock")
    # Bind but do not listen or accept -> connection refused or refused on connect
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.close()
    # Now sock_path exists as a socket file, but no daemon is listening!
    msg = diagnose_socket_access(sock_path, probe_timeout=0.5)
    assert msg is not None
    assert "connection refused" in msg.lower() or "stopped" in msg.lower()


@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="AF_UNIX required for Unix socket tests",
)
def test_diagnose_socket_access_active_success(tmp_path):
    sock_path = str(tmp_path / "active.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)

    def serve():
        try:
            conn, _ = server.accept()
            conn.close()
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    try:
        msg = diagnose_socket_access(sock_path, probe_timeout=1.0)
        assert msg is None
    finally:
        server.close()
        t.join(timeout=1.0)


def test_diagnose_socket_access_tcp_refused_env(monkeypatch):
    # Free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    monkeypatch.setenv("DOCKER_HOST", f"tcp://127.0.0.1:{port}")
    msg = diagnose_socket_access(probe_timeout=0.5)
    assert msg is not None
    assert (
        "timed out" in msg.lower()
        or "connection refused" in msg.lower()
        or "stopped" in msg.lower()
    )


def test_diagnose_socket_access_tcp_refused_arg():
    # Direct argument
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    msg = diagnose_socket_access(f"tcp://127.0.0.1:{port}", probe_timeout=0.5)
    assert msg is not None
    assert (
        "timed out" in msg.lower()
        or "connection refused" in msg.lower()
        or "stopped" in msg.lower()
    )


def test_diagnose_socket_access_camel_case_alias():
    assert diagnoseSocketAccess is diagnose_socket_access


def test_cli_check_with_npipe_target(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["check", "web", "npipe:////./pipe/docker_engine"])
    assert exc_info.value.code == 4
    captured = capsys.readouterr()
    assert "Windows Docker named pipes ('npipe://') are not directly supported" in captured.err


def test_connect_uses_diagnose_socket_access_on_failure(monkeypatch):
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    with (
        patch("dockroute.docker.sdk.from_env") as mock_from_env,
        patch(
            "dockroute.docker.diagnose_socket_access",
            return_value="Custom diagnostic: daemon stopped",
        ),
    ):
        mock_from_env.side_effect = DockerException("Failed to ping")
        with pytest.raises(DockerUnavailable) as exc_info:
            connect()
        assert "Custom diagnostic: daemon stopped" in str(exc_info.value)
