import io
import json
import socket
import tarfile
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_core import node

from dockroute._probe_worker import inspect_listeners, run, tcp_check
from dockroute.models import Connection
from dockroute.probes import ProbeCleanupError, Prober


def test_listener_inspection_uses_destination_namespace_tables(tmp_path):
    (tmp_path / "tcp").write_text(
        "header\n 0: 0100007F:1F40 00000000:0000 0A\n 1: 00000000:1F41 00000000:0000 0A\n"
    )
    (tmp_path / "tcp6").write_text(
        "header\n 0: 00000000000000000000000001000000:1F40 00000000000000000000000000000000:0000 0A\n"
    )
    addresses, verified = inspect_listeners(8000, tmp_path)
    assert verified and set(addresses) == {"127.0.0.1", "::1"}
    assert inspect_listeners(8001, tmp_path)[0] == ["0.0.0.0"]
    assert inspect_listeners(8002, tmp_path) == ([], True)
    assert inspect_listeners(8000, tmp_path / "missing") == ([], False)


def test_worker_reads_shared_resolver_files_without_modifying_them(tmp_path, monkeypatch):
    files = {"resolv.conf": "nameserver 127.0.0.11\n", "hosts": "127.0.0.1 localhost\n"}
    for name, content in files.items():
        (tmp_path / name).write_bytes(content.encode())
    import dockroute._probe_worker as worker

    monkeypatch.setattr(worker, "tcp_check", lambda *args: {"tcp": "ok", "dns": "ok"})
    payload = {"mode": "connect", "host": "api", "port": 8000, "timeout": 1, "dns_files": files}
    assert run(payload, resolver_dir=tmp_path)["dns_equivalent"]
    mismatched = {**payload, "dns_files": {**files, "resolv.conf": "nameserver 8.8.8.8\n"}}
    assert not run(mismatched, resolver_dir=tmp_path)["dns_equivalent"]
    assert {name: (tmp_path / name).read_text() for name in files} == files


def test_worker_reports_dns_failure_and_tcp_timeout_without_inventing_causes(monkeypatch):
    import dockroute._probe_worker as worker

    def unavailable(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "not found")

    monkeypatch.setattr(worker.socket, "getaddrinfo", unavailable)
    assert tcp_check("missing", 8000, 1)["dns"] == "failed"
    monkeypatch.setattr(
        worker.socket,
        "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.20.0.2", 8000))],
    )

    class TimedSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, value):
            pass

        def connect(self, target):
            raise TimeoutError()

    monkeypatch.setattr(worker.socket, "socket", lambda *a: TimedSocket())
    result = tcp_check("api", 8000, 1, ["172.20.0.2"])
    assert result["dns"] == "ok" and result["tcp"] == "timeout"


def test_tcp_worker_distinguishes_reachable_refused_and_denied_scope():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        assert tcp_check("127.0.0.1", port, 1, ["127.0.0.1"])["tcp"] == "ok"
        assert tcp_check("127.0.0.1", port, 1, ["172.20.0.2"])["tcp"] == "blocked"
    # Windows can take multiple SYN retries before reporting ECONNREFUSED.
    assert tcp_check("127.0.0.1", port, 5, ["127.0.0.1"])["tcp"] == "refused"


def archive(name, content):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as tf:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    return [data.getvalue()], {}


class FakeClient:
    def __init__(self, failure=None):
        self.created = []
        self.removed = []
        self.failure = failure
        self.images = SimpleNamespace(get=lambda image: object())
        self.containers = SimpleNamespace(get=self.get, create=self.create)

    def get(self, identifier):
        if identifier.startswith("dockroute-probe-"):
            from docker.errors import NotFound

            raise NotFound("absent")
        service = identifier.split("-")[0]
        return SimpleNamespace(
            attrs={
                "Config": {
                    "Labels": {
                        "com.docker.compose.project": "shop",
                        "com.docker.compose.service": service,
                    }
                },
                "State": {"Running": True},
                "HostConfig": {"NetworkMode": "shop_default"},
            },
            get_archive=lambda path: archive(path.split("/")[-1], b"nameserver 127.0.0.11\n"),
        )

    def create(self, image, **kwargs):
        self.created.append(kwargs)
        mode = json.loads(kwargs["command"][-1])["mode"]

        def wait(**kw):
            if self.failure == "wait":
                helper.attrs["State"] = {"Status": "running", "Running": True, "ExitCode": 0}
                raise TimeoutError()
            if self.failure == "cancel":
                raise KeyboardInterrupt()
            return {"StatusCode": 0}

        def remove(**kw):
            if self.failure == "cleanup":
                raise RuntimeError("never expose SDK secrets")
            self.removed.append(mode)

        result = (
            {"dns": "ok", "tcp": "refused", "addresses": ["172.20.0.2"], "dns_equivalent": True}
            if mode == "connect"
            else {"listener_addresses": ["127.0.0.1"], "listener_verified": True}
        )
        helper = SimpleNamespace(
            id="helper-" + mode,
            attrs={
                "Image": "sha256:" + "a" * 64,
                "Config": {"Labels": kwargs["labels"]},
                "State": {"Status": "exited", "ExitCode": 0},
            },
            reload=lambda: None,
            start=lambda: None,
            wait=wait,
            remove=remove,
            logs=lambda **kw: (
                (
                    json.dumps({"event": "ready", "worker_schema": "1"})
                    + "\n"
                    + json.dumps(
                        {
                            "event": "result",
                            "worker_schema": "1",
                            "state": "TCP_REFUSED" if mode == "connect" else "SUCCESS",
                            **result,
                        }
                    )
                    + "\n"
                ).encode()
                if kw.get("stdout")
                else b""
            ),
        )
        return helper


def test_helper_lifecycle_cleanup_and_least_privilege():
    client = FakeClient()
    p = Prober(client, "shop", timeout=1, engine_os="linux")
    result = p.check(Connection("app-id", "app", "api", 8000), [node("app"), node("api")])
    assert result.listener_verified and result.tcp == "refused"
    assert client.removed == ["connect", "listen"]
    for config in client.created:
        assert config["network_mode"].startswith("container:")
        assert config["cap_drop"] == ["ALL"] and config["read_only"]
        assert config["labels"]["io.dockroute.helper"] == "true"
        assert "volumes" not in config and "privileged" not in config


@pytest.mark.parametrize("failure", ["wait", "cancel"])
def test_helper_cleanup_on_timeout_and_cancellation(failure):
    client = FakeClient(failure)
    p = Prober(client, "shop", timeout=1, engine_os="linux")
    if failure == "cancel":
        with pytest.raises(KeyboardInterrupt):
            p.check(Connection("app-id", "app", "api", 8000), [node("app"), node("api")])
    else:
        assert (
            p.check(Connection("app-id", "app", "api", 8000), [node("app"), node("api")]).tcp
            == "unknown"
        )
    assert client.removed


def test_cleanup_failure_is_a_reportable_error():
    with pytest.raises(ProbeCleanupError, match="helper-connect"):
        Prober(FakeClient("cleanup"), "shop", engine_os="linux").check(
            Connection("app-id", "app", "api", 8000), [node("app"), node("api")]
        )


def test_automatic_probe_never_scans_external_or_other_projects():
    client = FakeClient()
    p = Prober(client, "shop", engine_os="linux")
    assert p.check(Connection("app-id", "app", "example.com", 443), [node("app")]).tcp == "unknown"
    foreign = replace(node("api"), project="foreign")
    p.check(Connection("app-id", "app", "api", 8000), [node("app"), foreign])
    assert not client.created


def test_probe_unsupported_engine_and_missing_image_do_not_create_helpers():
    client = FakeClient()
    result = Prober(client, "shop", engine_os="windows").check(
        Connection("app-id", "app", "api", 8000), [node("app"), node("api")]
    )
    assert result.notes and not client.created
    from docker.errors import ImageNotFound

    def missing(image, **kwargs):
        raise ImageNotFound("not found")

    client.containers.create = missing
    result = Prober(client, "shop", engine_os="linux").check(
        Connection("app-id", "app", "api", 8000), [node("app"), node("api")]
    )
    assert "locally" in " ".join(result.notes)
    assert not client.created
