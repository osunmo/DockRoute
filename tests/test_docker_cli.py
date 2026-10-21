import json
from types import SimpleNamespace

import pytest
from docker.errors import DockerException
from test_core import node

from dockroute import cli
from dockroute.docker import DockerUnavailable, Inspector, container_from_inspect


def test_inspector_parses_actual_engine_fields_without_logging_secrets():
    attrs = {
        "Id": "id",
        "Name": "/shop-api-1",
        "RestartCount": 3,
        "Config": {
            "Labels": {"com.docker.compose.project": "shop", "com.docker.compose.service": "api"},
            "Env": ["PASSWORD=hidden", "UPSTREAM_URL=http://api:8000"],
            "ExposedPorts": {"8000/tcp": {}, "53/udp": {}},
            "Healthcheck": {"Test": ["CMD", "curl", "http://localhost:8000"]},
        },
        "State": {
            "Status": "running",
            "Health": {"Status": "healthy", "Log": [{"Output": "secret"}]},
        },
        "HostConfig": {"NetworkMode": "shop_default", "ExtraHosts": ["custom:10.0.0.2"]},
        "NetworkSettings": {
            "Networks": {
                "shop_default": {
                    "NetworkID": "net-id",
                    "Aliases": ["api", "upstream"],
                    "IPAddress": "172.22.0.2",
                    "GlobalIPv6Address": "",
                }
            },
            "Ports": {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18000"}]},
        },
    }
    c = container_from_inspect(attrs)
    assert c.service == "api" and c.restart_count == 3 and c.health == "healthy"
    assert c.networks["shop_default"].aliases == ("api", "upstream")
    assert c.ports[0].container == 53 and c.ports[1].host == 18000
    assert "hidden" not in repr(c) and "secret" not in repr(c)


def test_list_projects_uses_only_summaries_and_snapshot_is_project_filtered():
    calls = []

    class API:
        def containers(self, **kw):
            calls.append(kw)
            return [
                {
                    "Id": "app-id",
                    "Names": ["/shop-app-1"],
                    "State": "running",
                    "Labels": {
                        "com.docker.compose.project": "shop",
                        "com.docker.compose.service": "app",
                    },
                }
            ]

        def inspect_container(self, identifier):
            assert identifier == "app-id"
            return {
                "Id": identifier,
                "Config": {
                    "Labels": {
                        "com.docker.compose.project": "shop",
                        "com.docker.compose.service": "app",
                    }
                },
                "State": {"Status": "running"},
            }

    client = SimpleNamespace(api=API())
    inspector = Inspector(client)
    assert inspector.identities()[0].service == "app"
    assert inspector.snapshot("shop")[0].project == "shop"
    assert calls[1]["filters"]["label"] == [
        "com.docker.compose.project=shop",
        "com.docker.compose.service",
    ]


def test_snapshot_retries_transient_engine_inspection_error():
    calls = []

    class API:
        def containers(self, **_kw):
            return [{"Id": "app-id"}]

        def inspect_container(self, identifier):
            calls.append(identifier)
            if len(calls) == 1:
                raise DockerException("transient engine error")
            return {
                "Id": identifier,
                "Config": {
                    "Labels": {
                        "com.docker.compose.project": "shop",
                        "com.docker.compose.service": "app",
                    }
                },
            }

    assert Inspector(SimpleNamespace(api=API())).snapshot("shop")[0].service == "app"
    assert calls == ["app-id", "app-id"]


def test_snapshot_persistent_engine_error_remains_unavailable():
    class API:
        def __init__(self):
            self.calls = 0

        def containers(self, **_kw):
            self.calls += 1
            raise DockerException("secret-bearing daemon error")

    api = API()
    with pytest.raises(DockerUnavailable, match="Unable to inspect") as error:
        Inspector(SimpleNamespace(api=api)).snapshot("shop")
    assert "secret-bearing" not in str(error.value)
    assert api.calls == 3


@pytest.fixture
def fake_inspector(monkeypatch):
    class Fake:
        client = None

        def identities(self):
            return [node("app"), node("api")]

        def snapshot(self, project):
            return [node("app", env={"UPSTREAM_URL": "http://api:8000"}), node("api")]

        def version(self):
            return {"Version": "29.0.0", "Os": "linux"}

        def close(self):
            pass

    monkeypatch.setattr(cli, "connect", lambda **kw: Fake())


def test_cli_doctor_json_and_manual_check(fake_inspector, capsys):
    assert cli.main(["doctor", "--project", "shop", "--format", "json"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["destination"] == "api"
    assert cli.main(["check", "app", "api:8000", "--project", "shop"]) == 2
    assert "UNKNOWN" in capsys.readouterr().out


def test_cli_docker_unavailable_json_has_no_sdk_exception_secrets(monkeypatch, capsys):
    def fail(**kw):
        raise DockerUnavailable("Docker Engine unavailable. Start Docker and check your context.")

    monkeypatch.setattr(cli, "connect", fail)
    assert cli.main(["doctor", "--format", "json"]) == 3
    error = json.loads(capsys.readouterr().out)
    assert error["error"]["code"] == "DOCKER_UNAVAILABLE"


def test_cli_invalid_target_and_missing_source(fake_inspector, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "app", "http://u:secret@api:8000/path"])
    assert exc.value.code == 4
    assert "secret" not in capsys.readouterr().err
    assert cli.main(["check", "missing", "api:8000", "--project", "shop"]) == 4
