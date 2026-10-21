"""Live corpus isolation/lifecycle boundaries, without starting Docker resources."""

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from docker.errors import NotFound

PROJECT = "dockroute-corpus-" + "a" * 32


@pytest.fixture
def live():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_corpus_live.py"
    assert path.is_file(), "the safe live corpus runner has not been implemented"
    spec = importlib.util.spec_from_file_location("corpus_live_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configuration():
    return {
        "name": "upstream",
        "services": {
            "app": {
                "image": "example/app:1",
                "container_name": "fixed-app",
                "environment": {"DATABASE_URL": "postgres://db:5432/test"},
                "ports": [{"target": 8080, "published": "8080", "host_ip": "0.0.0.0"}],
                "networks": {"backend": {"aliases": ["application"]}},
                "volumes": [{"type": "volume", "source": "data", "target": "/data"}],
            },
            "db": {"image": "example/db:1", "networks": {"backend": None}},
        },
        "networks": {"backend": {"name": "shared-backend"}},
        "volumes": {"data": {"name": "production-data"}},
    }


def test_preparation_preserves_service_aliases_and_replaces_global_resource_names(live, tmp_path):
    original = configuration()
    frozen = copy.deepcopy(original)
    result = live.prepare_config(original, PROJECT, tmp_path)
    assert original == frozen
    assert set(result["services"]) == {"app", "db"}
    assert result["services"]["app"]["networks"] == {"backend": {"aliases": ["application"]}}
    assert "container_name" not in result["services"]["app"]
    assert result["services"]["app"]["ports"] == [
        {"target": 8080, "published": "0", "host_ip": "127.0.0.1"}
    ]
    assert result["networks"]["backend"]["name"] == PROJECT + "_network_backend"
    assert result["volumes"]["data"]["name"] == PROJECT + "_volume_data"
    assert result["volumes"]["data"]["labels"]["io.dockroute.corpus.owner"] == PROJECT
    assert live.validate_isolation(result, PROJECT, tmp_path)["isolated"] is True


@pytest.mark.parametrize(
    ("section", "value"),
    [
        ("privileged", True),
        ("devices", ["/dev/sda:/dev/sda"]),
        ("cap_add", ["SYS_ADMIN"]),
        ("network_mode", "host"),
        ("network_mode", "container:production"),
        ("pid", "host"),
        ("volumes_from", ["production"]),
        ("extra_hosts", ["database:host-gateway"]),
        ("post_start", [{"command": "id", "privileged": True}]),
        ("pre_start", [{"command": "id", "privileged": True}]),
        ("pre_stop", [{"command": "id", "privileged": True}]),
        ("credential_spec", {"file": "C:/outside-scratch/credential.json"}),
    ],
)
def test_host_access_and_foreign_resource_references_are_refused(live, tmp_path, section, value):
    config = configuration()
    config["services"]["app"][section] = value
    with pytest.raises(live.SafetyError):
        live.prepare_config(config, PROJECT, tmp_path)


@pytest.mark.parametrize("resource", ["networks", "volumes", "configs", "secrets"])
def test_external_resources_are_refused_before_name_rewriting(live, tmp_path, resource):
    config = configuration()
    config[resource] = {"outside": {"external": True, "name": "production"}}
    with pytest.raises(live.SafetyError):
        live.prepare_config(config, PROJECT, tmp_path)


def test_bind_and_file_resources_confined_readonly_and_identifier_names_retained(live, tmp_path):
    data = tmp_path / "payload"
    data.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("inert fixture value")
    config = configuration()
    config["services"]["app"]["volumes"] = [
        {"type": "bind", "source": str(data), "target": "/app/data"}
    ]
    config["secrets"] = {"password": {"file": str(secret), "name": "production-password"}}
    config["configs"] = {"settings": {"file": str(secret)}}
    config["services"]["app"]["secrets"] = [{"source": "password", "target": "password"}]
    result = live.prepare_config(config, PROJECT, tmp_path)
    assert result["services"]["app"]["volumes"][0]["read_only"] is True
    assert set(result["secrets"]) == {"password"}
    assert result["services"]["app"]["secrets"][0]["source"] == "password"
    assert result["secrets"]["password"]["name"] == PROJECT + "_secret_password"
    writable = live.prepare_config(
        config, PROJECT, tmp_path, writable_paths={str(data): "fixture application cache"}
    )
    assert writable["services"]["app"]["volumes"][0]["read_only"] is False


@pytest.mark.parametrize("kind", ["bind", "secret", "build"])
def test_paths_and_symlink_targets_cannot_escape_scratch(live, tmp_path, kind):
    root = tmp_path / "scratch"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        if sys.platform != "win32":
            pytest.skip("symlink creation is unavailable on this host")
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True, timeout=10
        )
        if created.returncode:
            pytest.skip("symlink and junction creation are unavailable on this host")
    config = configuration()
    if kind == "bind":
        config["services"]["app"]["volumes"] = [
            {"type": "bind", "source": str(link), "target": "/payload"}
        ]
    elif kind == "secret":
        config["secrets"] = {"bad": {"file": str(link / "credential")}}
    else:
        config["services"]["app"]["build"] = {"context": str(root)}
    with pytest.raises(live.SafetyError):
        live.prepare_config(config, PROJECT, root)


def test_direct_parent_path_and_docker_socket_are_refused(live, tmp_path):
    root = tmp_path / "scratch"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("fixture")
    for source, target in ((str(outside), "/payload"), (str(root), "/var/run/docker.sock")):
        config = configuration()
        config["services"]["app"]["volumes"] = [
            {"type": "bind", "source": source, "target": target}
        ]
        with pytest.raises(live.SafetyError):
            live.prepare_config(config, PROJECT, root)


def test_whole_private_scratch_directory_is_a_readonly_confined_bind(live, tmp_path):
    payload = tmp_path / "app.py"
    payload.write_text("print('fixture')")
    config = configuration()
    config["services"]["app"]["volumes"] = [
        {"type": "bind", "source": str(tmp_path), "target": "/code"}
    ]
    prepared = live.prepare_config(config, PROJECT, tmp_path)
    assert prepared["services"]["app"]["volumes"][0]["read_only"] is True
    assert live.validate_isolation(prepared, PROJECT, tmp_path)["isolated"] is True


def test_numeric_server_port_is_not_a_hostname_but_numeric_host_still_refused(live, tmp_path):
    config = configuration()
    config["services"]["app"]["environment"]["FLASK_SERVER_PORT"] = "9091"
    prepared = live.prepare_config(config, PROJECT, tmp_path)
    assert prepared["services"]["app"]["environment"]["FLASK_SERVER_PORT"] == "9091"
    config["services"]["app"]["environment"]["DATABASE_HOST"] = "9091"
    with pytest.raises(live.SafetyError):
        live.prepare_config(config, PROJECT, tmp_path)


def test_external_endpoint_requires_explicit_recipe_review(live, tmp_path):
    config = configuration()
    config["services"]["app"]["environment"]["DATABASE_URL"] = "postgres://prod.example:5432/x"
    with pytest.raises(live.SafetyError):
        live.prepare_config(config, PROJECT, tmp_path)
    result = live.prepare_config(
        config, PROJECT, tmp_path, approved_external_endpoints=["prod.example"]
    )
    assert result["services"]["app"]["environment"]["DATABASE_URL"].startswith("postgres://")


def test_prelaunch_revalidation_rejects_privilege_or_unapproved_writable_bind_mutation(
    live, tmp_path
):
    config = live.prepare_config(configuration(), PROJECT, tmp_path)
    config["services"]["app"]["privileged"] = True
    with pytest.raises(live.SafetyError):
        live.validate_isolation(config, PROJECT, tmp_path)
    payload = tmp_path / "payload"
    payload.mkdir()
    config = configuration()
    config["services"]["app"]["volumes"] = [
        {"type": "bind", "source": str(payload), "target": "/payload"}
    ]
    prepared = live.prepare_config(config, PROJECT, tmp_path)
    prepared["services"]["app"]["volumes"][0]["read_only"] = False
    with pytest.raises(live.SafetyError):
        live.validate_isolation(prepared, PROJECT, tmp_path)


def test_unowned_volume_driver_options_and_tmpfs_paths_are_refused(live, tmp_path):
    config = configuration()
    config["volumes"]["data"]["driver_opts"] = {"type": "none", "device": "/", "o": "bind"}
    with pytest.raises(live.SafetyError):
        live.prepare_config(config, PROJECT, tmp_path)


def test_anonymous_compose_and_image_volumes_become_explicit_owned_mounts(live, tmp_path):
    config = configuration()
    config["services"]["app"]["volumes"].append({"type": "volume", "target": "/scratch"})
    prepared = live.prepare_config(config, PROJECT, tmp_path)
    api = FakeAPI(live)
    live.freeze_images(prepared, PROJECT, api)
    mounts = prepared["services"]["app"]["volumes"]
    assert {mount["target"] for mount in mounts} == {"/data", "/scratch", "/implicit"}
    for mount in mounts:
        volume = prepared["volumes"][mount["source"]]
        assert volume["name"].startswith(PROJECT + "_volume_")
        assert volume["labels"][live.OWNER_LABEL] == PROJECT
    assert prepared["services"]["app"]["image"] == "sha256:" + "b" * 64
    records = live.freeze_images(prepared, PROJECT, api)
    assert records[0]["repo_digests"] == ["example/app@sha256:" + "d" * 64]


class FakeAPI:
    """Docker API side effects only; actual isolation and cleanup code stays real."""

    def __init__(self, live):
        self.live = live
        self.volumes_by_name = {}
        self.containers_by_id = {}
        self.networks_by_id = {}
        self.removed = []

    def containers(self, all=True, filters=None):
        return [v for v in self.containers_by_id.values() if self._match(v["Labels"], filters)]

    def networks(self, filters=None):
        return [v for v in self.networks_by_id.values() if self._match(v["Labels"], filters)]

    def volumes(self, filters=None):
        return {
            "Volumes": [
                v for v in self.volumes_by_name.values() if self._match(v["Labels"], filters)
            ]
        }

    @staticmethod
    def _match(labels, filters):
        for item in (filters or {}).get("label", []):
            key, _, value = item.partition("=")
            if key not in labels or (value and labels[key] != value):
                return False
        return True

    def inspect_image(self, image):
        return {
            "Id": "sha256:" + "b" * 64,
            "RepoDigests": ["example/app@sha256:" + "d" * 64],
            "Config": {"Volumes": {"/implicit": {}}},
        }

    def inspect_volume(self, name):
        if name not in self.volumes_by_name:
            raise NotFound("missing")
        return copy.deepcopy(self.volumes_by_name[name])

    def inspect_network(self, name):
        for attrs in self.networks_by_id.values():
            if attrs["Name"] == name:
                return attrs
        raise NotFound("missing")

    def inspect_container(self, name):
        if name not in self.containers_by_id:
            raise NotFound("missing")
        return self.containers_by_id[name]

    def remove_volume(self, name, force=False):
        assert force is False, "owned volume deletion must fail if still in use"
        self.removed.append(name)
        del self.volumes_by_name[name]


def owned_volume(live, project, name, *, created="2026-10-13T00:00:00Z"):
    return {
        "Name": name,
        "CreatedAt": created,
        "Driver": "local",
        "Scope": "local",
        "Labels": {
            "com.docker.compose.project": project,
            live.OWNER_LABEL: project,
        },
        "Options": {},
        "Mountpoint": "/var/lib/docker/volumes/" + name,
    }


def test_volume_cleanup_prevalidates_every_exact_identity_before_deleting(live, tmp_path):
    config = live.prepare_config(configuration(), PROJECT, tmp_path)
    config["volumes"]["other"] = {
        "name": PROJECT + "_volume_other",
        "labels": {live.OWNER_LABEL: PROJECT},
    }
    api = FakeAPI(live)
    first = owned_volume(live, PROJECT, PROJECT + "_volume_data")
    second = owned_volume(live, PROJECT, PROJECT + "_volume_other")
    second["Labels"][live.OWNER_LABEL] = "foreign"
    api.volumes_by_name = {v["Name"]: v for v in (first, second)}
    result = live.cleanup_owned_volumes(api, config, PROJECT, {})
    assert result["cleanup"] == "failed"
    assert api.removed == []
    second["Labels"][live.OWNER_LABEL] = PROJECT
    result = live.cleanup_owned_volumes(api, config, PROJECT, {})
    assert result["cleanup"] == "complete"
    assert set(api.removed) == {PROJECT + "_volume_data", PROJECT + "_volume_other"}


@pytest.mark.parametrize("created_at", [None, "", "malformed", "2026-99-13T00:00:00Z"])
def test_missing_or_invalid_volume_creation_identity_is_never_deleted(live, tmp_path, created_at):
    config = live.prepare_config(configuration(), PROJECT, tmp_path)
    api = FakeAPI(live)
    attrs = owned_volume(live, PROJECT, PROJECT + "_volume_data", created=created_at)
    api.volumes_by_name[attrs["Name"]] = attrs
    result = live.cleanup_owned_volumes(
        api, config, PROJECT, {}, created=copy.deepcopy(api.volumes_by_name)
    )
    assert result["cleanup"] == "failed"
    assert api.removed == []


def test_down_refuses_container_or_network_ids_absent_from_captured_lease(live, tmp_path):
    config = live.prepare_config(configuration(), PROJECT, tmp_path)
    api = FakeAPI(live)
    labels = {live.OWNER_LABEL: PROJECT, "com.docker.compose.project": PROJECT}
    api.containers_by_id["new-container"] = {"Id": "new-container", "Labels": labels}
    api.networks_by_id["new-network"] = {
        "Id": "new-network",
        "Name": PROJECT + "_network_backend",
        "Labels": labels,
    }
    captured = {"containers": ["old-container"], "networks": ["old-network"]}
    with pytest.raises(live.SafetyError):
        live._guard_down(api, PROJECT, config, captured=captured)
    api.containers_by_id["new-container"]["Labels"] = {
        **labels,
        "com.docker.compose.service": "unplanned-service",
    }
    captured = {"containers": ["new-container"], "networks": ["new-network"]}
    with pytest.raises(live.SafetyError):
        live._guard_down(api, PROJECT, config, captured=captured)


def test_preexisting_volume_and_changed_volume_identity_are_never_removed(live, tmp_path):
    config = live.prepare_config(configuration(), PROJECT, tmp_path)
    api = FakeAPI(live)
    attrs = owned_volume(live, PROJECT, PROJECT + "_volume_data")
    api.volumes_by_name[attrs["Name"]] = attrs
    result = live.cleanup_owned_volumes(api, config, PROJECT, {attrs["Name"]: attrs})
    assert result["cleanup"] == "failed"
    assert api.removed == []
    captured = copy.deepcopy(api.volumes_by_name)
    attrs["CreatedAt"] = "2026-10-13T00:00:01Z"
    result = live.cleanup_owned_volumes(api, config, PROJECT, {}, created=captured)
    assert result["cleanup"] == "failed"
    assert api.removed == []


def test_runtime_mount_evidence_refuses_anonymous_or_wrong_project_volume(live, tmp_path):
    config = live.prepare_config(configuration(), PROJECT, tmp_path)
    api = FakeAPI(live)
    labels = {
        live.OWNER_LABEL: PROJECT,
        "com.docker.compose.project": PROJECT,
        "com.docker.compose.service": "app",
    }
    api.containers_by_id["e" * 64] = {
        "Id": "e" * 64,
        "Labels": labels,
        "Config": {"Labels": labels},
        "Image": "example/app:1",
        "Mounts": [
            {"Type": "volume", "Name": "anonymous-foreign", "Destination": "/data", "RW": True}
        ],
    }
    with pytest.raises(live.SafetyError):
        live.inspect_owned_mounts(api, config, PROJECT)
    name = PROJECT + "_volume_data"
    api.volumes_by_name[name] = owned_volume(live, PROJECT, name)
    api.containers_by_id["e" * 64]["Mounts"][0]["Name"] = name
    result = live.inspect_owned_mounts(api, config, PROJECT)
    assert result[0]["mounts"][0]["volume_name"] == name


def test_full_raw_outcomes_retained_on_http_failure_and_exact_resources_cleaned(
    live, tmp_path, monkeypatch
):
    api = FakeAPI(live)
    inspector = SimpleNamespace(client=SimpleNamespace(api=api))
    config_path = tmp_path / "normalized.json"
    config_path.write_text(json.dumps(configuration()))
    recipe = {
        "id": "fixture",
        "root": str(tmp_path),
        "compose_file": str(config_path),
        "incoming_service": "app",
        "incoming_port": 8080,
        "health_path": "/",
        "expected_statuses": [200],
        "annotations": ["prepared fixture"],
        "checks": [{"source": "app", "target": "db:5432"}],
    }
    commands = []

    def command(argv, *, timeout, cwd, log_directory, env=None):
        commands.append(argv)
        frozen = json.loads(Path(argv[argv.index("-f") + 1]).read_text())
        project = argv[argv.index("-p") + 1]
        if "up" in argv:
            for volume in frozen["volumes"].values():
                attrs = owned_volume(live, project, volume["name"])
                api.volumes_by_name[attrs["Name"]] = attrs
        return {"exit_code": 0, "timed_out": False}

    raw = {"schema_version": "3.0", "findings": [{"code": "UNKNOWN"}], "status": "UNKNOWN"}
    monkeypatch.setattr(live, "_command", command)
    monkeypatch.setattr(
        live,
        "run_diagnostic",
        lambda *args, **kwargs: {
            "report": copy.deepcopy(raw),
            "cleanup": "complete",
            "exit_code": 2,
            "source": {"stable": True, "before": {}, "after": {}},
        },
    )
    monkeypatch.setattr(
        live, "check_http", lambda *args, **kwargs: {"ready": False, "error": "http_unavailable"}
    )
    result = live.run_case(recipe, inspector=inspector)
    assert result["status"] == "failed"
    assert result["automatic"]["static"]["report"] == raw
    assert result["automatic"]["probe"]["report"] == raw
    assert result["manual_checks"][0]["discovery"] == "manual_only"
    assert result["manual_checks"][0]["source_service"] == "app"
    assert result["manual_checks"][0]["source"]["stable"] is True
    assert result["cleanup"]["cleanup"] == "complete"
    assert api.volumes_by_name == {}
    assert any("down" in argv for argv in commands)
    assert all("-v" not in argv and "--volumes" not in argv for argv in commands)
    assert (Path(result["private_directory"]) / "frozen-compose.json").is_file()


@pytest.mark.parametrize("invalid", [False, True])
def test_case_consumes_grading_validity_and_recipe_readiness_deadline(
    live, tmp_path, monkeypatch, invalid
):
    api = FakeAPI(live)
    inspector = SimpleNamespace(client=SimpleNamespace(api=api))
    config_path = tmp_path / "normalized.json"
    config_path.write_text(json.dumps(configuration()))
    recipe = {
        "id": "grading",
        "root": str(tmp_path),
        "compose_file": str(config_path),
        "incoming_service": "app",
        "incoming_port": 8080,
        "readiness_timeout": 1,
    }
    monkeypatch.setattr(
        live, "_command", lambda *args, **kwargs: {"exit_code": 0, "timed_out": False}
    )
    deadlines = []

    def http(*args, **kwargs):
        deadlines.append(kwargs.get("timeout"))
        return {"ready": True}

    monkeypatch.setattr(live, "check_http", http)
    raw = (
        {"schema_version": "3.0", "error": {"code": "SOURCE_SELECTION"}}
        if invalid
        else {"schema_version": "3.0", "findings": []}
    )
    monkeypatch.setattr(
        live,
        "run_diagnostic",
        lambda *args, **kwargs: {
            "report": copy.deepcopy(raw),
            "cleanup": "not_needed",
            "exit_code": 4 if invalid else 0,
            "valid_for_grading": not invalid,
        },
    )
    result = live.run_case(recipe, inspector=inspector)
    assert result["status"] == ("failed" if invalid else "complete")
    assert deadlines == [1]
    assert result["automatic"]["probe"]["report"] == raw


def test_missing_images_are_refused_without_pull_before_up(live, tmp_path, monkeypatch):
    api = FakeAPI(live)
    api.inspect_image = lambda image: (_ for _ in ()).throw(NotFound("missing"))
    inspector = SimpleNamespace(client=SimpleNamespace(api=api))
    config_path = tmp_path / "normalized.json"
    config_path.write_text(json.dumps(configuration()))
    recipe = {
        "id": "missing",
        "root": str(tmp_path),
        "compose_file": str(config_path),
        "incoming_service": "app",
        "incoming_port": 8080,
    }
    commands = []
    monkeypatch.setattr(live, "_command", lambda argv, **kwargs: commands.append(argv))
    result = live.run_case(recipe, inspector=inspector)
    assert result["status"] == "refused"
    assert result["error"] == "image_missing_pull_not_allowed"
    assert commands == []


def test_invalid_manual_endpoint_is_refused_before_launch_and_not_exported(
    live, tmp_path, monkeypatch
):
    api = FakeAPI(live)
    inspector = SimpleNamespace(client=SimpleNamespace(api=api))
    config_path = tmp_path / "normalized.json"
    config_path.write_text(json.dumps(configuration()))
    recipe = {
        "id": "unsafe-manual",
        "root": str(tmp_path),
        "compose_file": str(config_path),
        "incoming_service": "app",
        "incoming_port": 8080,
        "checks": [{"source": "app", "target": "user:privatevalue@prod.example:5432"}],
    }
    commands = []
    monkeypatch.setattr(live, "_command", lambda argv, **kwargs: commands.append(argv))
    result = live.run_case(recipe, inspector=inspector)
    assert result["status"] == "refused"
    assert result["error"] == "manual_check_invalid"
    assert "privatevalue" not in json.dumps(result)
    assert commands == []


def test_http_checks_exact_owned_mapping_and_refuses_redirects(live):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "http://foreign.invalid/")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"fixture ready")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        api = FakeAPI(live)
        labels = {
            live.OWNER_LABEL: PROJECT,
            "com.docker.compose.project": PROJECT,
            "com.docker.compose.service": "app",
        }
        api.containers_by_id["e" * 64] = {
            "Id": "e" * 64,
            "Labels": labels,
            "Config": {"Labels": labels},
            "NetworkSettings": {
                "Ports": {
                    "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(server.server_port)}]
                }
            },
        }
        recipe = {
            "incoming_service": "app",
            "incoming_port": 8080,
            "expected_body_pattern": "fixture ready",
        }
        assert live._incoming_port(api, PROJECT, "app", 8080) == server.server_port
        result = live.check_http(api, PROJECT, recipe, timeout=1)
        assert result["ready"] is True, result
        assert result["mapped_port"] == server.server_port
        assert "fixture ready" not in json.dumps(result)
        recipe.update(health_path="/redirect", expected_body_pattern=None)
        result = live.check_http(api, PROJECT, recipe, timeout=5)
        assert result["ready"] is False
        assert result["http_status"] == 302
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_command_timeout_reaps_owned_grandchild_before_returning(live, tmp_path):
    child_file = tmp_path / "child.py"
    parent_file = tmp_path / "parent.py"
    marker = tmp_path / "alive.txt"
    child_file.write_text(
        "import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\n"
        "deadline=time.monotonic()+30\n"
        "while time.monotonic()<deadline:\n p.write_text(str(time.time()))\n time.sleep(.02)\n"
    )
    parent_file.write_text(
        "import subprocess,sys,time\n"
        "subprocess.Popen([sys.executable,sys.argv[1],sys.argv[2]])\n"
        "time.sleep(60)\n"
    )
    result = live._command(
        [sys.executable, str(parent_file), str(child_file), str(marker)],
        timeout=10,
        cwd=tmp_path,
        log_directory=tmp_path / "logs",
    )
    assert result["timed_out"] is True
    assert marker.is_file(), result
    last = marker.read_text()
    time.sleep(0.2)
    assert marker.read_text() == last, "owned grandchild kept mutating after timeout cleanup"
    assert result["process_tree_exited"] is True


def test_command_logs_have_a_bounded_private_disk_footprint(live, tmp_path):
    result = live._command(
        [
            sys.executable,
            "-c",
            "import sys,time;sys.stdout.write('x'*(17*1024*1024));sys.stdout.flush();time.sleep(2)",
        ],
        timeout=10,
        cwd=tmp_path,
        log_directory=tmp_path / "logs",
    )
    assert result["error"] == "command_log_limit"
    assert Path(result["stdout_path"]).stat().st_size <= 16 * 1024 * 1024
    assert result["process_tree_exited"] is True


def test_child_timeout_uses_private_cancel_and_reaps_only_owned_child(live, tmp_path):
    api = FakeAPI(live)
    inspector = SimpleNamespace(client=SimpleNamespace(api=api))
    control = tmp_path / "control"
    control.mkdir()
    code = (
        "import json,time,pathlib; p=pathlib.Path(__import__('sys').argv[1]); "
        "(p/'lease.json').write_text(json.dumps({'execution_id':'c'*32,'project':__import__('sys').argv[2],'helpers':[]})); "
        "\nwhile not (p/'cancel').exists(): time.sleep(.01)\n"
        "print(json.dumps({'schema_version':'3.0','error':{'code':'CANCELLED'}}))"
    )
    result = live.run_diagnostic(
        inspector,
        PROJECT,
        control,
        command=[sys.executable, "-c", code, str(control), PROJECT],
        probe=True,
        timeout=0.2,
    )
    assert result["cancellation_requested"] is True
    assert result["error"] == "child_timeout"
    assert result["report"]["error"]["code"] == "CANCELLED"
    assert result["cleanup"] == "complete"
    assert result["exit_code"] == 0
    assert result["process_tree_exited"] is True
    assert result["command"][0] == sys.executable
    assert result["wall_ms"] > 0
    assert Path(result["stdout_path"]).read_text().strip().startswith("{")
    assert Path(result["stderr_path"]).read_text() == ""


@pytest.mark.parametrize("mutate", [False, True])
def test_each_diagnostic_fingerprints_actual_invocation_and_refuses_midrun_source_change(
    live, tmp_path, monkeypatch, mutate
):
    source_root = tmp_path / "source"
    source_root.mkdir()
    module = source_root / "cli.py"
    module.write_text("# original\n", encoding="utf-8")
    worker = source_root / "_probe_worker.py"
    worker.write_bytes(b"print('fixture')\r\n")
    monkeypatch.setattr(live, "SOURCE_DIRECTORY", source_root, raising=False)
    code = (
        "import json,pathlib,sys;"
        + ("pathlib.Path(sys.argv[1]).write_text('# modified\\n');" if mutate else "")
        + "print(json.dumps({'schema_version':'3.0','dockroute_version':'fixture-version','findings':[]}))"
    )
    inspector = SimpleNamespace(client=SimpleNamespace(api=FakeAPI(live)))
    result = live.run_diagnostic(
        inspector,
        PROJECT,
        tmp_path / "control",
        command=[sys.executable, "-c", code, str(module)],
        timeout=10,
    )
    assert result["report"]["dockroute_version"] == "fixture-version"
    assert result["source"]["dockroute_version"] == "fixture-version"
    assert (
        result["source"]["before"]["helper_worker_sha256"]
        == hashlib.sha256(b"print('fixture')\n").hexdigest()
    ), "helper transports read_text UTF-8 bytes after newline normalization"
    assert result["source"]["stable"] is (not mutate)
    assert result["valid_for_grading"] is (not mutate)
    if mutate:
        assert result["error"] == "source_changed_during_diagnostic"
        assert (
            result["source"]["before"]["product_source_sha256"]["cli.py"]
            != result["source"]["after"]["product_source_sha256"]["cli.py"]
        )
    else:
        assert result["source"]["before"] == result["source"]["after"]


def test_static_process_tree_uncertainty_is_an_error_without_discarding_raw_json(
    live, tmp_path, monkeypatch
):
    monkeypatch.setattr(live._ProcessTree, "confirm_exited", lambda *args, **kwargs: False)
    inspector = SimpleNamespace(client=SimpleNamespace(api=FakeAPI(live)))
    result = live.run_diagnostic(
        inspector,
        PROJECT,
        tmp_path / "control",
        command=[sys.executable, "-c", 'print(\'{"schema_version":"3.0","findings":[]}\')'],
        timeout=10,
    )
    assert result["report"]["findings"] == []
    assert result["error"] == "diagnostic_process_tree_uncertain"
    assert result["valid_for_grading"] is False
