"""Run an explicitly prepared, private Compose corpus recipe with owned cleanup.

Recipe: {id, root, compose_file, incoming_service, incoming_port, health_path: '/',
expected_statuses: [200], expected_body_pattern?: str, annotations?: list,
checks?: [{source, target}], writable_paths?: {absolute_path: reason},
approved_external_endpoints?: [host]}. compose_file is resolved Compose JSON.

Builds/pulls require explicit flags. Raw command logs and frozen configurations
stay under work/corpus-live; exported evidence contains sanitized error codes and
unchanged DockRoute JSON. Manual checks never enter automatic discovery results.
"""

import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORY = ROOT / "src" / "dockroute"
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from docker.errors import DockerException, NotFound  # noqa: E402

from dockroute.docker import DockerUnavailable, connect  # noqa: E402

OWNER_LABEL = "io.dockroute.corpus.owner"
PROJECT_LABEL = "com.docker.compose.project"
ERRORS = (OSError, ValueError, TypeError, DockerException, DockerUnavailable)
RESOURCE_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
PROJECT_KEY = re.compile(r"dockroute-corpus-[0-9a-f]{32}")


class SafetyError(ValueError):
    """Stable, non-secret refusal code; never include raw configuration values."""


def _canonical(value, *, depth=0):
    """Resolve links using lstat/readlink (Windows sandbox denies strict directory handles)."""
    if depth > 40:
        raise SafetyError("path_link_cycle")
    absolute = Path(os.path.abspath(value))
    current = Path(absolute.anchor)
    parts = absolute.parts[1:]
    for index, part in enumerate(parts):
        current /= part
        attrs = current.lstat()
        reparse = getattr(attrs, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024
        )
        if stat.S_ISLNK(attrs.st_mode) or reparse:
            try:
                target = os.readlink(current)
            except OSError:
                raise SafetyError("path_reparse_unresolved") from None
            if target.startswith("\\\\?\\"):
                target = target[4:]
            linked = Path(target)
            if not linked.is_absolute():
                linked = current.parent / linked
            return _canonical(linked.joinpath(*parts[index + 1 :]), depth=depth + 1)
    return absolute


def _path(value, root, *, directory=False, allow_root=False):
    try:
        root = _canonical(root)
        path = Path(value)
        if not path.is_absolute():
            path = root / path
        resolved = _canonical(path)
    except OSError:
        raise SafetyError("path_unresolvable") from None
    if not resolved.is_relative_to(root) or (resolved == root and not allow_root):
        raise SafetyError("path_outside_scratch")
    if directory and not resolved.is_dir():
        raise SafetyError("path_not_directory")
    return resolved


def _walk_confined(directory, root):
    # Do not follow links: validate their final destination, including directory links.
    for current, directories, files in os.walk(directory, followlinks=False):
        for name in (*directories, *files):
            _path(Path(current) / name, root, allow_root=True)


def _labels(labels, project):
    if labels is not None and not isinstance(labels, dict):
        raise SafetyError("labels_not_normalized")
    result = dict(labels or {})
    if any(key.startswith("com.docker.compose.") for key in result):
        raise SafetyError("reserved_compose_label")
    result[OWNER_LABEL] = project
    return result


def _resource_name(project, kind, key):
    if not isinstance(key, str) or not RESOURCE_KEY.fullmatch(key):
        raise SafetyError("invalid_resource_identifier")
    return f"{project}_{kind}_{key}"


def _new_volume(config, project, service, target):
    key = "corpus_" + hashlib.sha256(f"{service}:{target}".encode()).hexdigest()[:24]
    if key in config.setdefault("volumes", {}):
        raise SafetyError("generated_volume_collision")
    config["volumes"][key] = {
        "name": _resource_name(project, "volume", key),
        "labels": {OWNER_LABEL: project},
    }
    return key


def _environment_hosts(config):
    internal = {"localhost", "host.docker.internal", "gateway.docker.internal"}
    # Host gateway names are deliberately excluded below; they refer outside the fixture.
    internal -= {"host.docker.internal", "gateway.docker.internal"}
    for name, service in config["services"].items():
        internal.add(name.lower())
        if service.get("hostname"):
            internal.add(str(service["hostname"]).lower())
        for network in (service.get("networks") or {}).values():
            internal.update(str(alias).lower() for alias in (network or {}).get("aliases", []))
    found = []
    for name, service in config["services"].items():
        env = service.get("environment") or {}
        if not isinstance(env, dict):
            raise SafetyError("environment_not_normalized")
        for key, value in env.items():
            if value is None:
                raise SafetyError("environment_not_resolved")
            value = str(value)
            if "${" in value:
                raise SafetyError("interpolation_not_resolved")
            if (key.upper() == "PORT" or key.upper().endswith("_PORT")) and value.isdecimal():
                continue
            hosts = []
            # Capture URLs even inside JSON/list-valued environment settings.
            for match in re.finditer(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+", value):
                try:
                    host = urlsplit(match.group()).hostname
                except ValueError:
                    raise SafetyError("endpoint_invalid") from None
                if host:
                    hosts.append(host)
            if re.search(
                r"(?:^|_)(?:HOST|HOSTNAME|SERVER|ENDPOINT|ADDRESS|URL|URI)(?:$|_)", key.upper()
            ):
                if not hosts and re.fullmatch(r"[a-zA-Z0-9_.-]+(?::\d+)?", value):
                    hosts.append(value.split(":")[0])
            for host in hosts:
                host = host.lower().rstrip(".")
                try:
                    loopback = ipaddress.ip_address(host).is_loopback
                except ValueError:
                    loopback = False
                if host not in internal and not loopback:
                    found.append({"service": name, "key": key, "host": host})
    return found


def prepare_config(config, project, root, *, writable_paths=None, approved_external_endpoints=None):
    """Copy normalized input, refuse unsafe features, replace every global resource name."""
    if not PROJECT_KEY.fullmatch(project):
        raise SafetyError("project_not_fresh_uuid")
    root = _canonical(root)
    if not root.is_dir() or not isinstance(config, dict) or not config.get("services"):
        raise SafetyError("configuration_invalid")
    config = copy.deepcopy(config)
    if any(config.get(key) for key in ("include", "extends")):
        raise SafetyError("configuration_not_resolved")
    config["name"] = project
    writable = {}
    for path, reason in (writable_paths or {}).items():
        if not isinstance(reason, str) or not reason.strip():
            raise SafetyError("writable_path_reason_missing")
        writable[str(_path(path, root))] = reason
    for category, kind in (
        ("networks", "network"),
        ("volumes", "volume"),
        ("configs", "config"),
        ("secrets", "secret"),
    ):
        for key, attributes in config.setdefault(category, {}).items():
            attributes = attributes or {}
            if not isinstance(attributes, dict) or attributes.get("external"):
                raise SafetyError("external_resource")
            if category in {"networks", "volumes"}:
                if attributes.get("driver") not in (
                    None,
                    "bridge" if category == "networks" else "local",
                ):
                    raise SafetyError("unsafe_resource_driver")
                if attributes.get("driver_opts") or attributes.get("ipam"):
                    raise SafetyError("unsafe_resource_driver_options")
                attributes["labels"] = _labels(attributes.get("labels"), project)
            else:
                if (
                    not attributes.get("file")
                    or attributes.get("environment")
                    or attributes.get("content")
                ):
                    raise SafetyError("file_resource_required")
                resource_path = _path(attributes["file"], root)
                if not resource_path.is_file():
                    raise SafetyError("file_resource_not_regular")
                attributes["file"] = str(resource_path)
            attributes.pop("external", None)
            attributes["name"] = _resource_name(project, kind, key)
            config[category][key] = attributes
    for name, service in config["services"].items():
        _resource_name(project, "service", name)
        if not isinstance(service, dict):
            raise SafetyError("service_invalid")
        for key in (
            "privileged",
            "devices",
            "device_cgroup_rules",
            "cap_add",
            "volumes_from",
            "external_links",
            "links",
            "extra_hosts",
            "use_api_socket",
            "develop",
            "provider",
            "post_start",
            "pre_start",
            "pre_stop",
            "credential_spec",
        ):
            if service.get(key):
                raise SafetyError("unsafe_service_option")
        if service.get("gpus") or (service.get("deploy") or {}).get("resources", {}).get(
            "reservations", {}
        ).get("devices"):
            raise SafetyError("unsafe_service_device")
        for key in ("pid", "ipc", "uts", "userns_mode"):
            if service.get(key) and service[key] not in {"private", "shareable"}:
                raise SafetyError("unsafe_host_namespace")
        mode = service.get("network_mode")
        if (
            mode
            and mode != "none"
            and not (
                isinstance(mode, str)
                and mode.startswith("service:")
                and mode[8:] in config["services"]
            )
        ):
            raise SafetyError("unsafe_network_mode")
        if service.get("env_file") or service.get("extends"):
            raise SafetyError("configuration_not_resolved")
        service.pop("container_name", None)
        service.pop("profiles", None)
        service["labels"] = _labels(service.get("labels"), project)
        for port in service.get("ports", []):
            if not isinstance(port, dict) or port.get("protocol", "tcp") not in {"tcp", "udp"}:
                raise SafetyError("ports_not_normalized")
            try:
                target = int(port["target"])
            except (KeyError, ValueError, TypeError):
                raise SafetyError("port_invalid") from None
            if not 1 <= target <= 65535:
                raise SafetyError("port_invalid")
            port.update(published="0", host_ip="127.0.0.1")
        networks = service.get("networks")
        if networks is None and not mode:
            service["networks"] = {"default": None}
            if "default" not in config["networks"]:
                config["networks"]["default"] = {
                    "name": _resource_name(project, "network", "default"),
                    "labels": {OWNER_LABEL: project},
                }
        elif networks is not None:
            if not isinstance(networks, dict) or any(
                key not in config["networks"] for key in networks
            ):
                raise SafetyError("network_reference_not_normalized")
            if any(
                (value or {}).get(key)
                for value in networks.values()
                for key in ("ipv4_address", "ipv6_address", "mac_address")
            ):
                raise SafetyError("fixed_network_address")
        for mount in service.setdefault("volumes", []):
            if not isinstance(mount, dict):
                raise SafetyError("mount_not_normalized")
            target = mount.get("target", "")
            if (
                not isinstance(target, str)
                or not target.startswith("/")
                or re.search(
                    r"docker[.]sock|docker_engine|containerd[.]sock|podman[.]sock", target, re.I
                )
            ):
                raise SafetyError("unsafe_mount_target")
            mount_kind = mount.get("type")
            if mount_kind == "bind":
                source = _path(mount.get("source", ""), root, allow_root=True)
                _walk_confined(source, root) if source.is_dir() else None
                if re.search(
                    r"docker[.]sock|docker_engine|containerd[.]sock|podman[.]sock",
                    str(source),
                    re.I,
                ):
                    raise SafetyError("host_socket_forbidden")
                mount.update(source=str(source), read_only=str(source) not in writable)
                if (mount.get("bind") or {}).get("propagation") not in (None, "rprivate"):
                    raise SafetyError("bind_propagation_forbidden")
                mount["bind"] = {"create_host_path": False}
            elif mount_kind == "volume":
                if (mount.get("volume") or {}).get("subpath"):
                    raise SafetyError("volume_subpath_unsupported")
                if not mount.get("source"):
                    mount["source"] = _new_volume(config, project, name, target)
                if mount["source"] not in config["volumes"]:
                    raise SafetyError("unknown_volume_source")
            elif mount_kind != "tmpfs":
                raise SafetyError("unsafe_mount_type")
        build = service.get("build")
        if build:
            if not isinstance(build, dict) or not build.get("context"):
                raise SafetyError("build_not_normalized")
            for key in (
                "ssh",
                "secrets",
                "entitlements",
                "privileged",
                "dockerfile_inline",
                "additional_contexts",
                "cache_from",
                "cache_to",
            ):
                if build.get(key):
                    raise SafetyError("unsafe_build_option")
            if build.get("network") not in (None, "none"):
                raise SafetyError("unsafe_build_network")
            context = _path(build["context"], root, directory=True, allow_root=True)
            _walk_confined(context, root)
            dockerfile = _path(context / build.get("dockerfile", "Dockerfile"), root)
            if not dockerfile.is_file():
                raise SafetyError("dockerfile_not_regular")
            build.update(context=str(context), dockerfile=str(dockerfile))
            service["image"] = project + "-build-" + name.lower()
        if not service.get("image"):
            raise SafetyError("service_image_missing")
        # Compose must never pull implicitly during up, including :latest tags.
        service["pull_policy"] = "never"
    approved = {str(host).lower().rstrip(".") for host in approved_external_endpoints or []}
    if any(endpoint["host"] not in approved for endpoint in _environment_hosts(config)):
        raise SafetyError("external_endpoint_requires_review")
    return config


def validate_isolation(
    config, project, root, *, writable_paths=None, approved_external_endpoints=None
):
    """Recheck a prepared configuration immediately before a mutating Compose call."""
    if config.get("name") != project or not PROJECT_KEY.fullmatch(project):
        raise SafetyError("project_identity_changed")
    rechecked = prepare_config(
        config,
        project,
        root,
        writable_paths=writable_paths,
        approved_external_endpoints=approved_external_endpoints,
    )
    if rechecked != config:
        raise SafetyError("prepared_configuration_changed")
    for category, kind in (
        ("networks", "network"),
        ("volumes", "volume"),
        ("configs", "config"),
        ("secrets", "secret"),
    ):
        for key, value in config.get(category, {}).items():
            if value.get("external") or value.get("name") != _resource_name(project, kind, key):
                raise SafetyError("resource_identity_changed")
            if (
                category in {"networks", "volumes"}
                and value.get("labels", {}).get(OWNER_LABEL) != project
            ):
                raise SafetyError("resource_owner_changed")
            if value.get("file"):
                _path(value["file"], root)
    for service in config["services"].values():
        if service.get("labels", {}).get(OWNER_LABEL) != project or service.get("container_name"):
            raise SafetyError("service_owner_changed")
        for port in service.get("ports", []):
            if str(port.get("published")) != "0" or port.get("host_ip") != "127.0.0.1":
                raise SafetyError("host_port_not_ephemeral_loopback")
        for mount in service.get("volumes", []):
            if mount.get("type") == "bind":
                path = _path(mount["source"], root, allow_root=True)
                if path.is_dir():
                    _walk_confined(path, root)
            if mount.get("type") == "volume" and mount.get("source") not in config["volumes"]:
                raise SafetyError("volume_mount_not_owned")
        if service.get("build"):
            _walk_confined(
                _path(service["build"]["context"], root, directory=True, allow_root=True), root
            )
    return {
        "isolated": True,
        "project": project,
        "volume_names": sorted(v["name"] for v in config.get("volumes", {}).values()),
        "network_names": sorted(v["name"] for v in config.get("networks", {}).values()),
    }


def freeze_images(config, project, api):
    """Pin inspected image IDs and name every implicit image volume before up."""
    result = []
    for name, service in config["services"].items():
        image_reference = service["image"]
        image = api.inspect_image(service["image"])
        image_id = image.get("Id", "")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise SafetyError("image_identity_invalid")
        mounts = service.setdefault("volumes", [])
        targets = {mount["target"] for mount in mounts}
        for target in sorted((image.get("Config") or {}).get("Volumes") or {}):
            if target not in targets:
                if not target.startswith("/") or "docker.sock" in target:
                    raise SafetyError("image_volume_target_invalid")
                mounts.append(
                    {
                        "type": "volume",
                        "source": _new_volume(config, project, name, target),
                        "target": target,
                    }
                )
        service["image"] = image_id
        service.pop("build", None)
        result.append(
            {
                "service": name,
                "requested_reference": image_reference,
                "image_id": image_id,
                "repo_digests": image.get("RepoDigests") or [],
                "repo_tags": image.get("RepoTags") or [],
                "declared_volume_targets": sorted((image.get("Config") or {}).get("Volumes") or {}),
            }
        )
    return result


def snapshot_resources(api, project):
    filters = {"label": [f"{PROJECT_LABEL}={project}"]}
    return {
        "containers": sorted(c["Id"] for c in api.containers(all=True, filters=filters)),
        "networks": sorted(n["Id"] for n in api.networks(filters=filters)),
        "volumes": {v["Name"]: v for v in api.volumes(filters=filters).get("Volumes") or []},
        "helpers": sorted(
            c["Id"]
            for c in api.containers(
                all=True,
                filters={"label": [f"io.dockroute.project={project}", "io.dockroute.helper=true"]},
            )
        ),
    }


def inspect_owned_mounts(api, config, project):
    """Inspect actual mounts and refuse anonymous/foreign volumes before diagnostic exec."""
    result = []
    for summary in api.containers(all=True, filters={"label": [f"{PROJECT_LABEL}={project}"]}):
        attrs = api.inspect_container(summary["Id"])
        labels = (attrs.get("Config") or {}).get("Labels") or {}
        name = labels.get("com.docker.compose.service")
        if (
            labels.get(OWNER_LABEL) != project
            or labels.get(PROJECT_LABEL) != project
            or name not in config["services"]
        ):
            raise SafetyError("runtime_container_not_owned")
        service = config["services"][name]
        expected = {mount["target"]: mount for mount in service.get("volumes", [])}
        # File-based Compose secrets/configs are explicit read-only bind mounts.
        for category in ("secrets", "configs"):
            for reference in service.get(category, []):
                reference = {"source": reference} if isinstance(reference, str) else reference
                source = reference["source"]
                target = reference.get("target") or (
                    ("/run/secrets/" if category == "secrets" else "/") + source
                )
                if not target.startswith("/"):
                    target = ("/run/secrets/" if category == "secrets" else "/") + target
                expected[target] = {"type": "bind", "read_only": True}
        mounts = []
        seen = set()
        for mount in attrs.get("Mounts", []):
            target = mount.get("Destination")
            intent = expected.get(target)
            if intent is None or mount.get("Type") != intent.get("type"):
                raise SafetyError("runtime_mount_not_declared")
            seen.add(target)
            record = {
                "target": target,
                "type": mount["Type"],
                "read_only": not mount.get("RW", False),
            }
            if mount["Type"] == "volume":
                actual_name = mount.get("Name")
                wanted = config["volumes"][intent["source"]]["name"]
                if actual_name != wanted:
                    raise SafetyError("runtime_volume_not_owned")
                actual = api.inspect_volume(actual_name)
                if (actual.get("Labels") or {}).get(OWNER_LABEL) != project or (
                    actual.get("Labels") or {}
                ).get(PROJECT_LABEL) != project:
                    raise SafetyError("runtime_volume_owner_mismatch")
                record["volume_name"] = actual_name
            if intent.get("read_only") and mount.get("RW"):
                raise SafetyError("runtime_readonly_mount_writable")
            mounts.append(record)
        if any(
            mount.get("type") == "volume" and target not in seen
            for target, mount in expected.items()
        ):
            raise SafetyError("runtime_owned_volume_missing")
        result.append(
            {
                "id": attrs["Id"],
                "service": name,
                "image_id": attrs.get("Image"),
                "state": (attrs.get("State") or {}).get("Status"),
                "health": ((attrs.get("State") or {}).get("Health") or {}).get("Status"),
                "mounts": mounts,
            }
        )
    return result


def _empty_before(api, config, project):
    before = snapshot_resources(api, project)
    if any(before.values()):
        raise SafetyError("fresh_project_collision")
    for category, method in (("volumes", api.inspect_volume), ("networks", api.inspect_network)):
        for value in config.get(category, {}).values():
            try:
                method(value["name"])
            except NotFound:
                continue
            raise SafetyError("fresh_resource_name_collision")
    return before


def _volume_identity(value):
    # Docker's local volume API has no independent ID: Name plus creation metadata
    # and ownership labels is the exact observable identity; keep it in the lease.
    created = value.get("CreatedAt")
    if not isinstance(created, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.]\d+)?(?:Z|[+-]\d{2}:\d{2})", created
    ):
        raise SafetyError("volume_creation_identity_missing")
    try:
        datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        raise SafetyError("volume_creation_identity_invalid") from None
    if not value.get("Mountpoint") or value.get("Scope") != "local":
        raise SafetyError("volume_creation_identity_missing")
    return {
        key: value.get(key)
        for key in ("Name", "CreatedAt", "Driver", "Scope", "Mountpoint", "Labels", "Options")
    }


def cleanup_owned_volumes(api, config, project, before, *, created=None):
    """Prevalidate all intents, then remove individually without force or global prune."""
    result: dict[str, Any] = {
        "cleanup": "failed",
        "removed_volume_names": [],
        "volume_identities": {},
    }
    intents = {value["name"]: value for value in config.get("volumes", {}).values()}
    present = []
    try:
        for name, intent in intents.items():
            if (
                name in before
                or not name.startswith(project + "_volume_")
                or intent.get("labels", {}).get(OWNER_LABEL) != project
            ):
                return result
            try:
                attrs = api.inspect_volume(name)
            except NotFound:
                continue
            labels = attrs.get("Labels") or {}
            if (
                attrs.get("Name") != name
                or labels.get(OWNER_LABEL) != project
                or labels.get(PROJECT_LABEL) != project
                or attrs.get("Driver") != "local"
                or attrs.get("Options")
            ):
                return result
            identity = _volume_identity(attrs)
            if created is not None and (
                name not in created or identity != _volume_identity(created[name])
            ):
                return result
            result["volume_identities"][name] = identity
            present.append(name)
        for name in present:
            # Reinspect just before mutation: refuse if the object changed since validation.
            if _volume_identity(api.inspect_volume(name)) != result["volume_identities"][name]:
                return result
            api.remove_volume(name, force=False)
            result["removed_volume_names"].append(name)
        for name in intents:
            try:
                api.inspect_volume(name)
            except NotFound:
                continue
            return result
        result["cleanup"] = "complete"
    except ERRORS:
        pass
    return result


def _environment():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    for key in (
        "DOCKROUTE_HELPER_CPUS",
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_PROFILES",
        "COMPOSE_ENV_FILES",
    ):
        env.pop(key, None)
    env["COMPOSE_DISABLE_ENV_FILE"] = "1"
    return env


class _ProcessTree:
    """Kernel-owned command tree; Windows child cannot run before job assignment."""

    def __init__(self):
        self.job: Any = None
        self.child: subprocess.Popen[Any] | None = None
        self.win32job: Any = None
        self.winerrors: tuple[type[BaseException], ...] = (OSError,)
        if sys.platform == "win32":
            import pywintypes
            import win32api
            import win32job

            self.win32job = win32job
            self.winerrors = (OSError, pywintypes.error)
            try:
                self.job = win32job.CreateJobObject(
                    None, "dockroute-corpus-command-" + uuid.uuid4().hex
                )
                if win32api.GetLastError() == 183:
                    self.job.Close()
                    self.job = None
                    raise OSError("owned job collision")
                limits = win32job.QueryInformationJobObject(
                    self.job, win32job.JobObjectExtendedLimitInformation
                )
                limits["BasicLimitInformation"]["LimitFlags"] |= (
                    win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                )
                win32job.SetInformationJobObject(
                    self.job, win32job.JobObjectExtendedLimitInformation, limits
                )
            except self.winerrors:
                if self.job is not None:
                    self.job.Close()
                    self.job = None
                raise OSError("owned command job could not be created") from None

    def spawn(self, argv, **kwargs):
        options = (
            {
                "creationflags": getattr(subprocess, "CREATE_SUSPENDED", 4)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            }
            if self.job is not None
            else {"start_new_session": True}
        )
        self.child = subprocess.Popen(argv, **kwargs, **options)
        if self.job is not None:
            import ctypes

            try:
                owned_handle = getattr(self.child, "_handle")
                self.win32job.AssignProcessToJobObject(self.job, owned_handle)
                resume = getattr(ctypes, "WinDLL")("ntdll").NtResumeProcess
                resume.argtypes = [ctypes.c_void_p]
                resume.restype = ctypes.c_long
                if resume(int(owned_handle)) != 0:
                    raise OSError("owned child resume failed")
            except Exception:
                # Still suspended: no plugin/descendant could have been launched.
                self.child.kill()
                self.child.wait(timeout=5)
                raise OSError("owned child job assignment or resume failed") from None
            except BaseException:
                self.child.kill()
                self.child.wait(timeout=5)
                raise
        return self.child

    def active(self):
        if self.job is not None:
            try:
                return (
                    self.win32job.QueryInformationJobObject(
                        self.job, self.win32job.JobObjectBasicAccountingInformation
                    )["ActiveProcesses"]
                    != 0
                )
            except self.winerrors:
                raise OSError("owned job state unavailable") from None
        if self.child is None:
            return False
        try:
            os.killpg(self.child.pid, 0)
            return True
        except ProcessLookupError:
            return False

    def terminate(self):
        if self.job is not None:
            try:
                self.win32job.TerminateJobObject(self.job, 1)
            except self.winerrors:
                raise OSError("owned job termination failed") from None
        elif self.child is not None and self.active():
            os.killpg(self.child.pid, signal.SIGKILL)

    def confirm_exited(self, *, timeout=5):
        if self.child is not None:
            try:
                self.child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                return False
        deadline = time.monotonic() + timeout
        while self.active():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)
        return True

    def close(self):
        if self.job is not None:
            self.job.Close()
            self.job = None


def _command(argv, *, timeout, cwd, log_directory, env=None):
    directory = Path(log_directory)
    directory.mkdir(parents=True, exist_ok=True)
    number = uuid.uuid4().hex
    output = directory / (number + ".stdout")
    error = directory / (number + ".stderr")
    began = time.perf_counter()
    result: dict[str, Any] = {
        "command": list(argv),
        "stdout_path": str(output),
        "stderr_path": str(error),
    }
    tree = None
    with output.open("wb") as out, error.open("wb") as err:
        try:
            tree = _ProcessTree()
            child = tree.spawn(
                argv,
                cwd=cwd,
                env=env or _environment(),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
            )
            deadline = time.monotonic() + timeout
            result["timed_out"] = False
            while child.poll() is None:
                if (
                    output.stat().st_size > 16 * 1024 * 1024
                    or error.stat().st_size > 16 * 1024 * 1024
                ):
                    result.update(exit_code=None, error="command_log_limit")
                    break
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(argv, timeout)
                time.sleep(0.05)
            else:
                result["exit_code"] = child.returncode
        except subprocess.TimeoutExpired:
            result.update(exit_code=None, timed_out=True, error="command_timeout")
        except (OSError, KeyboardInterrupt):
            result.update(exit_code=None, timed_out=False, error="command_failed_or_cancelled")
        finally:
            if tree is not None:
                try:
                    if not tree.confirm_exited(timeout=0.5):
                        if not result.get("timed_out") and result.get("exit_code") == 0:
                            result.update(exit_code=None, error="command_descendant_active")
                        tree.terminate()
                    result["process_tree_exited"] = tree.confirm_exited()
                    if tree.child is not None:
                        result["exit_code"] = tree.child.returncode
                except (OSError, subprocess.TimeoutExpired):
                    result["process_tree_exited"] = False
                finally:
                    tree.close()
            else:
                result["process_tree_exited"] = True
            if not result["process_tree_exited"]:
                result.update(error="command_process_tree_uncertain", exit_code=None)
    for path in (output, error):
        if path.stat().st_size > 16 * 1024 * 1024:
            with path.open("r+b") as handle:
                handle.truncate(16 * 1024 * 1024)
            result.update(logs_truncated=True)
            result.setdefault("error", "command_log_limit")
    result["wall_ms"] = (time.perf_counter() - began) * 1000
    return result


def _helper_recovery(inspector, control, project, *, hard_killed=False, allow_missing=False):
    spec = importlib.util.spec_from_file_location(
        "corpus_helper_recovery", ROOT / "scripts" / "benchmark_latency.py"
    )
    if spec is None or spec.loader is None:
        raise SafetyError("helper_recovery_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.recover_leased_helpers(
        inspector, control, project, hard_killed=hard_killed, allow_missing=allow_missing
    )


def _source_state():
    """Fingerprint checkout code and the exact text bytes embedded in probe helpers."""
    files = sorted(SOURCE_DIRECTORY.rglob("*.py"))
    if not files:
        raise OSError("product source is unavailable")
    worker = SOURCE_DIRECTORY / "_probe_worker.py"
    return {
        "source_root": str(SOURCE_DIRECTORY),
        "product_source_sha256": {
            path.relative_to(SOURCE_DIRECTORY).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in files
        },
        # Prober uses read_text(encoding='utf-8') followed by program.encode().
        "helper_worker_sha256": hashlib.sha256(
            worker.read_text(encoding="utf-8").encode()
        ).hexdigest(),
        "python_version": sys.version,
        "docker_sdk_version": version("docker"),
    }


def run_diagnostic(
    inspector, project, control, *, probe=False, source=None, target=None, timeout=180, command=None
):
    """Capture full JSON while cooperatively cancelling/reaping only this child."""
    control = Path(control)
    control.mkdir(parents=True, exist_ok=True)
    if any(control.iterdir()):
        raise SafetyError("control_directory_not_empty")
    argv = command or [sys.executable, "-m", "dockroute", "check" if source else "doctor"]
    if command is None:
        if source:
            argv.extend([source, target])
        argv.extend(["--project", project, "--format", "json", "--timing"])
        if probe:
            argv.extend(["--probe", "--_benchmark-control", str(control)])
    result: dict[str, Any] = {
        "report": None,
        "exit_code": None,
        "cleanup": "not_needed",
        "command": list(argv),
        "stdout_path": str(control / "child.stdout"),
        "stderr_path": str(control / "child.stderr"),
        "source": {"before": None, "after": None, "stable": False},
    }
    began = time.perf_counter()
    child = None
    tree = None
    stdout, stderr = "", ""
    hard_killed = False
    try:
        tree = _ProcessTree()
        try:
            result["source"]["before"] = _source_state()
        except ERRORS:
            result["error"] = "source_fingerprint_unavailable"
            raise
        child = tree.spawn(
            argv,
            cwd=ROOT,
            env=_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as event:
            result.update(
                cancellation_requested=True,
                error="cancelled" if isinstance(event, KeyboardInterrupt) else "child_timeout",
            )
            if probe:
                (control / "cancel").write_text("cancel\n", encoding="utf-8")
            try:
                stdout, stderr = child.communicate(timeout=25 if probe else 5)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                tree.terminate()
                hard_killed = True
                result["child_killed"] = True
                try:
                    stdout, stderr = child.communicate(timeout=5)
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    result["child_exit_unconfirmed"] = True
        result["exit_code"] = child.returncode
        if stdout:
            parsed = json.loads(stdout)
            if not isinstance(parsed, dict):
                raise ValueError("report must be an object")
            result["report"] = parsed
        else:
            result.setdefault("error", "child_report_missing")
    except ERRORS:
        result.setdefault("error", "child_command_or_report_failed")
    finally:
        if child is not None and child.returncode is None:
            if probe:
                try:
                    (control / "cancel").write_text("cancel\n", encoding="utf-8")
                except OSError:
                    result["cancel_channel_failed"] = True
            try:
                stdout, stderr = child.communicate(timeout=25 if probe else 5)
            except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
                assert tree is not None
                tree.terminate()
                hard_killed = True
                try:
                    stdout, stderr = child.communicate(timeout=5)
                except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt):
                    result["child_exit_unconfirmed"] = True
        if tree is not None:
            try:
                if not tree.confirm_exited(timeout=0.5):
                    tree.terminate()
                    hard_killed = True
                result["process_tree_exited"] = tree.confirm_exited()
            except (OSError, subprocess.TimeoutExpired):
                result["process_tree_exited"] = False
            finally:
                tree.close()
        else:
            result["process_tree_exited"] = True
        if not result["process_tree_exited"]:
            result.setdefault("error", "diagnostic_process_tree_uncertain")
        try:
            (control / "child.stdout").write_text(stdout, encoding="utf-8")
            (control / "child.stderr").write_text(stderr, encoding="utf-8")
        except OSError:
            result.setdefault("error", "private_log_write_failed")
        if child is not None:
            result["exit_code"] = child.returncode
        if probe:
            if not result["process_tree_exited"] or (
                child is not None and child.returncode is None
            ):
                result["cleanup"] = "uncertain"
            else:
                recovery = _helper_recovery(
                    inspector,
                    control,
                    project,
                    hard_killed=hard_killed,
                    allow_missing=result["report"] is None
                    or bool(result.get("error"))
                    or bool((result["report"] or {}).get("error")),
                )
                result.update(recovery)
        try:
            result["source"]["after"] = _source_state()
            result["source"]["stable"] = (
                result["source"]["before"] is not None
                and result["source"]["before"] == result["source"]["after"]
            )
            if result["source"]["before"] is not None and not result["source"]["stable"]:
                if result.get("error"):
                    result["prior_error"] = result["error"]
                result["error"] = "source_changed_during_diagnostic"
        except ERRORS:
            if result.get("error"):
                result["prior_error"] = result["error"]
            result["error"] = "source_fingerprint_unavailable"
        result["source"]["dockroute_version"] = (result["report"] or {}).get("dockroute_version")
        result["valid_for_grading"] = bool(
            result["source"]["stable"]
            and result["report"] is not None
            and not result.get("error")
            and not (result["report"] or {}).get("error")
            and result["cleanup"] in {"complete", "not_needed"}
            and result["process_tree_exited"]
        )
        result["wall_ms"] = (time.perf_counter() - began) * 1000
    return result


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _incoming_port(api, project, service, port):
    containers = api.containers(
        all=True,
        filters={"label": [f"{PROJECT_LABEL}={project}", f"com.docker.compose.service={service}"]},
    )
    if len(containers) != 1:
        raise SafetyError("incoming_service_missing_or_ambiguous")
    attrs = api.inspect_container(containers[0]["Id"])
    labels = (attrs.get("Config") or {}).get("Labels") or {}
    if labels.get(OWNER_LABEL) != project or labels.get(PROJECT_LABEL) != project:
        raise SafetyError("incoming_service_not_owned")
    bindings = ((attrs.get("NetworkSettings") or {}).get("Ports") or {}).get(f"{port}/tcp") or []
    if len(bindings) != 1 or bindings[0].get("HostIp") != "127.0.0.1":
        raise SafetyError("incoming_port_not_loopback")
    mapped = int(bindings[0]["HostPort"])
    if not 1 <= mapped <= 65535:
        raise SafetyError("incoming_port_invalid")
    return mapped


def check_http(api, project, recipe, *, timeout=240):
    """Bounded localhost check with redirects and inherited proxies disabled."""
    path = recipe.get("health_path", "/")
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or path.startswith("//")
        or any(x in path for x in ("\r", "\n", "#"))
    ):
        raise SafetyError("health_path_invalid")
    statuses = recipe.get("expected_statuses", [200])
    if (
        not isinstance(statuses, list)
        or not statuses
        or any(not isinstance(x, int) or not 100 <= x <= 599 for x in statuses)
    ):
        raise SafetyError("expected_statuses_invalid")
    pattern = (
        re.compile(recipe["expected_body_pattern"]) if recipe.get("expected_body_pattern") else None
    )
    deadline = time.monotonic() + min(240, max(0, timeout))
    result: dict[str, Any] = {"ready": False, "attempts": 0, "error": "http_unavailable"}
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    while True:
        result["attempts"] += 1
        try:
            mapped = _incoming_port(
                api, project, recipe["incoming_service"], int(recipe["incoming_port"])
            )
            remaining = max(0.05, deadline - time.monotonic())
            try:
                response = opener.open(
                    f"http://127.0.0.1:{mapped}{path}", timeout=min(3, remaining)
                )
            except HTTPError as event:
                response = event
            with response:
                body = response.read(1024 * 1024).decode("utf-8", errors="replace")
                status = response.code
            result.update(
                host="127.0.0.1",
                mapped_port=mapped,
                http_status=status,
                body_sha256=hashlib.sha256(body.encode()).hexdigest(),
                body_pattern_matched=bool(pattern.search(body)) if pattern else None,
            )
            if status in statuses and (pattern is None or pattern.search(body)):
                result.update(ready=True, error=None)
                return result
            result["error"] = "http_expectation_failed"
        except (SafetyError, URLError, OSError, DockerException, ValueError):
            pass
        if time.monotonic() >= deadline:
            return result
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def _write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _runtime_metadata(api):
    from dockroute import __version__

    result: dict[str, Any] = {
        "python": sys.version,
        "docker_sdk": version("docker"),
        "dockroute": __version__,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "case_start_source_scope": "Before build/pull; diagnostic.source fingerprints are authoritative for each child invocation.",
        "case_start_source_sha256": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((ROOT / "src" / "dockroute").glob("*.py"))
        },
    }
    if hasattr(api, "version"):
        result["engine"] = api.version()
        for key, command in (
            ("compose", ["docker", "compose", "version", "--short"]),
            ("repository_revision", ["git", "rev-parse", "HEAD"]),
        ):
            try:
                child = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=_environment(),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                result[key] = child.stdout.strip() if child.returncode == 0 else "unavailable"
            except (OSError, subprocess.TimeoutExpired):
                result[key] = "unavailable"
    return result


def _guard_down(api, project, config, *, captured):
    if captured is None:
        raise SafetyError("created_resource_ids_unknown")
    for container in api.containers(all=True, filters={"label": [f"{PROJECT_LABEL}={project}"]}):
        labels = container.get("Labels") or {}
        if (
            labels.get(OWNER_LABEL) != project
            or container["Id"] not in captured["containers"]
            or labels.get("com.docker.compose.service") not in config["services"]
        ):
            raise SafetyError("cleanup_container_owner_mismatch")
    names = {value["name"] for value in config.get("networks", {}).values()}
    for network in api.networks(filters={"label": [f"{PROJECT_LABEL}={project}"]}):
        if (
            network.get("Name") not in names
            or network["Id"] not in captured["networks"]
            or (network.get("Labels") or {}).get(OWNER_LABEL) != project
        ):
            raise SafetyError("cleanup_network_owner_mismatch")


def run_case(recipe, *, allow_build=False, allow_pull=False, inspector=None):
    """Execute one fresh case; always return failures, raw reports, and cleanup evidence."""
    project = "dockroute-corpus-" + uuid.uuid4().hex
    private = ROOT / "work" / "corpus-live" / project
    private.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {
        "schema_version": "corpus-live-1",
        "id": recipe.get("id"),
        "project": project,
        "status": "refused",
        "private_directory": str(private),
        "annotations": recipe.get("annotations", []),
        "automatic": {},
        "manual_checks": [],
        "safety": {"allow_build": allow_build, "allow_pull": allow_pull, "trace": []},
        "cleanup": {"cleanup": "not_needed"},
        "provenance": {
            key: recipe[key]
            for key in ("upstream", "revision", "source_compose_sha256")
            if key in recipe
        },
    }
    own_inspector = inspector is None
    api, config, base = None, None, None
    up_attempted, uncertain_mutation = False, False
    before: dict[str, Any] = {"volumes": {}}
    created = None
    captured_resources = None
    try:
        root = _canonical(recipe["root"])
        compose = _path(recipe["compose_file"], root)
        review = {
            "writable_paths": recipe.get("writable_paths"),
            "approved_external_endpoints": recipe.get("approved_external_endpoints"),
        }
        config = prepare_config(
            json.loads(compose.read_text(encoding="utf-8")),
            project,
            root,
            writable_paths=recipe.get("writable_paths"),
            approved_external_endpoints=recipe.get("approved_external_endpoints"),
        )
        service = recipe["incoming_service"]
        incoming = int(recipe["incoming_port"])
        if service not in config["services"] or not 1 <= incoming <= 65535:
            raise SafetyError("incoming_service_or_port_invalid")
        from dockroute.endpoints import parse_endpoint

        for check in recipe.get("checks", []):
            target = check.get("target")
            if (
                check.get("source") not in config["services"]
                or not isinstance(target, str)
                or any(value in target for value in ("/", "@", "?", "#"))
                or not parse_endpoint(target)
            ):
                raise SafetyError("manual_check_invalid")
        if not any(
            int(port["target"]) == incoming and port.get("protocol", "tcp") == "tcp"
            for port in config["services"][service].get("ports", [])
        ):
            config["services"][service].setdefault("ports", []).append(
                {"target": incoming, "protocol": "tcp", "published": "0", "host_ip": "127.0.0.1"}
            )
        report["safety"]["external_endpoints_reviewed"] = _environment_hosts(config)
        report["safety"]["writable_paths"] = recipe.get("writable_paths", {})
        if inspector is None:
            inspector = connect(timeout=5)
        api = inspector.client.api
        report["runtime"] = _runtime_metadata(api)
        before = _empty_before(api, config, project)
        report["safety"]["before"] = before
        report["safety"]["trace"].append("fresh_project_and_resource_names_verified_empty")
        frozen = private / "frozen-compose.json"
        _write_json(frozen, config)
        base = [
            "docker",
            "compose",
            "--project-directory",
            str(root),
            "-p",
            project,
            "-f",
            str(frozen),
        ]
        builders = [name for name, svc in config["services"].items() if svc.get("build")]
        if builders and not allow_build:
            raise SafetyError("build_not_allowed")
        if builders:
            # Build may fetch missing base images; permission for both is required.
            if not allow_pull:
                raise SafetyError("build_base_pull_not_allowed")
            validate_isolation(config, project, root, **review)
            outcome = _command(
                [*base, "build", *builders], timeout=600, cwd=root, log_directory=private
            )
            report["safety"]["build"] = outcome
            if outcome.get("timed_out") or outcome.get("error") or outcome.get("exit_code") != 0:
                raise SafetyError("build_failed")
        for name, svc in config["services"].items():
            try:
                api.inspect_image(svc["image"])
            except NotFound:
                if not allow_pull:
                    raise SafetyError("image_missing_pull_not_allowed") from None
                outcome = _command(
                    ["docker", "pull", svc["image"]], timeout=600, cwd=root, log_directory=private
                )
                report["safety"].setdefault("pulls", []).append({"service": name, **outcome})
                if (
                    outcome.get("timed_out")
                    or outcome.get("error")
                    or outcome.get("exit_code") != 0
                ):
                    raise SafetyError("pull_failed")
        report["safety"]["images"] = freeze_images(config, project, api)
        report["safety"]["isolation"] = validate_isolation(config, project, root, **review)
        # New implicit image volumes add names: check the complete final resource set.
        _empty_before(api, config, project)
        _write_json(frozen, config)
        digest = hashlib.sha256(frozen.read_bytes()).hexdigest()
        report["safety"]["frozen_config_sha256"] = digest
        lease = {
            "project": project,
            "config_sha256": digest,
            "resources": report["safety"]["isolation"],
            "before": before,
            "phase": "prepared",
        }
        _write_json(private / "resource-lease.json", lease)
        report["safety"]["trace"].append("image_ids_volume_intents_and_config_frozen_before_up")
        up_attempted = True
        outcome = _command(
            [*base, "up", "-d", "--no-build", "--pull", "never"],
            timeout=180,
            cwd=root,
            log_directory=private,
        )
        uncertain_mutation = bool(outcome.get("timed_out"))
        report["compose_up"] = outcome
        captured_resources = snapshot_resources(api, project)
        created = captured_resources["volumes"]
        lease.update(phase="created", created_resources=captured_resources)
        _write_json(private / "resource-lease.json", lease)
        if outcome.get("timed_out") or outcome.get("error") or outcome.get("exit_code") != 0:
            raise SafetyError("compose_up_failed")
        report["status"] = "failed"
        report["safety"]["inspected_containers"] = inspect_owned_mounts(api, config, project)
        report["http"] = check_http(
            api, project, recipe, timeout=recipe.get("readiness_timeout", 240)
        )
        # Diagnose even when readiness fails; unhealthy outcomes are part of the corpus.
        report["automatic"]["static"] = run_diagnostic(
            inspector, project, private / "static-control"
        )
        report["automatic"]["probe"] = run_diagnostic(
            inspector, project, private / "probe-control", probe=True
        )
        for index, check in enumerate(recipe.get("checks", [])):
            if check.get("source") not in config["services"] or not isinstance(
                check.get("target"), str
            ):
                raise SafetyError("manual_check_invalid")
            checked = run_diagnostic(
                inspector,
                project,
                private / f"manual-{index}-control",
                probe=True,
                source=check["source"],
                target=check["target"],
            )
            report["manual_checks"].append(
                {
                    "source": check["source"],
                    "source_service": check["source"],
                    "target": check["target"],
                    "discovery": "manual_only",
                    **checked,
                }
            )
        valid = report["http"]["ready"] and all(
            value.get("valid_for_grading") is True
            and value.get("report") is not None
            and not value.get("error")
            and value.get("cleanup") in {"complete", "not_needed"}
            for value in report["automatic"].values()
        )
        report["status"] = "complete" if valid else "failed"
    except SafetyError as event:
        report["error"] = str(event)
        report["status"] = "failed" if up_attempted else "refused"
    except KeyboardInterrupt:
        report.update(status="cancelled", error="cancelled")
        uncertain_mutation = up_attempted
    except ERRORS:
        report.update(status="failed", error="case_boundary_failure")
    finally:
        if up_attempted and api is not None and config is not None:
            cleanup: dict[str, Any] = {"cleanup": "failed"}
            try:
                if base is None:
                    raise SafetyError("frozen_compose_command_unavailable")
                if not report.get("compose_up", {}).get("process_tree_exited", True):
                    raise SafetyError("compose_command_exit_unconfirmed")
                _guard_down(api, project, config, captured=captured_resources)
                down = _command(
                    [*base, "down", "--timeout", "15"], timeout=90, cwd=root, log_directory=private
                )
                cleanup["compose_down"] = down
                if created is None:
                    cleanup["error"] = "created_volume_identity_unknown"
                else:
                    cleanup.update(
                        cleanup_owned_volumes(
                            api, config, project, before["volumes"], created=created
                        )
                    )
                after = snapshot_resources(api, project)
                cleanup["after"] = after
                probes = [*report["automatic"].values(), *report["manual_checks"]]
                if (
                    any(after.values())
                    or down.get("exit_code") != 0
                    or down.get("error")
                    or uncertain_mutation
                    or any(
                        value.get("cleanup") not in {"complete", "not_needed"} for value in probes
                    )
                ):
                    cleanup.update(cleanup="failed", error="cleanup_uncertain")
            except ERRORS:
                cleanup.update(cleanup="failed", error="cleanup_boundary_failure")
            report["cleanup"] = cleanup
            if cleanup["cleanup"] != "complete":
                report.update(status="failed", error="cleanup_uncertain")
        if own_inspector and inspector is not None:
            inspector.close()
        _write_json(private / "evidence.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--allow-build", action="store_true")
    parser.add_argument("--allow-pull", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        recipe = json.loads(args.recipe.read_text(encoding="utf-8"))
        report = run_case(recipe, allow_build=args.allow_build, allow_pull=args.allow_pull)
    except (OSError, ValueError, TypeError):
        report = {"schema_version": "corpus-live-1", "status": "refused", "error": "recipe_invalid"}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        _write_json(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
