"""Official Docker SDK boundary. Inspection operations are read-only."""

import os
import socket
import stat
import time
from dataclasses import replace
from urllib.parse import urlsplit

import docker as sdk
from docker.errors import DockerException, NotFound
from requests.exceptions import RequestException

from dockroute.compose import parse_labels
from dockroute.endpoints import NPIPE_GUIDANCE
from dockroute.models import Container, Network, Port


class DockerUnavailable(RuntimeError):
    pass


def diagnose_socket_access(
    socket_path: str | None = None,
    *,
    probe_timeout: float = 1.0,
) -> str | None:
    """Preflight reachability probe for Docker daemon.

    Performs filesystem stat/permission validation and an active socket connection
    probe to detect stopped (ECONNREFUSED) or unresponsive Docker daemons.
    Returns an actionable error diagnosis message if unreachable, or None if healthy.
    """
    docker_host = os.environ.get("DOCKER_HOST", "").strip()
    target_raw = (socket_path or "").strip() or docker_host

    target_lower = target_raw.lower()
    if (
        target_lower.startswith("npipe://")
        or target_lower.startswith("npipe:")
        or target_lower.startswith(r"\\.\pipe")
        or target_lower.startswith("//./pipe")
    ):
        return NPIPE_GUIDANCE

    target_path = socket_path
    if not target_path:
        if docker_host.startswith("unix://"):
            target_path = docker_host[7:]
        elif docker_host.startswith("tcp://"):
            target_path = docker_host
        else:
            candidates = [
                "/var/run/docker.sock",
                os.path.expanduser("~/.docker/run/docker.sock"),
            ]
            xdg = os.environ.get("XDG_RUNTIME_DIR")
            if xdg:
                candidates.insert(1, os.path.join(xdg, "docker.sock"))
            target_path = next((p for p in candidates if os.path.exists(p)), candidates[0])

    if target_path.startswith("tcp://"):
        u = urlsplit(target_path)
        host = u.hostname or "127.0.0.1"
        port = u.port or 2375
        try:
            with socket.create_connection((host, port), timeout=probe_timeout):
                return None
        except ConnectionRefusedError:
            return (
                f"Docker daemon at {host}:{port} is stopped or not accepting connections "
                "(connection refused). Start the Docker daemon and retry."
            )
        except (TimeoutError, socket.timeout):
            return (
                f"Connection to Docker daemon at {host}:{port} timed out after {probe_timeout:.1f}s. "
                "The daemon may be hung or blocked by firewall."
            )
        except OSError as exc:
            return f"Failed to connect to Docker daemon at {host}:{port}: {exc}"

    if target_path.startswith("unix://"):
        target_path = target_path[7:]

    if not os.path.exists(target_path):
        return (
            f"Docker socket not found at '{target_path}'. "
            "Ensure Docker Engine or Docker Desktop is installed and running."
        )

    try:
        st = os.stat(target_path)
        if not stat.S_ISSOCK(st.st_mode):
            return f"Path '{target_path}' exists but is not a valid UNIX socket."
    except OSError as exc:
        return f"Cannot stat Docker socket at '{target_path}': {exc}"

    if not os.access(target_path, os.R_OK | os.W_OK):
        return (
            f"Permission denied accessing Docker socket at '{target_path}'. "
            f"Check file permissions or add your user to the 'docker' group (socket GID {st.st_gid})."
        )

    if hasattr(socket, "AF_UNIX"):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(probe_timeout)
                s.connect(target_path)
                return None
        except ConnectionRefusedError:
            return (
                f"Docker socket exists at '{target_path}', but the Docker daemon is stopped "
                "(connection refused). Start Docker Desktop/Engine ('systemctl start docker') and retry."
            )
        except (TimeoutError, socket.timeout):
            return (
                f"Connection to Docker socket '{target_path}' timed out after {probe_timeout:.1f}s. "
                "The Docker daemon may be hung or unresponsive. Restart the daemon and retry."
            )
        except PermissionError:
            return (
                f"Permission denied while connecting to Docker socket '{target_path}'. "
                "Check socket permissions or docker group membership."
            )
        except OSError as exc:
            return f"Active connection probe to Docker socket '{target_path}' failed: {exc}"

    return None


# Alias for interoperability
diagnoseSocketAccess = diagnose_socket_access


def connect(*, timeout: float = 5) -> "Inspector":
    docker_host = os.environ.get("DOCKER_HOST", "").strip().lower()
    if (
        docker_host.startswith("npipe://")
        or docker_host.startswith("npipe:")
        or docker_host.startswith(r"\\.\pipe")
        or docker_host.startswith("//./pipe")
    ):
        raise DockerUnavailable(NPIPE_GUIDANCE)

    client = None
    try:
        # SDK 7.2+ honors DOCKER_CONTEXT/current Docker Desktop context as well as
        # DOCKER_HOST, DOCKER_TLS_VERIFY and DOCKER_CERT_PATH without shell commands.
        client = sdk.from_env(
            timeout=timeout,
            version=os.environ.get("DOCKER_API_VERSION", "auto"),
            use_ssh_client=True,
        )
        client.ping()
        return Inspector(client)
    except (DockerException, RequestException, OSError, ValueError):
        if client:
            client.close()
        diag = diagnose_socket_access(probe_timeout=min(2.0, timeout))
        if diag:
            raise DockerUnavailable(diag) from None
        # SDK exceptions can contain endpoint credentials, response bodies or keys.
        raise DockerUnavailable(
            "Docker Engine unavailable. Start Docker Desktop/Engine and check DOCKER_HOST, Docker context and socket permissions."
        ) from None


def container_from_inspect(attrs: dict) -> Container | None:
    config = attrs.get("Config") or {}
    identity = parse_labels(config.get("Labels") or {})
    if not identity:
        return None
    settings = attrs.get("NetworkSettings") or {}
    host_config = attrs.get("HostConfig") or {}
    state = attrs.get("State") or {}
    networks = {}
    for name, n in (settings.get("Networks") or {}).items():
        n = n or {}
        networks[name] = Network(
            name,
            n.get("NetworkID", ""),
            tuple(sorted(set(n.get("Aliases") or []) | set(n.get("DNSNames") or []))),
            tuple(x for x in (n.get("IPAddress"), n.get("GlobalIPv6Address")) if x),
        )
    published = settings.get("Ports") or host_config.get("PortBindings") or {}
    port_keys = set(config.get("ExposedPorts") or {}) | set(published)
    ports = []
    for key in sorted(port_keys, key=lambda s: (int(s.split("/")[0]), s)):
        number, _, protocol = key.partition("/")
        for mapping in published.get(key) or [None]:
            ports.append(
                Port(
                    int(number),
                    protocol or "tcp",
                    int(mapping["HostPort"]) if mapping and mapping.get("HostPort") else None,
                    mapping.get("HostIp", "") if mapping else "",
                )
            )
    env = {}
    for entry in config.get("Env") or []:
        key, sep, value = entry.partition("=")
        if sep and len(entry) <= 16384:
            env[key] = value
    return Container(
        id=attrs.get("Id", ""),
        name=attrs.get("Name", "").lstrip("/"),
        project=identity.project,
        service=identity.service,
        state=state.get("Status", "unknown"),
        health=(state.get("Health") or {}).get("Status", "none"),
        restart_count=attrs.get("RestartCount", 0),
        networks=networks,
        ports=tuple(ports),
        env=env,
        healthcheck=tuple((config.get("Healthcheck") or {}).get("Test") or []),
        depends_on=identity.depends_on,
        working_dir=identity.working_dir,
        config_files=identity.config_files,
        network_mode=host_config.get("NetworkMode", ""),
        extra_hosts=tuple(host_config.get("ExtraHosts") or []),
        started_at=state.get("StartedAt", ""),
        tty=bool(config.get("Tty", False)),
        mounts=tuple(attrs.get("Mounts") or ()),
    )


class Inspector:
    def __init__(self, client):
        self.client = client

    def identities(self) -> list[Container]:
        try:
            summaries = self.client.api.containers(
                all=True,
                filters={"label": ["com.docker.compose.project", "com.docker.compose.service"]},
            )
            result = []
            for s in summaries:
                identity = parse_labels(s.get("Labels") or {})
                if identity:
                    result.append(
                        Container(
                            s["Id"],
                            (s.get("Names") or [""])[0].lstrip("/"),
                            identity.project,
                            identity.service,
                            s.get("State", "unknown"),
                            depends_on=identity.depends_on,
                            working_dir=identity.working_dir,
                            config_files=identity.config_files,
                        )
                    )
            return result
        except (DockerException, RequestException, OSError):
            raise DockerUnavailable(
                "Unable to list Compose containers. Check Docker connection and permissions."
            ) from None

    def snapshot(self, project: str) -> list[Container]:
        for attempt in range(3):
            result = []
            try:
                summaries = self.client.api.containers(
                    all=True,
                    filters={
                        "label": [
                            f"com.docker.compose.project={project}",
                            "com.docker.compose.service",
                        ]
                    },
                )
                for summary in summaries:
                    try:
                        c = container_from_inspect(self.client.api.inspect_container(summary["Id"]))
                    except NotFound:
                        continue  # A concurrent Compose recreation may remove an old instance.
                    if c and c.project == project:
                        result.append(c)
                return sorted(result, key=lambda c: (c.service, c.id))
            except (DockerException, RequestException, OSError):
                if attempt == 2:
                    raise DockerUnavailable(
                        "Unable to inspect the selected Compose project. Retry after container recreation completes."
                    ) from None
                time.sleep(0.1 * (attempt + 1))
        raise AssertionError("snapshot retry loop exhausted without a result")

    def supplement_snapshot(self, containers: list[Container]) -> list[Container]:
        """Read bounded config and recent error evidence from this project only."""
        from dockroute.config_extractors import collect_mounted_configs, extract_configs
        from dockroute.log_evidence import read_log_evidence

        if not containers or len({c.project for c in containers}) != 1:
            return containers
        result = []
        for container in containers:
            issues: set[str] = set()
            hints = ()
            if container.mounts:
                collection = collect_mounted_configs(
                    container.mounts,
                    lambda path, cid=container.id: self.client.api.get_archive(cid, path),
                )
                extracted = extract_configs(collection.documents)
                hints = extracted.hints
                issues.update(collection.issues)
                issues.update(extracted.issues)
            logs = ()
            if container.state in {"exited", "dead"} or container.health == "unhealthy":
                log_result = read_log_evidence(
                    self.client.api,
                    container,
                    containers,
                    started_at=container.started_at,
                    tty=container.tty,
                )
                logs = log_result.hints
                if log_result.status in {"timeout", "unavailable"}:
                    issues.add("LOG_READ_" + log_result.status.upper())
                if log_result.truncated:
                    issues.add("LOG_TAIL_TRUNCATED")
            result.append(
                replace(
                    container,
                    config_hints=hints,
                    log_hints=logs,
                    supplemental_issues=tuple(sorted(issues)),
                )
            )
        return result

    def version(self) -> dict:
        try:
            return self.client.version()
        except (DockerException, RequestException, OSError):
            raise DockerUnavailable("Unable to read Docker Engine version.") from None

    def close(self):
        self.client.close()
