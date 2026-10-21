"""Evaluate frozen DockRoute discovery on normalized Compose configuration.

Example::

    python scripts/evaluate_corpus.py --manifest manifest.json \
        --split development --output results.json --labels reviews.json

The manifest is {"cases": [{"id": "project", "repo": "public URL",
"revision": "pinned commit", "root": "/absolute/prepared/copy",
"compose_files": ["compose.yaml"], "env_file": "sample.env",
"split": "development", "oracle_coverage": "partial"}]}. ``repo_dir`` may
replace ``root``; relative roots resolve against the manifest directory. Compose
files are relative to the root. An explicitly supplied env file may be absolute.
The caller prepares inert env files; no missing values are guessed here. Without
env_file, an explicit empty env source prevents implicit .env/ambient variables.
Optional raw_log_directory must stay inside the case root or this checkout's
work/ directory. Exact binary stdout/stderr for each unique attempt are saved
privately there (default: ignored work/evaluator-raw/); public records contain
only relative log filenames, byte counts and hashes, plus command argv, exit
code and elapsed time. Raw normalization logs can contain credentials.

Only ``docker compose config`` runs: this module never starts or inspects a
container and never invokes diagnosis. Optional ``profiles`` selects explicit
profiles (``["*"]`` requests the full configured catalog); when absent the explicit
env file and Compose defaults select profiles. YAML anchors, interpolation,
include/extends and env_file are handled by the installed Compose CLI. Returned attempts retain sanitized failures, not
raw configuration, stderr, environment values or healthcheck commands.

Independent source oracles must be authored before predictions. Optional review
labels are a separate JSON list, or {"labels": [...]}, with fields case_id,
source, host, port and label (correct, wrong-target, not-a-connection, missed,
unreviewed). The scorer consumes these reviews; it never creates ground truth.
"""

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from dockroute import __version__  # noqa: E402
from dockroute.config_extractors import (  # noqa: E402
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    ConfigDocument,
    config_kind_for_path,
    extract_configs,
)
from dockroute.discovery import discover, resolve_hostname, shared_networks  # noqa: E402
from dockroute.models import Container, Network, Port  # noqa: E402
from dockroute.safety import is_loopback, safe_key, safe_text, valid_host  # noqa: E402

SCHEMA_VERSION = "dockroute.corpus-evaluator/1.1"
BASELINE_REVISION = "2a9060d67175635210ad09f2db4633335a0a3fac"
REVIEW_LABELS = ("correct", "wrong-target", "not-a-connection", "missed", "unreviewed")
_INTERPOLATION = re.compile(r"(?<!\$)\$(?:\{[^}]*\}|[a-zA-Z_][a-zA-Z0-9_]*)")
_MAX_CONFIG_BYTES = 16 * 1024 * 1024


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _strings(value):
    return (
        tuple(str(item) for item in value if isinstance(item, (str, int)))
        if isinstance(value, (list, tuple))
        else ()
    )


def _environment(service):
    environment = service.get("environment")
    if isinstance(environment, list):
        environment = dict(
            item.split("=", 1) for item in environment if isinstance(item, str) and "=" in item
        )
    return {
        str(key): str(value)
        for key, value in _mapping(environment).items()
        if value is not None and not _INTERPOLATION.search(str(value))
    }


def _extra_hosts(value):
    if isinstance(value, dict):
        return tuple(sorted(f"{key}:{target}" for key, target in value.items()))
    result = []
    for item in _strings(value):
        host, separator, address = item.partition("=" if "=" in item else ":")
        if separator:
            result.append(f"{host}:{address}")
    return tuple(sorted(result))


def _port_number(value):
    text = str(value)
    return int(text) if text.isdecimal() and 1 <= int(text) <= 65535 else None


def _ports(service):
    ports = []
    for item in service.get("ports", ()) or ():
        if not isinstance(item, dict):
            continue  # Short syntax belongs to Compose normalization, not this adapter.
        target = _port_number(item.get("target"))
        published = _port_number(item.get("published"))
        if target:
            ports.append(
                Port(
                    target,
                    str(item.get("protocol", "tcp")),
                    published,
                    str(item.get("host_ip", "")),
                )
            )
    for item in service.get("expose", ()) or ():
        target, _, protocol = str(item).partition("/")
        number = _port_number(target)
        if number:
            ports.append(Port(number, protocol or "tcp"))
    return tuple(dict.fromkeys(ports))


def configuration_containers(config: dict, project: str) -> list[Container]:
    """Adapt normalized fields into private models with synthetic IDs only.

    The models are input to unchanged discovery, never a runtime snapshot.
    Static network addresses are deliberately not supplied as observed IPs.
    """
    services = _mapping(config.get("services"))
    configured_networks = _mapping(config.get("networks"))
    containers = []
    for service, raw in sorted(services.items()):
        raw = _mapping(raw)
        mode = str(raw.get("network_mode", ""))
        network_entries = raw.get("networks", {} if mode else {"default": None})
        if isinstance(network_entries, list):
            network_entries = dict.fromkeys(network_entries)
        networks = {}
        for key, properties in sorted(_mapping(network_entries).items()):
            declaration = _mapping(configured_networks.get(key))
            name = str(declaration.get("name") or f"{project}_{key}")
            networks[str(key)] = Network(
                name,
                f"config-only:{project}:network:{key}",
                _strings(_mapping(properties).get("aliases")),
                (),
            )
        health = _mapping(raw.get("healthcheck"))
        healthcheck = () if health.get("disable") else _strings(health.get("test"))
        if isinstance(health.get("test"), str) and not health.get("disable"):
            healthcheck = (health["test"],)
        dependencies = raw.get("depends_on", ())
        dependencies = (
            tuple(sorted(str(key) for key in dependencies))
            if isinstance(dependencies, (dict, list, tuple))
            else ()
        )
        containers.append(
            Container(
                id=f"config-only:{project}:service:{service}",
                name=str(raw.get("container_name") or service),
                project=project,
                service=str(service),
                state="unknown",
                health="unknown",
                networks=networks,
                ports=_ports(raw),
                env=_environment(raw),
                healthcheck=healthcheck,
                depends_on=dependencies,
                network_mode=mode,
                extra_hosts=_extra_hosts(raw.get("extra_hosts")),
            )
        )
    return containers


def _unresolved_environment(config):
    result = []
    for name, service in sorted(_mapping(config.get("services")).items()):
        for key, value in sorted(_mapping(_mapping(service).get("environment")).items()):
            if value is None or _INTERPOLATION.search(str(value)):
                reason = "unset_environment" if value is None else "unresolved_interpolation"
                result.append(
                    {
                        "service": safe_text(name),
                        "field": "environment",
                        "key": safe_key(str(key)),
                        "reason": reason,
                    }
                )
    return result


def _limitations(container):
    result = []
    if container.network_mode == "host":
        result.append("host_network")
    elif container.network_mode.startswith(("service:", "container:")):
        result.append("network_namespace_mode")
    if container.extra_hosts:
        result.append("extra_hosts")
    return result


def _mounted_documents(
    definition: dict, case_root: Path
) -> tuple[tuple[ConfigDocument, ...], tuple[str, ...]]:
    """Read only known config names from files inside this prepared corpus copy."""
    root = case_root.resolve()
    issues: set[str] = set()
    documents: list[ConfigDocument] = []
    total = 0
    seen: set[Path] = set()
    for mount in definition.get("volumes", ()) or ():
        if not isinstance(mount, dict) or mount.get("type") != "bind":
            continue
        source_text, target = mount.get("source"), mount.get("target")
        if not isinstance(source_text, str) or not isinstance(target, str):
            continue
        candidates: list[tuple[Path, str]] = []
        source = Path(source_text)
        kind = config_kind_for_path(target)
        if kind:
            candidates.append((source, target))
        elif target == "/etc/nginx":
            candidates.append((source / "nginx.conf", target + "/nginx.conf"))
            confdir = source / "conf.d"
            if confdir.is_dir():
                candidates.extend(
                    (p, target + "/conf.d/" + p.name)
                    for p in sorted(confdir.iterdir())
                    if p.name.endswith(".conf")
                )
        elif target == "/etc/nginx/conf.d" and source.is_dir():
            candidates.extend(
                (p, target + "/" + p.name)
                for p in sorted(source.iterdir())
                if p.name.endswith(".conf")
            )
        elif target in {"/etc/prometheus", "/etc/envoy"}:
            names = (
                ("prometheus.yml", "prometheus.yaml")
                if target.endswith("prometheus")
                else ("envoy.yaml", "envoy.yml")
            )
            candidates.extend((source / name, target + "/" + name) for name in names)
        for path, destination in candidates:
            if len(documents) >= MAX_FILES or total >= MAX_TOTAL_BYTES:
                issues.add("CONFIG_TOTAL_LIMIT")
                break
            file_kind = config_kind_for_path(destination)
            if file_kind is None:
                continue
            try:
                # Windows sandboxed temp files can deny realpath metadata while
                # still allowing a normal open. Check lexical containment first,
                # then reject every symlink/junction before reading the file.
                resolved = Path(os.path.abspath(path))
                if not resolved.is_relative_to(root):
                    issues.add("CONFIG_OUTSIDE_CASE_ROOT")
                    continue
                current = resolved
                while current != root:
                    if current.is_symlink() or (
                        hasattr(os.path, "isjunction") and os.path.isjunction(current)
                    ):
                        raise ValueError("symlink")
                    current = current.parent
                if not resolved.is_file():
                    issues.add("CONFIG_FILE_UNAVAILABLE")
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                with resolved.open("rb") as stream:
                    content = stream.read(MAX_FILE_BYTES + 1)
                if len(content) > MAX_FILE_BYTES:
                    issues.add("CONFIG_FILE_SIZE_LIMIT")
                    continue
                if total + len(content) > MAX_TOTAL_BYTES:
                    issues.add("CONFIG_TOTAL_LIMIT")
                    break
                total += len(content)
                documents.append(ConfigDocument(file_kind, destination, content))
            except FileNotFoundError:
                issues.add("CONFIG_FILE_UNAVAILABLE")
            except (OSError, ValueError):
                issues.add("CONFIG_READ_FAILED")
    return tuple(documents), tuple(sorted(issues))


def discover_configuration(config: dict, project: str, *, case_root: Path | None = None) -> dict:
    """Return sanitized intentions and configured ambiguity, without diagnoses."""
    containers = configuration_containers(config, project)
    configuration_issues: set[str] = set()
    if case_root is not None:
        enriched = []
        for container in containers:
            definition = _mapping(_mapping(config.get("services")).get(container.service))
            documents, read_issues = _mounted_documents(definition, case_root)
            extracted = extract_configs(documents)
            configuration_issues.update(read_issues)
            configuration_issues.update(extracted.issues)
            enriched.append(replace(container, config_hints=extracted.hints))
        containers = enriched
    by_id = {c.id: c for c in containers}
    declarations = _mapping(config.get("networks"))
    external = {str(key) for key, value in declarations.items() if _mapping(value).get("external")}
    services = []
    for container in containers:
        definition = _mapping(_mapping(config.get("services")).get(container.service))
        services.append(
            {
                "service": safe_text(container.service),
                "profiles": [safe_text(p) for p in _strings(definition.get("profiles"))],
                "configured_networks": [safe_text(n.name) for n in container.networks.values()],
                "network_mode": safe_text(container.network_mode),
                "configured_ports": [
                    {
                        "container": p.container,
                        "protocol": safe_text(p.protocol),
                        "published": p.host,
                        "host_ip": p.host_ip if valid_host(p.host_ip) else "",
                    }
                    for p in container.ports
                ],
                "extra_hosts_names": [
                    safe_text(item.partition(":")[0]) for item in container.extra_hosts
                ],
                "limitations": _limitations(container),
            }
        )
    intentions = []
    for connection in discover(containers):
        source = by_id[connection.source_id]
        destinations = resolve_hostname(connection.host, containers)
        dependency_only = bool(connection.evidence) and all(
            e.kind == "depends_on" for e in connection.evidence
        )
        common = sorted(
            {name for destination in destinations for name in shared_networks(source, destination)}
        )
        involved = [source, *destinations]
        limitations = sorted({limitation for c in involved for limitation in _limitations(c)})
        external_names = sorted(
            {n.name for c in involved for key, n in c.networks.items() if key in external}
        )
        host = connection.host.lower().rstrip(".")
        kind = (
            "loopback"
            if is_loopback(host)
            else "internal"
            if destinations
            else "external-or-unknown"
        )
        intentions.append(
            {
                "source": safe_text(connection.source),
                "host": host if valid_host(host) else "[redacted endpoint]",
                "port": connection.port,
                "evidence": [
                    {"kind": e.kind, "detail": safe_text(e.detail, 512)}
                    for e in connection.evidence
                ],
                "matched_services": sorted(safe_text(c.service) for c in destinations),
                "dependency_only": dependency_only,
                "connection_confirmed": False,
                "context": {
                    "destination_kind": kind,
                    "configured_shared_networks": [safe_text(name) for name in common],
                    "external_networks": [safe_text(name) for name in external_names],
                    "ambiguous_match": len(destinations) > 1,
                    "host_network": any(c.network_mode == "host" for c in involved),
                    "extra_hosts_match": any(
                        item.partition(":")[0].lower() == host for item in source.extra_hosts
                    ),
                    "limitations": limitations,
                },
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "files-only",
        "kind": "connection-intentions",
        "runtime_observed": False,
        "project": safe_text(project),
        "services": services,
        "intentions": intentions,
        "unresolved": _unresolved_environment(config),
        "configuration_issues": sorted(configuration_issues),
    }


def _case_paths(case, base_dir=None):
    root_value = case.get("root") or case.get("repo_dir")
    if not isinstance(root_value, str) or not root_value:
        raise ValueError("case requires an explicit root or repo_dir")
    root = Path(root_value)
    if not root.is_absolute():
        root = Path(base_dir or Path.cwd()) / root
    root = root.resolve()
    compose_files = case.get("compose_files")
    if not isinstance(compose_files, list) or not compose_files:
        raise ValueError("compose_files must be a nonempty list")
    files = []
    for name in compose_files:
        path = Path(name)
        if path.is_absolute() or not (root / path).resolve().is_relative_to(root):
            raise ValueError("compose file must stay within case root")
        files.append((root / path).resolve())
    env = case.get("env_file")
    env_path = Path(env) if env else None
    if env_path is not None and not env_path.is_absolute():
        env_path = root / env_path
    return root, files, env_path.resolve() if env_path is not None else None


def _project_directory(case, root, files):
    value = case.get("project_directory")
    if value is None:
        return files[0].parent
    path = Path(value)
    path = path.resolve() if path.is_absolute() else (root / path).resolve()
    if not path.is_relative_to(root):
        raise ValueError("project_directory must stay within case root")
    return path


def _profiles(case):
    profiles = case.get("profiles", [])
    if not isinstance(profiles, list) or any(
        not isinstance(p, str) or not re.fullmatch(r"\*|[a-zA-Z0-9][a-zA-Z0-9_.-]*", p)
        for p in profiles
    ):
        raise ValueError("profiles must be a list of profile names")
    return list(dict.fromkeys(profiles))


def _normalization_environment():
    # Exclude inherited Compose interpolation values and automatic COMPOSE_FILE.
    allowed = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMDATA",
    }
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def _error_class(stderr):
    message = stderr.lower()
    if "required variable" in message or "required value" in message or "is required" in message:
        return "required_interpolation"
    if "yaml" in message or "validating" in message or "invalid compose" in message:
        return "invalid_compose"
    if "no such file" in message or "cannot find" in message or "not found" in message:
        return "missing_input"
    if "unknown flag" in message or "unknown command" in message:
        return "unsupported_compose_cli"
    return "compose_config_failed"


class RawLogScopeError(ValueError):
    """A caller supplied a raw output location outside the permitted scratch scope."""


def _raw_log_directory(case, root=None, *, use_default=False):
    work = (ROOT / "work").resolve()
    value = None if use_default else case.get("raw_log_directory")
    if value is None:
        case_hash = hashlib.sha256(str(case.get("id", "case")).encode()).hexdigest()[:16]
        directory = work / "evaluator-raw" / case_hash
    else:
        directory = Path(value)
        if not directory.is_absolute():
            if root is None:
                raise RawLogScopeError("relative raw logs require a case root")
            directory = root / directory
        directory = directory.resolve()
        if not directory.is_relative_to(work) and not (
            root is not None and directory.is_relative_to(root)
        ):
            raise RawLogScopeError("raw logs must stay within case root or workspace work")
    # Repeated runs retain each attempt, even when the case ID and output root repeat.
    return directory / uuid.uuid4().hex


def _stream_bytes(value):
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    raise TypeError("subprocess stream must be bytes or text")


def _save_raw_logs(directory, root, stdout, stderr):
    """Keep exact binary streams private; expose only their filenames and hashes."""
    directory.mkdir(parents=True, exist_ok=False)
    if root is not None and directory.is_relative_to(root):
        path_base, relative = "case-root", directory.relative_to(root)
    else:
        path_base, relative = "workspace", directory.relative_to(ROOT)
    metadata = {"path_base": path_base, "directory": relative.as_posix()}
    for name, content in (("stdout", stdout), ("stderr", stderr)):
        filename = "normalization." + name + ".bin"
        (directory / filename).write_bytes(content)
        metadata[name] = {
            "filename": filename,
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        }
    return metadata


def normalize_compose(case: dict, *, timeout=30, base_dir=None) -> dict:
    """Run bounded normalization and preserve every attempt's private binary streams.

    raw_log_directory is optional, relative to the case root or an absolute path
    within the case root / checkout work directory. Default logs live in ignored
    work/evaluator-raw. Neither returned config nor raw streams belong in public
    reports; evaluate_manifest projects config onto sanitized intentions.
    """
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("normalization timeout must be between 0 and 60 seconds")
    started = time.monotonic()
    result: dict[str, Any] = {
        "status": "skipped",
        "warnings": [],
        "command_argv": [],
        "process_returncode": None,
        "process_duration_ms": 0.0,
    }
    root = None
    log_directory = None
    stdout = stderr = b""
    try:
        root, files, env = _case_paths(case, base_dir)
        log_directory = _raw_log_directory(case, root)
        project_directory = _project_directory(case, root, files)
        profiles = _profiles(case)
        project = (
            "dockroute-files-"
            + hashlib.sha256(str(case.get("id", "case")).encode()).hexdigest()[:16]
        )
        arguments = [
            "docker",
            "compose",
            "--project-directory",
            str(project_directory),
            "--project-name",
            project,
            "--env-file",
            str(env) if env is not None else os.devnull,
        ]
        for profile in profiles:
            arguments.extend(["--profile", profile])
        for path in files:
            arguments.extend(["-f", str(path)])
        result["command_argv"] = [*arguments, "config", "--format", "json"]
        process_started = time.monotonic()
        try:
            command = subprocess.run(
                result["command_argv"],
                capture_output=True,
                timeout=timeout,
                check=False,
                cwd=root,
                env=_normalization_environment(),
            )
        finally:
            result["process_duration_ms"] = round((time.monotonic() - process_started) * 1000, 3)
        stdout = _stream_bytes(command.stdout)
        stderr = _stream_bytes(command.stderr)
        result["process_returncode"] = command.returncode
        stderr_text = stderr.decode("utf-8", errors="replace")
        if command.returncode:
            result["error_class"] = _error_class(stderr_text)
        elif re.search(
            r"variable.*(?:not set|defaulting to a blank)|invalid interpolation",
            stderr_text,
            re.IGNORECASE,
        ):
            result.update(
                error_class="unresolved_interpolation", warnings=["interpolation_warning"]
            )
        elif len(stdout) > _MAX_CONFIG_BYTES:
            result["error_class"] = "config_output_limit"
        else:
            config = json.loads(stdout.decode("utf-8"))
            if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
                raise ValueError("invalid normalized config")
            result.update(status="normalized", config=config)
            if stderr:
                result["warnings"] = ["compose_warning_values_omitted"]
    except subprocess.TimeoutExpired as error:
        stdout = _stream_bytes(error.stdout)
        stderr = _stream_bytes(error.stderr)
        result["error_class"] = "compose_timeout"
    except RawLogScopeError:
        result["error_class"] = "raw_log_directory_outside_scope"
    except FileNotFoundError:
        result["error_class"] = "compose_or_input_unavailable"
    except (OSError, subprocess.SubprocessError):
        result["error_class"] = "compose_invocation_failed"
    except (TypeError, ValueError):
        result["error_class"] = "invalid_config_or_manifest"
    try:
        if log_directory is None:
            log_directory = _raw_log_directory(case, root, use_default=True)
        result["raw_logs"] = _save_raw_logs(log_directory, root, stdout, stderr)
        result["raw_log_status"] = "captured"
    except (OSError, TypeError, ValueError):
        result["raw_log_status"] = "failed"
        if result.get("status") == "normalized":
            result.pop("config", None)
            result.update(status="skipped", error_class="raw_capture_failed")
    result["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_input_hashes(attempt, root, files, env):
    errors = []
    for path in [*files, *([env] if env is not None else [])]:
        filename = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.name
        try:
            digest = _sha256(path)
            if path == env:
                attempt["env_file_sha256"] = digest
            else:
                attempt["input_hashes"][filename] = digest
        except OSError as error:
            errors.append(
                {
                    "filename": safe_text(filename),
                    "error_class": "missing_input"
                    if isinstance(error, FileNotFoundError)
                    else "input_hash_failed",
                }
            )
    if errors:
        attempt["input_hash_errors"] = errors


def _revision():
    try:
        command = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        value = command.stdout.strip()
        return (
            value if command.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", value) else None
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _compose_version():
    try:
        command = subprocess.run(
            ["docker", "compose", "version", "--short"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            env=_normalization_environment(),
        )
        value = command.stdout.strip()
        return (
            value
            if command.returncode == 0 and re.fullmatch(r"v?[0-9][0-9a-zA-Z.+-]{0,63}", value)
            else None
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _safe_repo(value):
    parsed = urlsplit(str(value))
    if parsed.scheme in {"https", "http"} and parsed.hostname and valid_host(parsed.hostname):
        return safe_text(urlunsplit((parsed.scheme, parsed.hostname, parsed.path, "", "")), 512)
    return safe_text(value, 512)


def evaluate_manifest(manifest: dict, *, split=None, base_dir=None, timeout=30) -> dict:
    """Evaluate selected cases without reading excluded split roots or contents."""
    cases = manifest.get("cases")
    if not isinstance(cases, list):
        raise ValueError("manifest must contain cases")
    ids = [case.get("id") for case in cases if isinstance(case, dict)]
    if (
        len(ids) != len(cases)
        or any(not isinstance(i, str) or not i for i in ids)
        or len(set(ids)) != len(ids)
    ):
        raise ValueError("cases require unique nonempty IDs")
    if split not in {None, "development", "holdout"}:
        raise ValueError("invalid split")
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scope": "files-only",
        "runtime_observed": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": {
            "dockroute_version": __version__,
            "baseline_revision": BASELINE_REVISION,
            "checkout_revision": _revision(),
            "evaluator_sha256": _sha256(Path(__file__)),
            "evaluated_source_sha256": {
                str(path.relative_to(ROOT)).replace("\\", "/"): _sha256(path)
                for path in sorted((ROOT / "src" / "dockroute").rglob("*.py"))
            },
            "compose_version": _compose_version(),
            "python_version": sys.version.split()[0],
            "timing_scopes": {
                "process_duration_ms": "Compose child process only",
                "normalization_duration_ms": "Compose command preparation, process, parsing and private raw capture",
                "discovery_duration_ms": "Configuration adapter and unchanged product discovery",
                "total_duration_ms": "Per-case normalization, input hashes and discovery; global metadata excluded",
                "duration_ms": "Legacy alias of normalization_duration_ms",
            },
        },
        "selection": {"split": split, "excluded_cases": []},
        "attempts": [],
        "results": [],
    }
    for case in cases:
        if split is not None and case.get("split") != split:
            report["selection"]["excluded_cases"].append(
                {"id": safe_text(case["id"]), "reason": "split_filter"}
            )
            continue
        case_started = time.monotonic()
        attempt = {
            "case_id": safe_text(case["id"]),
            "repo": _safe_repo(case.get("repo", "")),
            "revision": safe_text(case.get("revision", "")),
            "split": safe_text(case.get("split", "")),
            "oracle_coverage": case.get("oracle_coverage")
            if case.get("oracle_coverage") in {"complete", "partial", "none"}
            else "unreviewed",
            "input_hashes": {},
            "normalization_duration_ms": None,
            "discovery_duration_ms": None,
        }
        case_result = None
        try:
            # Retain the actual normalization attempt even when an input cannot be hashed.
            normalized = normalize_compose(case, timeout=timeout, base_dir=base_dir)
            attempt.update(
                {
                    key: normalized[key]
                    for key in (
                        "status",
                        "error_class",
                        "duration_ms",
                        "warnings",
                        "command_argv",
                        "process_returncode",
                        "process_duration_ms",
                        "raw_logs",
                        "raw_log_status",
                    )
                    if key in normalized
                }
            )
            attempt["normalization_duration_ms"] = normalized.get("duration_ms")
            root, files, env = _case_paths(case, base_dir)
            profiles = _profiles(case)
            attempt["requested_profiles"] = profiles
            attempt["profile_scope"] = (
                "all-configured"
                if "*" in profiles
                else "explicit"
                if profiles
                else "env-file-or-compose-default"
            )
            attempt["project_directory"] = str(
                _project_directory(case, root, files).relative_to(root)
            ).replace("\\", "/")
            _record_input_hashes(attempt, root, files, env)
            if normalized.get("status") == "normalized" and attempt.get("input_hash_errors"):
                attempt.update(status="skipped", error_class="input_hash_failed")
            elif normalized.get("status") == "normalized":
                config = normalized["config"]
                attempt["normalized_config_sha256"] = hashlib.sha256(
                    json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                discovery_started = time.monotonic()
                try:
                    result = discover_configuration(config, "files-" + case["id"], case_root=root)
                finally:
                    attempt["discovery_duration_ms"] = round(
                        (time.monotonic() - discovery_started) * 1000, 3
                    )
                result.update(
                    case_id=attempt["case_id"],
                    oracle_coverage=attempt["oracle_coverage"],
                    discovery_duration_ms=attempt["discovery_duration_ms"],
                    normalization_duration_ms=attempt["normalization_duration_ms"],
                )
                attempt["configuration_issues"] = result["configuration_issues"]
                if result["unresolved"] or result["configuration_issues"]:
                    attempt["status"] = "partial"
                    attempt["error_class"] = (
                        "unresolved_configuration_values"
                        if result["unresolved"]
                        else "mounted_configuration_incomplete"
                    )
                report["results"].append(result)
                case_result = result
        except FileNotFoundError:
            attempt.update(status="skipped", error_class="missing_input")
        except (OSError, TypeError, ValueError, KeyError):
            attempt.update(status="skipped", error_class="invalid_config_or_manifest")
        attempt["total_duration_ms"] = round((time.monotonic() - case_started) * 1000, 3)
        if case_result is not None:
            case_result["total_duration_ms"] = attempt["total_duration_ms"]
        report["attempts"].append(attempt)
    report["summary"] = {
        "selected_cases": len(report["attempts"]),
        "normalized_cases": sum(a.get("status") == "normalized" for a in report["attempts"]),
        "partial_cases": sum(a.get("status") == "partial" for a in report["attempts"]),
        "skipped_cases": sum(a.get("status") == "skipped" for a in report["attempts"]),
        "eligible_intentions": sum(
            not e["dependency_only"] for r in report["results"] for e in r["intentions"]
        ),
        "dependency_only_intentions": sum(
            e["dependency_only"] for r in report["results"] for e in r["intentions"]
        ),
    }
    return report


def _edge_key(case_id, edge):
    return (
        case_id,
        edge.get("source"),
        str(edge.get("host", "")).lower().rstrip("."),
        edge.get("port"),
    )


def score_predictions(results, labels) -> dict:
    """Score explicit independent reviews; unreviewed predictions stay unknown.

    wrong-target is a false positive and a false negative. A missed review must
    identify an oracle endpoint without an eligible prediction. Dependency-only
    intentions never contribute a true positive. Recall is conditional on the
    reviewer oracle and its recorded source coverage, including source-hidden
    endpoints where the reviewer has sufficient evidence.
    """
    rows = results.get("results", []) if isinstance(results, dict) else results
    reviews = labels.get("labels", []) if isinstance(labels, dict) else labels
    if not isinstance(rows, list) or not isinstance(reviews, list):
        raise ValueError("results and labels must be lists")
    predictions = {}
    excluded = set()
    for result in rows:
        for edge in result.get("intentions", []):
            key = _edge_key(result.get("case_id"), edge)
            if key in predictions or key in excluded:
                raise ValueError("duplicate prediction")
            if edge.get("dependency_only"):
                excluded.add(key)
            else:
                predictions[key] = edge
    reviewed = {}
    misses = set()
    seen = set()
    for review in reviews:
        if not isinstance(review, dict) or review.get("label") not in REVIEW_LABELS:
            raise ValueError("unknown review label")
        key = _edge_key(review.get("case_id"), review)
        if key in seen:
            raise ValueError("duplicate review")
        seen.add(key)
        label = review["label"]
        if label == "missed":
            if key in predictions:
                raise ValueError("missed review matches an eligible prediction")
            misses.add(key)
        elif key in excluded:
            continue
        elif key not in predictions:
            raise ValueError("review does not match a prediction")
        else:
            reviewed[key] = label
    counts = dict.fromkeys(REVIEW_LABELS, 0)
    counts["missed"] = len(misses)
    for key in predictions:
        counts[reviewed.get(key, "unreviewed")] += 1
    precision_denominator = counts["correct"] + counts["wrong-target"] + counts["not-a-connection"]
    recall_denominator = counts["correct"] + counts["wrong-target"] + counts["missed"]
    attempts = results.get("attempts", []) if isinstance(results, dict) else []
    selected_cases = len(attempts) if attempts else len(rows)
    unavailable_cases = sum(a.get("status") != "normalized" for a in attempts)
    oracle_complete = bool(rows) and all(r.get("oracle_coverage") == "complete" for r in rows)

    def ratio(denominator):
        return {
            "numerator": counts["correct"],
            "denominator": denominator,
            "value": counts["correct"] / denominator if denominator else None,
        }

    return {
        "scope": "files-only-independent-review",
        "counts": counts,
        "dependency_only_excluded": len(excluded),
        "precision": ratio(precision_denominator),
        "recall": ratio(recall_denominator),
        "recall_scope": "reviewed-oracle-only",
        "oracle_coverage_complete": oracle_complete,
        "evaluated_case_coverage": {
            "evaluated": len(rows),
            "selected": selected_cases,
            "skipped_or_partial": unavailable_cases,
        },
        "corpus_recall_complete": oracle_complete
        and unavailable_cases == 0
        and counts["unreviewed"] == 0,
        "prediction_review_coverage": {
            "reviewed": precision_denominator,
            "eligible": len(predictions),
        },
        "wrong_target_counts_as": ["false-positive", "false-negative"],
    }


def _timeout_argument(value):
    number = float(value)
    if not math.isfinite(number) or not 0 < number <= 60:
        raise argparse.ArgumentTypeError("timeout must be greater than 0 and at most 60 seconds")
    return number


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="JSON manifest with a cases list; relative roots resolve here",
    )
    parser.add_argument(
        "--split", choices=("development", "holdout"), help="Only selected roots are read"
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Sanitized JSON attempts/results, including skipped cases",
    )
    parser.add_argument(
        "--labels", type=Path, help="Separately authored second-stage independent review labels"
    )
    parser.add_argument(
        "--timeout",
        type=_timeout_argument,
        default=30,
        help="Compose normalization deadline per case, at most 60 seconds",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8-sig"))
        report = evaluate_manifest(
            manifest,
            split=args.split,
            base_dir=args.manifest.resolve().parent,
            timeout=args.timeout,
        )
        report["metadata"]["manifest_sha256"] = _sha256(args.manifest)
        if args.labels:
            labels = json.loads(args.labels.read_text(encoding="utf-8-sig"))
            report["score"] = score_predictions(report, labels)
            report["metadata"]["review_labels_sha256"] = _sha256(args.labels)
    except (OSError, TypeError, ValueError):
        print("Corpus evaluation failed: invalid_input_or_review (values omitted)", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(
        f"Corpus evaluation: {len(report['results'])} results; {report['summary']['skipped_cases']} skipped"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
