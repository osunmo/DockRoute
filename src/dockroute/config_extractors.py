"""Bounded, read-only extraction of outgoing intentions from mounted configuration.

These are configuration candidates, not proof a file was loaded or traffic occurred.
The collector receives a selected container's Docker ``get_archive`` callback; it
never opens a host bind source, extracts an archive, or follows configuration includes.
"""

from __future__ import annotations

import io
import re
import tarfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from dockroute.endpoints import parse_endpoint
from dockroute.models import Evidence
from dockroute.safety import valid_host

MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_FILES = 32
MAX_ARCHIVE_MEMBERS = 128
MAX_DEPTH = 32
MAX_NODES = 20_000
MAX_TARGETS = 16


@dataclass(frozen=True)
class ConfigDocument:
    kind: str
    path: str = field(repr=False)
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class ConfigHint:
    host: str
    port: int
    evidence: Evidence


@dataclass(frozen=True)
class ExtractionResult:
    hints: tuple[ConfigHint, ...] = ()
    issues: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConfigCollection:
    documents: tuple[ConfigDocument, ...] = ()
    issues: tuple[str, ...] = ()


def _safe_path(path: str) -> bool:
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 1024:
        return False
    if "\\" in path or "//" in path or any(ord(c) < 32 for c in path):
        return False
    parts = path.split("/")
    if any(p in {".", ".."} for p in parts):
        return False
    forbidden = {
        "proc",
        "sys",
        "dev",
        "run",
        "secrets",
        ".ssh",
        ".aws",
        ".azure",
        ".docker",
        ".kube",
        "credentials",
        "certs",
        "certificates",
        "private",
        "ssl",
    }
    return not any(p.lower() in forbidden or p.lower().endswith(".sock") for p in parts)


def config_kind_for_path(path: str) -> str | None:
    """Recognize exact mounted config filenames without reading their parent directory."""
    if not _safe_path(path):
        return None
    name = PurePosixPath(path).name.lower()
    if name == "nginx.conf" or (path.startswith("/etc/nginx/conf.d/") and name.endswith(".conf")):
        return "nginx"
    if name in {"prometheus.yaml", "prometheus.yml"}:
        return "prometheus"
    if name in {"envoy.yaml", "envoy.yml"}:
        return "envoy"
    return None


def _mount_targets(mounts: Iterable[Mapping[str, Any]]) -> tuple[list[tuple[str, str]], set[str]]:
    targets: set[tuple[str, str]] = set()
    issues: set[str] = set()
    directory_targets = {
        "/etc/nginx": (("/etc/nginx/nginx.conf", "nginx"), ("/etc/nginx/conf.d", "nginx")),
        "/etc/nginx/conf.d": (("/etc/nginx/conf.d", "nginx"),),
        "/etc/prometheus": (
            ("/etc/prometheus/prometheus.yml", "prometheus"),
            ("/etc/prometheus/prometheus.yaml", "prometheus"),
        ),
        "/etc/envoy": (("/etc/envoy/envoy.yaml", "envoy"), ("/etc/envoy/envoy.yml", "envoy")),
    }
    for index, mount in enumerate(mounts):
        if index >= 256:
            issues.add("CONFIG_MOUNT_LIMIT")
            break
        if not isinstance(mount, Mapping) or mount.get("Type") not in {"bind", "volume"}:
            continue
        path = mount.get("Destination")
        if not isinstance(path, str) or not _safe_path(path):
            continue
        path = path.rstrip("/")
        kind = config_kind_for_path(path)
        if kind:
            targets.add((path, kind))
        elif path in directory_targets:
            targets.update(directory_targets[path])
    # A directory archive includes exact files beneath it, avoiding duplicate requests.
    if ("/etc/nginx/conf.d", "nginx") in targets:
        targets = {t for t in targets if not t[0].startswith("/etc/nginx/conf.d/")}
    ordered = sorted(targets)
    if len(ordered) > MAX_TARGETS:
        issues.add("CONFIG_TARGET_LIMIT")
    return ordered[:MAX_TARGETS], issues


def collect_mounted_configs(
    mounts: Iterable[Mapping[str, Any]],
    get_archive: Callable[[str], tuple[Iterable[bytes], Mapping[str, Any]]],
) -> ConfigCollection:
    """Read a bounded archive of conventional config targets from one selected container.

    The caller supplies Docker request timeouts/cancellation and project selection.
    All exceptions are replaced with constant issue codes; neither daemon exception
    text nor raw config is diagnostic evidence. Tar members are read in memory only.
    """
    targets, issues = _mount_targets(mounts)
    documents: list[ConfigDocument] = []
    seen: set[str] = set()
    total = 0
    for target, kind in targets:
        stream: Iterable[bytes] | None = None
        try:
            stream, stat = get_archive(target)
            if stat.get("linkTarget"):
                issues.add("CONFIG_ARCHIVE_UNSAFE_MEMBER")
                continue
            data = bytearray()
            for chunk in stream:
                if not isinstance(chunk, bytes):
                    raise ValueError("invalid archive chunk")
                if len(data) + len(chunk) > MAX_ARCHIVE_BYTES:
                    issues.add("CONFIG_ARCHIVE_SIZE_LIMIT")
                    break
                data.extend(chunk)
            else:
                root = PurePosixPath(target).name
                is_directory = target == "/etc/nginx/conf.d"
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                    for index, member in enumerate(archive):
                        if index >= MAX_ARCHIVE_MEMBERS:
                            issues.add("CONFIG_ARCHIVE_MEMBER_LIMIT")
                            break
                        name = member.name.removeprefix("./").rstrip("/")
                        parts = name.split("/")
                        if (
                            not name
                            or name.startswith("/")
                            or "\\" in name
                            or any(part in {".", "..", ""} for part in parts)
                            or any(ord(c) < 32 for c in name)
                            or not (name == root or is_directory and name.startswith(root + "/"))
                            or not (member.isfile() or member.isdir())
                            or member.issym()
                            or member.islnk()
                        ):
                            issues.add("CONFIG_ARCHIVE_UNSAFE_MEMBER")
                            continue
                        if member.isdir():
                            continue
                        if is_directory and not name.lower().endswith(".conf"):
                            continue
                        if member.size > MAX_FILE_BYTES or member.size < 0:
                            issues.add("CONFIG_FILE_SIZE_LIMIT")
                            continue
                        if len(documents) >= MAX_FILES or total + member.size > MAX_TOTAL_BYTES:
                            issues.add("CONFIG_TOTAL_LIMIT")
                            break
                        path = str(PurePosixPath(target).parent / name)
                        if path in seen:
                            issues.add("CONFIG_DUPLICATE_FILE")
                            continue
                        reader = archive.extractfile(member)
                        if reader is None:
                            continue
                        with reader:
                            content = reader.read(MAX_FILE_BYTES + 1)
                        if len(content) != member.size:
                            raise ValueError("truncated archive member")
                        documents.append(ConfigDocument(kind, path, content))
                        seen.add(path)
                        total += len(content)
        except Exception:
            issues.add("CONFIG_READ_FAILED")
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    issues.add("CONFIG_READ_FAILED")
    return ConfigCollection(tuple(documents), tuple(sorted(issues)))


class _ConfigError(ValueError):
    pass


def _bounded_yaml(text: str) -> Any:
    # Imported only when this optional subsystem parses a YAML config.
    import yaml

    class Loader(yaml.SafeLoader):
        depth = 0
        nodes = 0

        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise _ConfigError("CONFIG_YAML_ALIASES_UNSUPPORTED")
            self.depth += 1
            self.nodes += 1
            if self.depth > MAX_DEPTH or self.nodes > MAX_NODES:
                raise _ConfigError("CONFIG_STRUCTURE_LIMIT")
            try:
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

        def construct_mapping(self, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, (str, int, float, bool, type(None))) or key in result:
                    raise _ConfigError("CONFIG_YAML_DUPLICATE_OR_COMPLEX_KEY")
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    try:
        value = yaml.load(text, Loader=Loader)
    except _ConfigError:
        raise
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        raise _ConfigError("CONFIG_PARSE_FAILED") from None
    if not isinstance(value, dict):
        raise _ConfigError("CONFIG_PARSE_FAILED")
    return value


def _literal(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(token in value for token in ("$", "{{", "}}", "<%", "%>"))
    )


def _endpoint(value: Any, default_port: int | None = None) -> tuple[str, int] | None:
    if not _literal(value) or value.startswith("unix:"):
        return None
    if "grpc://" == value[:7]:
        value = "http://" + value[7:]
    elif "grpcs://" == value[:8]:
        value = "https://" + value[8:]
    endpoint = parse_endpoint(value)
    if endpoint is not None:
        return endpoint
    if default_port:
        try:
            parsed = urlsplit("//" + value)
            if (
                parsed.hostname
                and not parsed.path
                and parsed.port is None
                and valid_host(parsed.hostname)
            ):
                return parsed.hostname.lower().rstrip("."), default_port
        except ValueError:
            pass
    return None


def _hint(endpoint: tuple[str, int], role: str) -> ConfigHint:
    return ConfigHint(
        *endpoint,
        Evidence(
            "mounted_config",
            f"{role} specifies this endpoint (configuration values omitted; file loading unverified)",
        ),
    )


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _prometheus(data: dict, hints: list[ConfigHint], issues: set[str]) -> None:
    for job in _list(data.get("scrape_configs")):
        job = _dict(job)
        if any(key.endswith("_sd_configs") for key in job if isinstance(key, str)):
            issues.add("CONFIG_DYNAMIC_DISCOVERY_NOT_READ")
        relabels = [_dict(item) for item in _list(job.get("relabel_configs"))]
        if any(
            not isinstance(rule.get("target_label", ""), str)
            or not isinstance(rule.get("action", "replace"), str)
            for rule in relabels
        ):
            issues.add("CONFIG_PARSE_FAILED")
            continue
        if any(
            rule.get("target_label") in {"__address__", "__scheme__", "__param_target"}
            or rule.get("action", "replace")
            in {"drop", "keep", "keepequal", "dropequal", "labelmap"}
            for rule in relabels
        ):
            issues.add("CONFIG_TARGET_RELABELING_UNSUPPORTED")
            continue
        scheme = job.get("scheme", "http")
        if not isinstance(scheme, str) or scheme not in {"http", "https"}:
            issues.add("CONFIG_UNSUPPORTED_ENDPOINT")
            continue
        for group in _list(job.get("static_configs")):
            for target in _list(_dict(group).get("targets")):
                if isinstance(target, str) and any(c in target for c in "/@?#"):
                    issues.add("CONFIG_UNSUPPORTED_ENDPOINT")
                    continue
                endpoint = _endpoint(target, 443 if scheme == "https" else 80)
                if endpoint:
                    hints.append(_hint(endpoint, "Prometheus static scrape target"))
                else:
                    issues.add(
                        "CONFIG_UNRESOLVED_VARIABLE"
                        if isinstance(target, str) and not _literal(target)
                        else "CONFIG_UNSUPPORTED_ENDPOINT"
                    )


def _envoy(data: dict, hints: list[ConfigHint], issues: set[str]) -> None:
    if data.get("dynamic_resources"):
        issues.add("CONFIG_DYNAMIC_DISCOVERY_NOT_READ")
    for cluster in _list(_dict(data.get("static_resources")).get("clusters")):
        cluster = _dict(cluster)
        if not isinstance(cluster.get("type", "STATIC"), (str, int)):
            issues.add("CONFIG_PARSE_FAILED")
            continue
        if cluster.get("type") in {"EDS", "ORIGINAL_DST", 3, 4} or cluster.get(
            "eds_cluster_config"
        ):
            issues.add("CONFIG_DYNAMIC_DISCOVERY_NOT_READ")
            continue
        for locality in _list(_dict(cluster.get("load_assignment")).get("endpoints")):
            for lb_endpoint in _list(_dict(locality).get("lb_endpoints")):
                address = _dict(_dict(_dict(lb_endpoint).get("endpoint")).get("address"))
                socket = _dict(address.get("socket_address"))
                host, port = socket.get("address"), socket.get("port_value")
                if (
                    not isinstance(host, str)
                    or not _literal(host)
                    or not valid_host(host)
                    or isinstance(port, bool)
                    or not isinstance(port, int)
                    or not 1 <= port <= 65535
                    or not isinstance(socket.get("protocol", "TCP"), (str, int))
                    or socket.get("protocol", "TCP") not in {"TCP", 0}
                ):
                    issues.add(
                        "CONFIG_UNRESOLVED_VARIABLE"
                        if isinstance(host, str) and not _literal(host)
                        else "CONFIG_UNSUPPORTED_ENDPOINT"
                    )
                    continue
                hints.append(
                    _hint((host.lower().rstrip("."), port), "Envoy static cluster endpoint")
                )


@dataclass(frozen=True)
class _Directive:
    args: tuple[str, ...]
    children: tuple[_Directive, ...] | None = None


def _nginx_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    quote = ""
    escaped = False
    comment = False
    for character in text:
        if comment:
            if character == "\n":
                comment = False
            continue
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif quote:
            if character == quote:
                quote = ""
            else:
                current.append(character)
        elif character in {'"', "'"}:
            quote = character
        elif character == "#":
            if current:
                tokens.append("".join(current))
                current = []
            comment = True
        elif character.isspace() or character in "{};":
            if current:
                tokens.append("".join(current))
                current = []
            if character in "{};":
                tokens.append(character)
        else:
            current.append(character)
        if len(tokens) > MAX_NODES:
            raise _ConfigError("CONFIG_STRUCTURE_LIMIT")
    if quote or escaped:
        raise _ConfigError("CONFIG_PARSE_FAILED")
    if current:
        tokens.append("".join(current))
    return tokens


def _nginx_tree(text: str) -> tuple[_Directive, ...]:
    tokens = _nginx_tokens(text)
    index = 0

    def parse(depth: int) -> tuple[_Directive, ...]:
        nonlocal index
        if depth > MAX_DEPTH:
            raise _ConfigError("CONFIG_STRUCTURE_LIMIT")
        nodes: list[_Directive] = []
        args: list[str] = []
        while index < len(tokens):
            token = tokens[index]
            index += 1
            if token == "}":
                if args or not depth:
                    raise _ConfigError("CONFIG_PARSE_FAILED")
                return tuple(nodes)
            if token in {"{", ";"}:
                if not args:
                    raise _ConfigError("CONFIG_PARSE_FAILED")
                children = parse(depth + 1) if token == "{" else None
                nodes.append(_Directive(tuple(args), children))
                args = []
            else:
                args.append(token)
        if depth or args:
            raise _ConfigError("CONFIG_PARSE_FAILED")
        return tuple(nodes)

    return parse(0)


def _nginx(trees: list[tuple[_Directive, ...]], hints: list[ConfigHint], issues: set[str]) -> None:
    groups: dict[str, list[tuple[str, int]] | None] = {}
    passes: list[str] = []

    def walk(nodes: tuple[_Directive, ...], in_upstream: bool = False) -> None:
        for node in nodes:
            command, *args = node.args
            if command == "include":
                issues.add("CONFIG_INCLUDES_NOT_FOLLOWED")
            if command == "upstream" and node.children is not None and len(args) == 1:
                name = args[0].lower()
                if name in groups:
                    groups[name] = None
                    issues.add("CONFIG_AMBIGUOUS_UPSTREAM")
                    continue
                servers = []
                for child in node.children:
                    if child.args[0] != "server" or len(child.args) < 2 or "down" in child.args[2:]:
                        continue
                    value = child.args[1]
                    endpoint = (
                        None
                        if any(arg.startswith("service=") for arg in child.args[2:])
                        else _endpoint(value, 80)
                    )
                    if endpoint:
                        servers.append(endpoint)
                    else:
                        issues.add(
                            "CONFIG_UNRESOLVED_VARIABLE"
                            if not _literal(value)
                            else "CONFIG_UNSUPPORTED_ENDPOINT"
                        )
                groups[name] = servers
                walk(node.children, True)
            elif command in {"proxy_pass", "grpc_pass"} and len(args) == 1 and not in_upstream:
                passes.append(args[0])
            elif node.children is not None:
                walk(node.children, in_upstream)

    for tree in trees:
        walk(tree)
    for value in passes:
        if not _literal(value):
            issues.add("CONFIG_UNRESOLVED_VARIABLE")
            continue
        try:
            url = urlsplit(value if "://" in value else "//" + value)
            group = url.hostname.lower() if url.hostname else ""
            explicit_port = url.port
        except ValueError:
            issues.add("CONFIG_UNSUPPORTED_ENDPOINT")
            continue
        if group in groups and explicit_port is None:
            for endpoint in groups[group] or []:
                hints.append(_hint(endpoint, "Nginx referenced upstream server"))
        else:
            direct_endpoint = _endpoint(value)
            if direct_endpoint:
                hints.append(_hint(direct_endpoint, "Nginx outgoing proxy directive"))
            else:
                issues.add("CONFIG_UNSUPPORTED_ENDPOINT")


def extract_configs(documents: Iterable[ConfigDocument]) -> ExtractionResult:
    """Parse bounded config snapshots without Docker, filesystem access or secret output."""
    hints: list[ConfigHint] = []
    issues: set[str] = set()
    trees = []
    total = 0
    for index, document in enumerate(documents):
        if index >= MAX_FILES:
            issues.add("CONFIG_TOTAL_LIMIT")
            break
        total += len(document.content)
        if total > MAX_TOTAL_BYTES:
            issues.add("CONFIG_TOTAL_LIMIT")
            break
        if len(document.content) > MAX_FILE_BYTES:
            issues.add("CONFIG_FILE_SIZE_LIMIT")
            continue
        try:
            text = document.content.decode("utf-8-sig")
            if "\x00" in text:
                raise _ConfigError("CONFIG_PARSE_FAILED")
            if document.kind == "nginx":
                if re.search(r"\$\{", text):
                    issues.add("CONFIG_UNRESOLVED_VARIABLE")
                trees.append(_nginx_tree(text))
            elif document.kind == "prometheus":
                _prometheus(_bounded_yaml(text), hints, issues)
            elif document.kind == "envoy":
                _envoy(_bounded_yaml(text), hints, issues)
            else:
                issues.add("CONFIG_UNSUPPORTED_FORMAT")
        except UnicodeError:
            issues.add("CONFIG_ENCODING_UNSUPPORTED")
        except _ConfigError as error:
            issues.add(str(error))
    _nginx(trees, hints, issues)
    return ExtractionResult(
        tuple(sorted(set(hints), key=lambda h: (h.host, h.port, h.evidence.detail))),
        tuple(sorted(issues)),
    )
