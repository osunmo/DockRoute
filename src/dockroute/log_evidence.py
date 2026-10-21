"""Read bounded recent application error observations without retaining raw logs.

The SDK's ordinary multiplexed log iterator reads an entire Docker frame before
yielding. This boundary reads small HTTP chunks and decodes frame headers itself,
so a single huge application line cannot bypass the byte budget. The historical
observations returned here never assert current DNS/TCP reachability.
"""

import calendar
import ipaddress
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from queue import Empty, Queue
from threading import Thread
from typing import Any
from urllib.parse import unquote, urlsplit

from dockroute.models import Container, Evidence

MAX_LINES = 100
MAX_BYTES = 65536
MAX_LINE_BYTES = 8192
_STAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$")
_HOST = re.compile(r"[a-zA-Z0-9_](?:[a-zA-Z0-9_.-]{0,251}[a-zA-Z0-9_])?\.?\Z")
_SINGLE_LABEL = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,62}\Z")
_SIGNATURES = (
    (
        "NGINX_UPSTREAM_DNS",
        re.compile(r'\[emerg\][^\r\n]*?\bhost not found in upstream "([^"\s]+)"'),
    ),
    ("NODE_DNS", re.compile(r"\bgetaddrinfo ENOTFOUND ([^\s,;]+)(?:\s|[,;]|$)")),
    ("TCP_REFUSED", re.compile(r"\bconnect ECONNREFUSED ([^\s,;]+)(?:\s|[,;]|$)")),
    (
        "POSTGRES_DNS",
        re.compile(r'\bcould not translate host name "([^"\s]+)" to address:'),
    ),
)
DNS_SIGNATURES = frozenset({"NGINX_UPSTREAM_DNS", "NODE_DNS", "POSTGRES_DNS"})


@dataclass(frozen=True)
class LogHint:
    source_id: str
    source: str
    host: str
    port: int | None
    signature: str
    observed_at: str
    destination_ids: tuple[str, ...] = ()
    shared_network_ids: tuple[str, ...] = ()

    def evidence(self) -> Evidence:
        host = f"[{self.host}]" if ":" in self.host else self.host
        endpoint = f"{host}:{self.port}" if self.port else host
        return Evidence(
            "container_log",
            f"Historical {self.signature} observation for {endpoint} at {self.observed_at}, "
            "during this container start; raw log omitted. It does not verify current reachability.",
        )


@dataclass(frozen=True)
class LogReadResult:
    hints: tuple[LogHint, ...] = ()
    status: str = "skipped"
    bytes_read: int = 0
    lines_read: int = 0
    truncated: bool = False
    reason: str = ""


def _timestamp_ns(value: str) -> int | None:
    match = _STAMP.fullmatch(value)
    if not match:
        return None
    try:
        instant = datetime.fromisoformat(match[1] + match[3].replace("Z", "+00:00"))
        if instant.year < 1970:
            return None
        seconds = calendar.timegm(instant.astimezone(UTC).utctimetuple())
        return seconds * 1_000_000_000 + int((match[2] or "").ljust(9, "0"))
    except (ValueError, OverflowError):
        return None


def _eligible(source: Container, containers: list[Container]) -> bool:
    return (
        bool(source.id and source.project)
        and any(c.id == source.id and c.project == source.project for c in containers)
        and all(c.project == source.project for c in containers)
        and (source.state in {"exited", "dead"} or source.health == "unhealthy")
    )


def _endpoint(value: str) -> tuple[str, int | None] | None:
    if any(c in value for c in "/@?%$#=\\") or any(ord(c) < 32 for c in value):
        return None
    port: int | None = None
    if value.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::([0-9]{1,5}))?", value)
        if not match:
            return None
        host, port_text = match.groups()
        try:
            if ipaddress.ip_address(host).version != 6:
                return None
        except ValueError:
            return None
    elif ":" in value:
        match = re.fullmatch(r"([^:]+):([0-9]{1,5})", value)
        if not match:
            return None
        host, port_text = match.groups()
    else:
        host, port_text = value, None
    if port_text:
        port = int(port_text)
        if not 1 <= port <= 65535:
            return None
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if not _HOST.fullmatch(host) or ".." in host:
            return None
        host = host.rstrip(".").lower()
    return host, port


def _matches(host: str, container: Container) -> bool:
    names = {container.service, container.name}
    for network in container.networks.values():
        names.update(network.aliases)
        names.update(network.addresses)
    return host in {name.rstrip(".").lower() for name in names}


def _secret_host(host: str, containers: list[Container]) -> bool:
    for container in containers:
        for key, value in container.env.items():
            if re.search(r"PASS|PWD|SECRET|TOKEN|KEY|CREDENTIAL|AUTH|COOKIE", key, re.I):
                if host and host.casefold() == value.strip().casefold():
                    return True
            if "://" in value:
                try:
                    endpoint = urlsplit(value)
                    if any(
                        host.casefold() == unquote(secret).casefold()
                        for secret in (endpoint.username, endpoint.password)
                        if secret
                    ):
                        return True
                except ValueError:
                    continue
    return False


def parse_log_line(
    line: str,
    source: Container,
    containers: list[Container],
    *,
    started_at: str,
    until: datetime | None = None,
) -> LogHint | None:
    """Extract a known error's endpoint, with no raw text or external name capture."""
    if len(line) > MAX_LINE_BYTES or not _eligible(source, containers):
        return None
    stamp, separator, message = line.partition(" ")
    start_ns = _timestamp_ns(started_at)
    observed_ns = _timestamp_ns(stamp)
    end_ns = _timestamp_ns((until or datetime.now(UTC)).isoformat())
    if (
        not separator
        or start_ns is None
        or observed_ns is None
        or end_ns is None
        or not start_ns <= observed_ns <= end_ns
        or any(ord(c) < 32 and c not in "\t\r\n" for c in message)
    ):
        return None
    for signature, pattern in _SIGNATURES:
        match = pattern.search(message)
        endpoint = _endpoint(match[1]) if match else None
        if endpoint is None:
            continue
        host, port = endpoint
        if signature == "TCP_REFUSED" and port is None:
            continue
        destinations = [c for c in containers if _matches(host, c)]
        if not destinations and not _SINGLE_LABEL.fullmatch(host):
            continue
        if _secret_host(host, containers):
            continue
        source_networks = {n.id for n in source.networks.values() if n.id}
        shared = {
            n.id
            for c in destinations
            for n in c.networks.values()
            if n.id and n.id in source_networks
        }
        return LogHint(
            source.id,
            source.service,
            host,
            port,
            signature,
            stamp,
            tuple(sorted(c.id for c in destinations)),
            tuple(sorted(shared)),
        )
    return None


class _Frames:
    """Decode Docker's 8-byte headers without buffering a complete frame."""

    def __init__(self, tty: bool):
        self.tty = tty
        self.header = bytearray()
        self.remaining = 0
        self.stream = 1

    def feed(self, chunk: bytes):
        if self.tty:
            yield 1, chunk
            return
        position = 0
        while position < len(chunk):
            if not self.remaining:
                size = min(8 - len(self.header), len(chunk) - position)
                self.header.extend(chunk[position : position + size])
                position += size
                if len(self.header) < 8:
                    return
                if self.header[0] not in {0, 1, 2} or self.header[1:4] != b"\0\0\0":
                    raise ValueError("Invalid Docker log framing")
                self.stream = self.header[0]
                self.remaining = int.from_bytes(self.header[4:8], "big")
                self.header.clear()
                if not self.remaining:
                    continue
            size = min(self.remaining, len(chunk) - position)
            yield self.stream, chunk[position : position + size]
            self.remaining -= size
            position += size


def read_log_evidence(
    api: Any,
    source: Container,
    containers: list[Container],
    *,
    started_at: str,
    until: datetime | None = None,
    tty: bool = False,
    timeout: float = 2.0,
    max_lines: int = MAX_LINES,
    max_bytes: int = MAX_BYTES,
) -> LogReadResult:
    """Read only this start's bounded tail; unsupported log drivers are unavailable.

    Docker SDK authenticated/context-aware HTTP transport is retained. An outer
    deadline bounds the caller even if a streaming transport stalls; SDK connect
    and read timeouts bound its request too. Any still-unwinding reader is daemon
    scoped, owns only this response, and closes it in ``finally``.
    """
    until = until or datetime.now(UTC)
    start_ns = _timestamp_ns(started_at)
    end_ns = _timestamp_ns(until.isoformat())
    if not _eligible(source, containers):
        return LogReadResult(reason="source_not_eligible_or_project_mismatch")
    if start_ns is None or end_ns is None or start_ns > end_ns:
        return LogReadResult(reason="current_start_unavailable")
    if not 0 < timeout <= 30 or max_lines <= 0 or max_bytes <= 0:
        return LogReadResult(reason="invalid_log_limits")
    max_lines, max_bytes = min(MAX_LINES, max_lines), min(MAX_BYTES, max_bytes)
    deadline = time.monotonic() + timeout
    completed: Queue[LogReadResult] = Queue(maxsize=1)
    responses: list[Any] = []

    def read() -> None:
        response = None
        hints: dict[tuple, LogHint] = {}
        byte_count = line_count = 0
        truncated = False
        pending = {stream: bytearray() for stream in (0, 1, 2)}
        oversized: set[int] = set()
        frames = _Frames(tty)

        def line_done(stream: int) -> None:
            nonlocal line_count
            line_count += 1
            if stream not in oversized:
                hint = parse_log_line(
                    pending[stream].decode("utf-8", errors="replace").rstrip("\r"),
                    source,
                    containers,
                    started_at=started_at,
                    until=until,
                )
                if hint:
                    hints[(hint.host, hint.port, hint.signature)] = hint
            pending[stream].clear()
            oversized.discard(stream)

        try:
            response = api._get(
                api._url("/containers/{0}/logs", source.id),
                params={
                    "stdout": True,
                    "stderr": True,
                    "timestamps": True,
                    "follow": False,
                    "tail": max_lines,
                    "since": start_ns // 1_000_000_000,
                    "until": end_ns // 1_000_000_000 + 1,
                },
                stream=True,
                timeout=(timeout, min(timeout, 0.5)),
            )
            responses.append(response)
            api._raise_for_status(response)
            for raw in response.iter_content(chunk_size=min(4096, max_bytes)):
                if time.monotonic() >= deadline:
                    raise TimeoutError
                chunk = raw[: max_bytes - byte_count]
                byte_count += len(chunk)
                for stream, payload in frames.feed(chunk):
                    for value in payload:
                        if value == 10:
                            line_done(stream)
                            if line_count >= max_lines:
                                truncated = True
                                break
                        elif stream not in oversized:
                            if len(pending[stream]) >= MAX_LINE_BYTES:
                                pending[stream].clear()
                                oversized.add(stream)
                            else:
                                pending[stream].append(value)
                    if truncated:
                        break
                if byte_count >= max_bytes:
                    truncated = True
                if truncated:
                    break
            if not truncated:
                if frames.header or frames.remaining:
                    raise ValueError("Incomplete Docker log framing")
                for stream in pending:
                    if pending[stream] or stream in oversized:
                        line_done(stream)
            result = LogReadResult(
                tuple(sorted(hints.values(), key=lambda h: (h.host, h.port or 0, h.signature))),
                "collected",
                byte_count,
                line_count,
                truncated,
            )
        except TimeoutError:
            result = LogReadResult(status="timeout", reason="log_deadline")
        except Exception:
            # Docker/log-driver/network errors may embed bodies, credentials or paths.
            result = LogReadResult(status="unavailable", reason="log_read_failed")
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
        completed.put(result)

    worker = Thread(target=read, name="dockroute-log-tail", daemon=True)
    worker.start()
    try:
        return completed.get(timeout=max(0.001, deadline - time.monotonic()))
    except Empty:
        # Closing can itself block in a third-party transport; keep the caller bounded.
        def close_response() -> None:
            for response in responses:
                try:
                    response.close()
                except Exception:
                    pass

        Thread(target=close_response, name="dockroute-log-close", daemon=True).start()
        return LogReadResult(status="timeout", reason="log_deadline")
