"""Opt-in SDK helpers with explicit stages, independent deadlines and owned cleanup."""

import hashlib
import io
import json
import re
import tarfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from docker.errors import ImageNotFound, NotFound
from docker.types import LogConfig
from requests.exceptions import Timeout
from urllib3.exceptions import TimeoutError as TransportTimeout

from dockroute.compose import parse_labels
from dockroute.discovery import resolve_hostname, shared_networks
from dockroute.models import Connection, Container, Finding, ProbeResult, ProbeTrace
from dockroute.probe_protocol import (
    INFRASTRUCTURE_FAILURES,
    InvalidWorkerOutput,
    decode_worker_output,
    worker_frames,
)

if TYPE_CHECKING:
    from dockroute.benchmark_control import BenchmarkControl

_ERROR_NAMES = {
    "APIError",
    "ImageNotFound",
    "NotFound",
    "ReadTimeout",
    "ConnectTimeout",
    "ConnectionError",
    "TimeoutError",
    "OSError",
    "FileNotFoundError",
    "PermissionError",
    "ValueError",
    "JSONDecodeError",
    "UnicodeDecodeError",
    "InvalidWorkerOutput",
    "RuntimeError",
}
_STDERR_NAMES = re.compile(
    r"\b(SyntaxError|ModuleNotFoundError|ImportError|RuntimeError|ValueError|TypeError|PermissionError|TimeoutError|MemoryError)\b"
)


def _error_type(exc):
    name = type(exc).__name__
    return name if name in _ERROR_NAMES else "Exception"


def _is_timeout(exc):
    """Named-pipe requests can wrap read timeouts in ConnectionError."""
    pending = [exc]
    visited: set[int] = set()
    while pending and len(visited) < 16:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, (Timeout, TimeoutError, TransportTimeout)):
            return True
        pending.extend(
            x
            for x in (current.__cause__, current.__context__, *current.args)
            if isinstance(x, BaseException)
        )
    return False


def _stderr_summary(output):
    """Recognized exception categories only; no raw source lines, paths or values."""
    if not output:
        return ""
    names = sorted(set(_STDERR_NAMES.findall(output[:65536].decode("utf-8", errors="replace"))))
    category = ", ".join(names) if names else "text"
    return f"Worker stderr omitted ({len(output)} bytes; categories: {category})."


def _identifier(value):
    return value if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value or "") else "[identifier omitted]"


class ProbeCleanupError(RuntimeError):
    def __init__(self, message, *, trace=()):
        super().__init__(message)
        self.trace = tuple(trace)


class _Failure(Exception):
    def __init__(self, state, stage):
        self.state, self.stage = state, stage


@dataclass
class _Execution:
    data: dict
    state: str
    failure_stage: str | None = None


def _read_config_file(container, filename):
    chunks, _ = container.get_archive("/etc/" + filename)
    data = bytearray()
    for chunk in chunks:
        data.extend(chunk)
        if len(data) > 256 * 1024:
            raise ValueError("oversized DNS archive")
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            if member.isfile() and member.name.split("/")[-1] == filename and member.size <= 65536:
                stream = archive.extractfile(member)
                if stream:
                    return stream.read(65537).decode("utf-8")
    raise ValueError("DNS file unavailable")


class Prober:
    def __init__(
        self,
        client,
        project: str,
        *,
        timeout=5.0,
        startup_timeout=15.0,
        image="python:3.12-alpine",
        engine_os="linux",
        timings=False,
        observe="poll",
        schedule="conditional",
        dns_timeout=2.0,
        connect_timeout=1.0,
    ):
        self.client, self.project = client, project
        self.timeout, self.startup_timeout = timeout, startup_timeout
        self.image, self.engine_os = image, engine_os
        self._image_id: str | None = None
        self.execution_id = uuid.uuid4().hex
        self.observe, self.schedule = observe, schedule
        self.dns_timeout, self.connect_timeout = dns_timeout, connect_timeout
        self._timing = None
        self._request_seen: dict[tuple[str, str], int] = {}
        self.benchmark_control: BenchmarkControl | None = None
        if timings:
            from dockroute.timings import RequestTimings

            self._timing = (
                RequestTimings(getattr(client, "api", None)) if timings is True else timings
            )
        self.cpu_limit = 0.25

    def close(self):
        if self._timing:
            self._timing.close()

    def request_summary(self):
        return self._timing.summary() if self._timing else []

    def _call(self, function, role, stage, budget=None):
        if self._timing:
            with self._timing.stage(role, stage):
                return self._request(function, budget)
        return self._request(function, budget)

    def _request(self, function, budget=None):
        api = getattr(self.client, "api", None)
        if api is None or not hasattr(api, "timeout"):
            return function()
        lock = api.__dict__.setdefault("_dockroute_request_lock", threading.RLock())
        deadline = time.monotonic() + max(0.01, budget) if budget is not None else None
        acquired = (
            lock.acquire()
            if deadline is None
            else lock.acquire(timeout=max(0, deadline - time.monotonic()))
        )
        if not acquired:
            raise Timeout("API request deadline expired before acquiring the request gate")
        try:
            if deadline is not None and time.monotonic() >= deadline:
                raise Timeout("API request deadline expired before the request")
            original = api.timeout
            if deadline is not None:
                api.timeout = min(original, max(0.01, min(budget, deadline - time.monotonic())))
            try:
                return function()
            finally:
                api.timeout = original
        finally:
            lock.release()

    def _record(self, trace, role, stage, started, state="SUCCESS", elapsed_ms=None, **details):
        if self._timing:
            count = self._timing.count(role, stage)
            previous = self._request_seen.get((role, stage), 0)
            self._request_seen[(role, stage)] = count
            details["timings"] = {
                "polls": 0,
                "empty_polls": 0,
                "reloads": 0,
                **(details.get("timings") or {}),
                "http_requests": count - previous,
            }
        details.setdefault("observe_mode", self.observe)
        trace.append(
            ProbeTrace(
                role,
                stage,
                state,
                round((time.monotonic() - started) * 1000, 3)
                if elapsed_ms is None
                else round(elapsed_ms, 3),
                **details,
            )
        )

    def _operation(
        self, trace, role, stage, function, failure_state, *, budget=None, configuration=None
    ):
        started = time.monotonic()
        try:
            result = self._call(function, role, stage, budget)
        except Exception as exc:
            timeout = _is_timeout(exc)
            state = (
                "HELPER_TIMEOUT"
                if timeout
                else "HELPER_IMAGE_UNAVAILABLE"
                if stage == "create" and isinstance(exc, ImageNotFound)
                else failure_state
            )
            self._record(
                trace,
                role,
                stage,
                started,
                state,
                error_type=_error_type(exc),
                timeout_kind="api_request" if timeout else None,
                helper_configuration=configuration,
            )
            raise _Failure(state, stage) from None
        self._record(trace, role, stage, started, helper_configuration=configuration)
        return result

    def _live(self, identifier):
        container = self.client.containers.get(identifier)
        identity = parse_labels((container.attrs.get("Config") or {}).get("Labels") or {})
        state = container.attrs.get("State") or {}
        mode = (container.attrs.get("HostConfig") or {}).get("NetworkMode", "")
        if (
            not identity
            or identity.project != self.project
            or not state.get("Running")
            or state.get("Paused")
            or mode in {"host", "none"}
            or mode.startswith("container:")
        ):
            raise ValueError("Selected namespace is unavailable")
        return container

    @staticmethod
    def _owned(helper, labels):
        actual = (helper.attrs.get("Config") or {}).get("Labels") or {}
        return all(actual.get(k) == v for k, v in labels.items())

    def _stderr(self, helper, role="source", stage="execution"):
        try:
            return _stderr_summary(
                self._call(lambda: helper.logs(stdout=False, stderr=True, tail=8), role, stage)
            )
        except Exception:
            return "Worker stderr retrieval unavailable."

    def _cleanup(self, helper, name, labels, attempted_create, trace, role):
        started = time.monotonic()
        try:
            if helper is None and attempted_create:
                try:
                    helper = self._call(lambda: self.client.containers.get(name), role, "cleanup")
                except NotFound:
                    pass
            if helper is not None:
                if not self._owned(helper, labels):
                    self._record(
                        trace, role, "cleanup", started, "UNKNOWN", cleanup="ownership_unconfirmed"
                    )
                    raise ProbeCleanupError(
                        f"Ownership of temporary helper {_identifier(helper.id)} was not confirmed; nothing was removed.",
                        trace=trace,
                    )
                self._call(lambda: helper.remove(force=True), role, "cleanup")
            self._record(
                trace, role, "cleanup", started, cleanup="removed" if helper else "not_needed"
            )
        except ProbeCleanupError:
            raise
        except Exception as exc:
            self._record(
                trace,
                role,
                "cleanup",
                started,
                "UNKNOWN",
                error_type=_error_type(exc),
                cleanup="failed",
            )
            identifier = _identifier(helper.id if helper else name)
            raise ProbeCleanupError(
                f"Cleanup of temporary helper {identifier} could not be completed. Inspect only this execution's io.dockroute.execution={self.execution_id} helpers after Docker reconnects.",
                trace=trace,
            ) from None

    def _ready(self, helper, mode, trace, role):
        started = time.monotonic()
        deadline = started + self.startup_timeout
        counters = {"polls": 0, "empty_polls": 0, "reloads": 0}

        def observed(ready, recovered=False):
            elapsed = (time.monotonic() - started) * 1000
            metrics = dict(counters)
            if self._timing:
                from dockroute.timings import ready_metrics

                inspected = time.monotonic()
                try:
                    self._call(helper.reload, role, "timing_inspect")
                    stamp = (helper.attrs.get("State") or {}).get("StartedAt", "")
                    self._record(trace, role, "timing_inspect", inspected, timings={"reloads": 1})
                except Exception as exc:
                    stamp = ""
                    self._record(
                        trace,
                        role,
                        "timing_inspect",
                        inspected,
                        "UNKNOWN",
                        error_type=_error_type(exc),
                    )
                metrics = {**ready_metrics(ready, stamp, elapsed), **counters}
            self._record(
                trace,
                role,
                "worker_startup",
                started,
                recovered=recovered,
                timings=metrics,
                elapsed_ms=elapsed,
            )
            return ready

        try:
            while True:
                counters["polls"] += 1
                output = self._call(
                    lambda: helper.logs(stdout=True, stderr=False, tail=4),
                    role,
                    "worker_startup",
                    deadline - time.monotonic(),
                )
                frames = worker_frames(output)
                if frames and frames[0]["event"] == "ready":
                    return observed(frames[0])
                counters["empty_polls"] += 1
                self._call(helper.reload, role, "worker_startup", deadline - time.monotonic())
                counters["reloads"] += 1
                state = helper.attrs.get("State") or {}
                if state.get("Status") in {"exited", "dead"}:
                    if state.get("ExitCode") == 0:
                        # The worker can finish between the logs and inspect requests.
                        final = self._call(
                            lambda: helper.logs(stdout=True, stderr=False, tail=4),
                            role,
                            "worker_startup",
                            deadline - time.monotonic(),
                        )
                        decode_worker_output(final, mode)
                        return observed(worker_frames(final)[0], recovered=True)
                    self._record(
                        trace,
                        role,
                        "worker_startup",
                        started,
                        "HELPER_EXECUTION_FAILED",
                        exit_code=state.get("ExitCode"),
                        stderr=self._stderr(helper, role, "worker_startup"),
                        timings=counters,
                    )
                    raise _Failure("HELPER_EXECUTION_FAILED", "worker_startup")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._record(
                        trace,
                        role,
                        "worker_startup",
                        started,
                        "HELPER_TIMEOUT",
                        timeout_kind="worker_startup",
                        timings=counters,
                    )
                    raise _Failure("HELPER_TIMEOUT", "worker_startup")
                time.sleep(min(0.1, remaining))
        except _Failure:
            raise
        except Exception as exc:
            state = (
                "INVALID_WORKER_OUTPUT"
                if isinstance(exc, InvalidWorkerOutput)
                else "HELPER_TIMEOUT"
                if _is_timeout(exc)
                else "HELPER_EXECUTION_FAILED"
            )
            self._record(
                trace,
                role,
                "worker_startup",
                started,
                state,
                error_type=_error_type(exc),
                stderr=self._stderr(helper, role, "worker_startup"),
                timings=counters,
                timeout_kind="api_request" if _is_timeout(exc) else None,
            )
            raise _Failure(state, "worker_startup") from None

    def _finished(self, helper, mode, trace, role):
        started = time.monotonic()
        error, recovered = None, False
        try:
            outcome = self._call(lambda: helper.wait(timeout=self.timeout + 2), role, "execution")
            exit_code = outcome.get("StatusCode")
            if outcome.get("Error"):
                exit_code = None
        except Exception as exc:
            error = exc
            try:
                self._call(helper.reload, role, "execution")
                state = helper.attrs.get("State") or {}
                if state.get("Status") == "exited":
                    exit_code = state.get("ExitCode")
                    recovered = exit_code == 0
                else:
                    exit_code = None
            except Exception:
                exit_code = None
        if exit_code != 0:
            state = "HELPER_TIMEOUT" if error and _is_timeout(error) else "HELPER_EXECUTION_FAILED"
            self._record(
                trace,
                role,
                "execution",
                started,
                state,
                exit_code=exit_code,
                error_type=_error_type(error) if error else None,
                timeout_kind="worker_execution" if state == "HELPER_TIMEOUT" else None,
                stderr=self._stderr(helper, role, "execution"),
            )
            raise _Failure(state, "execution")
        self._record(
            trace,
            role,
            "execution",
            started,
            exit_code=exit_code,
            recovered=recovered,
            error_type=_error_type(error) if error else None,
            timeout_kind="api_request" if recovered and _is_timeout(error) else None,
        )
        output = self._operation(
            trace,
            role,
            "logs",
            lambda: helper.logs(stdout=True, stderr=False, tail=4),
            "HELPER_EXECUTION_FAILED",
        )
        started = time.monotonic()
        try:
            result = decode_worker_output(output, mode)
        except InvalidWorkerOutput as exc:
            self._record(
                trace,
                role,
                "result_parsing",
                started,
                "INVALID_WORKER_OUTPUT",
                error_type=_error_type(exc),
                stderr=self._stderr(helper, role, "result_parsing"),
            )
            raise _Failure("INVALID_WORKER_OUTPUT", "result_parsing") from None
        self._record(
            trace,
            role,
            "result_parsing",
            started,
            result["state"],
            timings={k: result[k] for k in ("execution_ms", "dns_ms", "tcp_ms") if k in result},
            timeout_kind="worker_" + result["timeout_stage"]
            if result.get("timeout_stage")
            else None,
        )
        return result

    def _helper(self, target_id, payload, trace, role):
        helper, attempted_create = None, False
        token = uuid.uuid4().hex
        name = "dockroute-probe-" + token
        labels = {
            "io.dockroute.helper": "true",
            "io.dockroute.project": self.project,
            "io.dockroute.run": token,
            "io.dockroute.execution": self.execution_id,
        }
        try:
            program = self._operation(
                trace,
                role,
                "worker_script",
                lambda: Path(__file__).with_name("_probe_worker.py").read_text(encoding="utf-8"),
                "HELPER_EXECUTION_FAILED",
            )
            configuration = {
                "image": self._image_id or "[configured local image]",
                "network_mode": "container:" + _identifier(target_id),
                "entrypoint": ["python", "-I", "-c", "[embedded worker]"],
                "worker_sha256": hashlib.sha256(program.encode()).hexdigest(),
                "read_only": True,
                "cap_drop": ["ALL"],
                "memory_bytes": 134217728,
                "pids_limit": 32,
                "cpu_limit": self.cpu_limit,
                "helper_name": name,
                "execution_id": self.execution_id,
                "mode": payload["mode"],
            }
            if self.benchmark_control:
                self._operation(
                    trace,
                    role,
                    "benchmark_control",
                    lambda: self.benchmark_control.note_helper(name, labels),
                    "HELPER_EXECUTION_FAILED",
                )
            attempted_create = True
            helper = self._operation(
                trace,
                role,
                "create",
                lambda: self.client.containers.create(
                    self._image_id or self.image,
                    entrypoint=["python", "-I", "-c", program],
                    command=[
                        json.dumps(
                            {
                                **payload,
                                "timeout": self.timeout,
                                "dns_timeout": self.dns_timeout,
                                "connect_timeout": self.connect_timeout,
                            }
                        )
                    ],
                    name=name,
                    network_mode="container:" + target_id,
                    labels=labels,
                    detach=True,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    read_only=True,
                    user="0:0",
                    mem_limit="128m",
                    pids_limit=32,
                    nano_cpus=int(self.cpu_limit * 1_000_000_000),
                    restart_policy={"Name": "no"},
                    use_config_proxy=False,
                    log_config=LogConfig(
                        type="json-file", config={"max-size": "64k", "max-file": "1"}
                    ),
                ),
                "HELPER_CREATE_FAILED",
                configuration=configuration,
            )
            image_id = (helper.attrs or {}).get("Image")
            if (
                not isinstance(image_id, str)
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id)
                or (self._image_id is not None and image_id != self._image_id)
            ):
                self._record(
                    trace,
                    role,
                    "create",
                    time.monotonic(),
                    "HELPER_CREATE_FAILED",
                    error_type="ValueError",
                    helper_configuration=configuration,
                )
                raise _Failure("HELPER_CREATE_FAILED", "create")
            self._image_id = image_id
            configuration["image"] = image_id
            self._operation(
                trace,
                role,
                "start",
                helper.start,
                "HELPER_START_FAILED",
                budget=self.startup_timeout,
            )
            self._ready(helper, payload["mode"], trace, role)
            result = self._finished(helper, payload["mode"], trace, role)
            state = result["state"]
            return _Execution(
                result, state, "execution" if state in INFRASTRUCTURE_FAILURES else None
            )
        except _Failure as failure:
            return _Execution({}, failure.state, failure.stage)
        finally:
            self._cleanup(helper, name, labels, attempted_create, trace, role)

    def check(
        self,
        edge: Connection,
        containers: list[Container],
        *,
        static_finding: Finding | Callable[[], Finding] | None = None,
    ) -> ProbeResult:
        trace: list[ProbeTrace] = []

        def result(**kwargs):
            return ProbeResult(
                trace=tuple(trace),
                execution_id=self.execution_id,
                startup_timeout=self.startup_timeout,
                execution_timeout=self.timeout,
                dns_timeout=self.dns_timeout,
                connect_timeout=self.connect_timeout,
                **kwargs,
            )

        selected = [c for c in containers if c.project == self.project]
        source = next((c for c in selected if c.id == edge.source_id), None)
        destinations = resolve_hostname(edge.host, selected)
        if not source or edge.port is None:
            return result(notes=("No probe: source or destination port is unconfirmed.",))
        if self.engine_os != "linux":
            return result(
                state="HELPER_EXECUTION_FAILED",
                failure_stage="engine_prerequisite",
                notes=("Linux Engine containers are required for namespace/listener helpers.",),
            )
        if len(destinations) > 1 or (not destinations and not edge.explicit):
            return result(
                notes=(
                    "Automatic probing is restricted to unambiguous selected-project destinations.",
                )
            )
        destination = destinations[0] if destinations else None
        try:
            live_source = self._operation(
                trace,
                "source",
                "namespace",
                lambda: self._live(source.id),
                "HELPER_EXECUTION_FAILED",
            )
        except _Failure as failure:
            return result(
                state=failure.state,
                failure_stage=failure.stage,
                notes=("Selected source network namespace is unavailable.",),
            )
        started = time.monotonic()
        dns_files, notes = {}, []
        try:
            dns_files = {
                name: self._call(
                    lambda name=name: _read_config_file(live_source, name),
                    "source",
                    "resolver_snapshot",
                )
                for name in ("resolv.conf", "hosts")
            }
            self._record(trace, "source", "resolver_snapshot", started)
        except Exception as exc:
            self._record(
                trace,
                "source",
                "resolver_snapshot",
                started,
                "UNKNOWN",
                error_type=_error_type(exc),
            )
            notes.append("Source resolver snapshots unavailable; resolver comparison is unknown.")
        allowed = None
        if not edge.explicit:
            assert destination is not None
            allowed = [
                address
                for network in destination.networks.values()
                if network.name in shared_networks(source, destination)
                for address in network.addresses
            ]
        execution = self._helper(
            source.id,
            {
                "mode": "connect",
                "host": edge.host,
                "port": edge.port,
                "dns_files": dns_files,
                "allowed_ips": allowed,
            },
            trace,
            "source",
        )
        if execution.state in INFRASTRUCTURE_FAILURES:
            data = execution.data
            return result(
                state=execution.state,
                failure_stage=execution.failure_stage,
                dns=data.get("dns", "unknown"),
                tcp=data.get("tcp", "unknown"),
                addresses=tuple(data.get("addresses", [])),
                dns_equivalent=data.get("dns_equivalent") if len(dns_files) == 2 else None,
                notes=tuple(notes)
                + (
                    f"Active probe could not complete at {execution.failure_stage}: {execution.state}.",
                )
                + (
                    ("Helper image must be available locally; no image is pulled automatically.",)
                    if execution.state == "HELPER_IMAGE_UNAVAILABLE"
                    else ()
                ),
            )
        data = execution.data
        comparison = data.get("dns_equivalent") if len(dns_files) == 2 else None
        if comparison is None:
            notes.append(
                "Resolver comparison unavailable; application DNS equivalence was not established."
            )
        elif not comparison:
            notes.append(
                "Helper resolver files differ from the source; hostname outcomes cannot be attributed to the source."
            )
        if data.get("tcp") == "blocked":
            notes.append(
                "Resolved addresses were outside allowed project addresses; no TCP connection was attempted."
            )
        listener = _Execution({}, "UNKNOWN")
        skip_reason = None
        if destination and self.schedule == "conditional":
            from dockroute.diagnostics import diagnose

            provisional = result(
                dns=data.get("dns", "unknown"),
                tcp=data.get("tcp", "unknown"),
                dns_equivalent=comparison,
                state=execution.state,
            )
            static = (
                static_finding()
                if callable(static_finding)
                else static_finding
                if static_finding is not None
                else diagnose(edge, selected)
            )
            active = diagnose(edge, selected, provisional)
            if static.code == "NETWORK_ISOLATION":
                skip_reason = "Static network isolation is definitive; destination listeners cannot change this diagnosis."
            elif (
                data.get("tcp") == "ok"
                and active.code in {"TCP_REACHABLE", "SERVICE_UNHEALTHY"}
                and active.verification == "active"
            ):
                skip_reason = "Source TCP connectivity is verified; destination listeners cannot change this diagnosis."
            if skip_reason:
                started = time.monotonic()
                notes.append("Destination listener inspection skipped: " + skip_reason)
                self._record(trace, "destination", "listener_skipped", started, "SKIPPED")
        if destination and not skip_reason:
            try:
                self._operation(
                    trace,
                    "destination",
                    "namespace",
                    lambda: self._live(destination.id),
                    "HELPER_EXECUTION_FAILED",
                )
                listener = self._helper(
                    destination.id, {"mode": "listen", "port": edge.port}, trace, "destination"
                )
            except _Failure as failure:
                listener = _Execution({}, failure.state, failure.stage)
            if listener.state in INFRASTRUCTURE_FAILURES:
                notes.append(
                    f"Destination listener inspection unavailable at {listener.failure_stage}: {listener.state}."
                )
        return result(
            dns=data.get("dns", "unknown"),
            tcp=data.get("tcp", "unknown"),
            addresses=tuple(data.get("addresses", [])),
            dns_equivalent=comparison,
            listener_addresses=tuple(listener.data.get("listener_addresses", [])),
            listener_verified=listener.data.get("listener_verified", False),
            state=execution.state,
            listener_state=listener.state,
            failure_stage=listener.failure_stage,
            listener_skipped=skip_reason is not None,
            listener_skip_reason=skip_reason,
            notes=tuple(notes),
        )
