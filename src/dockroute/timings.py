"""Optional response-header telemetry. Values and bodies never enter this collector."""

import math
import re
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterator
from urllib.parse import urlsplit


def normalize_path(path_url: str) -> str:
    path = urlsplit(path_url).path
    path = re.sub(r"^/v[0-9]+\.[0-9]+(?=/)", "", path)
    if path in {
        "/_ping",
        "/version",
        "/info",
        "/containers/json",
        "/containers/create",
        "/networks",
        "/images/json",
    }:
        return path
    if re.fullmatch(r"/containers/[^/]+/(json|logs|start|wait|archive|attach)", path):
        return "/containers/{id}/" + path.rsplit("/", 1)[1]
    if re.fullmatch(r"/containers/[^/]+", path):
        return "/containers/{id}"
    if re.fullmatch(r"/images/[^/]+(?:/[^/]+)*/json", path):
        return "/images/{id}/json"
    return "/other"


class RequestTimings:
    def __init__(self, api: Any = None):
        self.api = api
        self._local = threading.local()
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self._hook = self._record
        self._attached = bool(api is not None and isinstance(getattr(api, "hooks", None), dict))
        if self._attached:
            api.hooks.setdefault("response", []).append(self._hook)

    @contextmanager
    def stage(self, role: str, stage: str) -> Iterator[None]:
        previous = getattr(self._local, "stage", ("project", "inspection"))
        self._local.stage = (role, stage)
        try:
            yield
        finally:
            self._local.stage = previous

    def _record(self, response: Any, *args: Any, **kwargs: Any) -> None:
        try:
            method = response.request.method
            if method not in {"GET", "POST", "DELETE", "HEAD", "PUT"}:
                method = "OTHER"
            elapsed = response.elapsed.total_seconds() * 1000
            if not math.isfinite(elapsed) or elapsed < 0:
                return
            status = response.status_code
            if type(status) is not int or not 100 <= status <= 599:
                return
            role, stage = getattr(self._local, "stage", ("project", "inspection"))
            path = normalize_path(response.request.path_url)
            key = role, stage, method, path
            with self._lock:
                entry = self._entries.setdefault(
                    key,
                    {
                        "role": role,
                        "stage": stage,
                        "method": method,
                        "path": path,
                        "count": 0,
                        "total_ms": 0.0,
                        "max_ms": 0.0,
                        "status_counts": {},
                    },
                )
                entry["count"] += 1
                entry["total_ms"] += elapsed
                entry["max_ms"] = max(entry["max_ms"], elapsed)
                code = str(status)
                entry["status_counts"][code] = entry["status_counts"].get(code, 0) + 1
        except (AttributeError, TypeError, ValueError):
            # Instrumentation cannot turn an otherwise valid response into a failure.
            return

    def count(self, role: str, stage: str) -> int:
        with self._lock:
            return sum(v["count"] for k, v in self._entries.items() if k[:2] == (role, stage))

    def summary(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    **entry,
                    "total_ms": round(entry["total_ms"], 3),
                    "max_ms": round(entry["max_ms"], 3),
                }
                for _, entry in sorted(self._entries.items())
            ]

    def close(self) -> None:
        if self._attached:
            hooks = self.api.hooks.get("response", [])
            if self._hook in hooks:
                hooks.remove(self._hook)
            self._attached = False


def ready_metrics(ready: dict, started_at: str, host_ready_ms: float) -> dict[str, Any]:
    metrics = {key: ready[key] for key in ("import_ms", "ready_ms", "wall_ts") if key in ready}
    metrics.update(
        host_ready_ms=round(host_ready_ms, 3),
        vm_startup_ms=None,
        observation_overhead_ms=None,
        derived=True,
    )
    try:
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        if started.tzinfo is not None and "wall_ts" in ready:
            vm_ms = (ready["wall_ts"] - started.timestamp()) * 1000
            if math.isfinite(vm_ms) and vm_ms >= 0:
                metrics["vm_startup_ms"] = round(vm_ms, 3)
                metrics["observation_overhead_ms"] = round(max(0.0, host_ready_ms - vm_ms), 3)
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    return metrics
