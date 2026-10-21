"""Small, strict worker wire protocol. Do not echo untrusted output on validation errors."""

import ipaddress
import json
import math

PROBE_STATES = frozenset(
    {
        "SUCCESS",
        "DNS_FAILURE",
        "TCP_REFUSED",
        "TCP_TIMEOUT",
        "HELPER_IMAGE_UNAVAILABLE",
        "HELPER_CREATE_FAILED",
        "HELPER_START_FAILED",
        "HELPER_EXECUTION_FAILED",
        "HELPER_TIMEOUT",
        "INVALID_WORKER_OUTPUT",
        "UNKNOWN",
    }
)
INFRASTRUCTURE_FAILURES = PROBE_STATES - {
    "SUCCESS",
    "DNS_FAILURE",
    "TCP_REFUSED",
    "TCP_TIMEOUT",
    "UNKNOWN",
}
_READY_KEYS = {"event", "worker_schema", "import_ms", "ready_ms", "wall_ts"}
_TIMING_FIELDS = {"import_ms", "ready_ms", "wall_ts", "execution_ms", "dns_ms", "tcp_ms"}
_RESULT_KEYS = {
    "event",
    "worker_schema",
    "state",
    "dns",
    "tcp",
    "addresses",
    "dns_equivalent",
    "listener_addresses",
    "listener_verified",
    "timeout_stage",
    "error_type",
    "execution_ms",
    "dns_ms",
    "tcp_ms",
}


class InvalidWorkerOutput(ValueError):
    pass


def worker_frames(output: bytes) -> list[dict]:
    if len(output) > 65536:
        raise InvalidWorkerOutput("Worker output exceeds the protocol limit")
    frames: list[dict] = []
    try:
        for line in output.decode("utf-8").splitlines():
            if not line.strip():
                continue
            frame = json.loads(line)
            if not isinstance(frame, dict) or frame.get("worker_schema") not in ("1", "2"):
                raise ValueError()
            if frame.get("event") == "ready":
                if set(frame) - _READY_KEYS or frames:
                    raise ValueError()
            elif frame.get("event") == "result":
                if set(frame) - _RESULT_KEYS or not frames or frames[0]["event"] != "ready":
                    raise ValueError()
                if frame["worker_schema"] != frames[0]["worker_schema"]:
                    raise ValueError()
            else:
                raise ValueError()
            for field in _TIMING_FIELDS & set(frame):
                value = frame[field]
                if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                    raise ValueError()
                if field == "wall_ts" and value <= 0:
                    raise ValueError()
            frames.append(frame)
            if len(frames) > 2:
                raise ValueError()
    except (ValueError, OverflowError, UnicodeError):
        raise InvalidWorkerOutput(
            "Worker output does not conform to the ready/result protocol"
        ) from None
    return frames


def decode_worker_output(output: bytes, mode: str) -> dict:
    frames = worker_frames(output)
    if len(frames) != 2 or frames[-1]["event"] != "result":
        raise InvalidWorkerOutput("Worker did not provide a complete result")
    result = frames[-1]
    for field in ("state", "dns", "tcp", "timeout_stage", "error_type"):
        value = result.get(field)
        if value is not None and not isinstance(value, str):
            raise InvalidWorkerOutput("Invalid worker field type")
    if result.get("state") not in {
        "SUCCESS",
        "DNS_FAILURE",
        "TCP_REFUSED",
        "TCP_TIMEOUT",
        "HELPER_TIMEOUT",
        "HELPER_EXECUTION_FAILED",
        "UNKNOWN",
    }:
        raise InvalidWorkerOutput("Invalid worker state")
    for field in ("addresses", "listener_addresses"):
        addresses = result.get(field, [])
        if not isinstance(addresses, list) or len(addresses) > 64:
            raise InvalidWorkerOutput("Invalid address observations")
        try:
            for address in addresses:
                if not isinstance(address, str):
                    raise ValueError()
                ipaddress.ip_address(address)
        except ValueError:
            raise InvalidWorkerOutput("Invalid address observations") from None
    if (
        "dns_equivalent" in result
        and result["dns_equivalent"] is not None
        and type(result["dns_equivalent"]) is not bool
    ):
        raise InvalidWorkerOutput("Invalid resolver comparison")
    if "listener_verified" in result and type(result["listener_verified"]) is not bool:
        raise InvalidWorkerOutput("Invalid listener observation")
    if result.get("timeout_stage") not in {None, "dns", "tcp", "listener", "execution"}:
        raise InvalidWorkerOutput("Invalid timeout stage")
    if result.get("error_type") not in {None, "OSError", "ValueError", "TimeoutError"}:
        raise InvalidWorkerOutput("Invalid worker error category")
    if mode == "connect":
        if result.get("dns") not in {"ok", "failed", "timeout", "unknown"} or result.get(
            "tcp"
        ) not in {
            "ok",
            "refused",
            "timeout",
            "blocked",
            "unknown",
        }:
            raise InvalidWorkerOutput("Missing or invalid DNS/TCP observations")
        expected = {
            "SUCCESS": ("ok", "ok"),
            "DNS_FAILURE": ("failed", "unknown"),
            "TCP_REFUSED": ("ok", "refused"),
            "TCP_TIMEOUT": ("ok", "timeout"),
        }
        if result["state"] == "DNS_FAILURE" and result["dns"] == "timeout":
            if result["tcp"] != "unknown" or result.get("timeout_stage") != "dns":
                raise InvalidWorkerOutput("DNS timeout contradicts its observations")
            return result
        if (
            result["state"] in expected
            and (result["dns"], result["tcp"]) != expected[result["state"]]
        ):
            raise InvalidWorkerOutput("Worker state contradicts its observations")
    elif mode == "listen":
        if result["state"] not in {
            "SUCCESS",
            "HELPER_TIMEOUT",
            "HELPER_EXECUTION_FAILED",
            "UNKNOWN",
        }:
            raise InvalidWorkerOutput("Invalid listener state")
        if "listener_verified" not in result:
            raise InvalidWorkerOutput("Missing listener observation")
        if result["state"] == "SUCCESS" and not result["listener_verified"]:
            raise InvalidWorkerOutput("Worker state contradicts listener verification")
    else:
        raise InvalidWorkerOutput("Invalid worker mode")
    return result
