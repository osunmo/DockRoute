import builtins
import json
import math
import runpy
import socket
import time
from pathlib import Path

import pytest

from dockroute import _probe_worker as worker
from dockroute.probe_protocol import InvalidWorkerOutput, decode_worker_output, worker_frames


def encoded_frames(ready=None, result=None, schema="2"):
    return (
        json.dumps({"event": "ready", "worker_schema": schema, **(ready or {})})
        + "\n"
        + json.dumps(
            {
                "event": "result",
                "worker_schema": schema,
                "state": "SUCCESS",
                "dns": "ok",
                "tcp": "ok",
                **(result or {}),
            }
        )
    ).encode()


def test_protocol_two_preserves_optional_worker_timings():
    ready = {"import_ms": 4.0, "ready_ms": 5, "wall_ts": 1_800_000_000.25}
    result = {"execution_ms": 20.0, "dns_ms": 3, "tcp_ms": 15.5}
    output = encoded_frames(ready, result)
    assert worker_frames(output)[0] == {"event": "ready", "worker_schema": "2", **ready}
    assert decode_worker_output(output, "connect")["execution_ms"] == 20.0
    assert decode_worker_output(output, "connect")["dns_ms"] == 3
    assert decode_worker_output(output, "connect")["tcp_ms"] == 15.5


@pytest.mark.parametrize("schema", ["1", "2"])
def test_legacy_and_current_protocol_work_without_optional_timings(schema):
    assert decode_worker_output(encoded_frames(schema=schema), "connect")["state"] == "SUCCESS"


@pytest.mark.parametrize(
    "field", ["import_ms", "ready_ms", "wall_ts", "execution_ms", "dns_ms", "tcp_ms"]
)
@pytest.mark.parametrize(
    "value", [-1, True, False, None, "1", [], {}, float("nan"), float("inf"), -float("inf")]
)
def test_invalid_optional_timings_are_rejected_before_result_decoding(field, value):
    ready = {field: value} if field in {"import_ms", "ready_ms", "wall_ts"} else {}
    result = {field: value} if field not in {"import_ms", "ready_ms", "wall_ts"} else {}
    with pytest.raises(InvalidWorkerOutput):
        worker_frames(encoded_frames(ready, result))


def test_wall_timestamp_must_be_positive():
    with pytest.raises(InvalidWorkerOutput):
        worker_frames(encoded_frames({"wall_ts": 0}))


def test_ready_and_result_versions_must_match():
    output = encoded_frames().replace(b'"worker_schema": "2"', b'"worker_schema": "1"', 1)
    with pytest.raises(InvalidWorkerOutput):
        worker_frames(output)


@pytest.mark.parametrize("field", ["import_ms", "ready_ms", "execution_ms", "dns_ms", "tcp_ms"])
def test_individual_duration_fields_are_optional_and_allow_zero(field):
    ready = {field: 0} if field in {"import_ms", "ready_ms"} else {}
    result = {field: 0} if field not in {"import_ms", "ready_ms"} else {}
    assert decode_worker_output(encoded_frames(ready, result), "connect")["state"] == "SUCCESS"


@pytest.mark.parametrize("where", ["ready", "result"])
def test_unknown_fields_remain_invalid_in_timed_frames(where):
    ready = {"import_ms": 1}
    result = {"execution_ms": 1}
    (ready if where == "ready" else result)["private_environment"] = "must-not-be-echoed"
    with pytest.raises(InvalidWorkerOutput, match="protocol"):
        worker_frames(encoded_frames(ready, result))


@pytest.mark.parametrize("which", [0, 1])
def test_duplicate_frames_remain_invalid_with_timings(which):
    output = encoded_frames({"ready_ms": 1}, {"execution_ms": 1})
    lines = output.splitlines()
    with pytest.raises(InvalidWorkerOutput):
        worker_frames(output + b"\n" + lines[which])


def test_timing_fields_do_not_bypass_contradictory_state_validation():
    output = encoded_frames({"ready_ms": 1}, {"execution_ms": 1, "tcp": "refused"})
    with pytest.raises(InvalidWorkerOutput, match="contradicts"):
        decode_worker_output(output, "connect")


def test_worker_clock_includes_other_imports_and_emits_execution_timing(monkeypatch, capsys):
    original_import = builtins.__import__

    def delayed_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "errno" and globals and globals.get("__name__") == "__main__":
            time.sleep(0.02)
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", delayed_import)
    payload = {"mode": "listen", "port": 1, "timeout": 1}
    monkeypatch.setattr(worker.sys, "argv", ["worker", json.dumps(payload)])
    if not hasattr(worker.signal, "SIGALRM"):
        # The helper runs on Linux; bypass only its POSIX watchdog on a Windows test host.
        monkeypatch.setattr(worker.signal, "SIGALRM", 14, raising=False)
        monkeypatch.setattr(worker.signal, "ITIMER_REAL", 0, raising=False)
        monkeypatch.setattr(worker.signal, "signal", lambda *args: None)
        monkeypatch.setattr(worker.signal, "setitimer", lambda *args: None, raising=False)
    before = time.time()
    runpy.run_path(str(Path(worker.__file__)), run_name="__main__")
    after = time.time()
    output = capsys.readouterr().out.encode()
    ready, result = worker_frames(output)
    assert ready["worker_schema"] == result["worker_schema"] == "2"
    assert ready["import_ms"] >= 15
    assert ready["ready_ms"] >= ready["import_ms"]
    assert before <= ready["wall_ts"] <= after
    assert math.isfinite(result["execution_ms"]) and result["execution_ms"] >= 0
    assert "dns_ms" not in result and "tcp_ms" not in result
    assert decode_worker_output(output, "listen")["state"] in {"SUCCESS", "UNKNOWN"}


def test_dns_failure_records_elapsed_time_without_measuring_tcp(monkeypatch):
    def missing(*args, **kwargs):
        time.sleep(0.02)
        raise socket.gaierror(socket.EAI_NONAME, "not found")

    monkeypatch.setattr(worker.socket, "getaddrinfo", missing)
    result = worker.tcp_check("missing", 8000, 1)
    assert result["dns"] == "failed" and result["tcp"] == "unknown"
    assert result["dns_ms"] >= 15
    assert "tcp_ms" not in result


def test_successful_tcp_probe_records_dns_and_tcp_elapsed_time():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        result = worker.tcp_check("127.0.0.1", server.getsockname()[1], 1, ["127.0.0.1"])
    assert result["dns"] == "ok" and result["tcp"] == "ok"
    assert math.isfinite(result["dns_ms"]) and result["dns_ms"] >= 0
    assert math.isfinite(result["tcp_ms"]) and result["tcp_ms"] >= 0
