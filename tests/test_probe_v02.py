import json
from types import SimpleNamespace

import pytest
from test_core import node
from test_probes import FakeClient

from dockroute.diagnostics import diagnose
from dockroute.models import Connection, ProbeResult
from dockroute.probes import Prober
from dockroute.reporting import make_report, render_json, render_terminal

READY = {"event": "ready", "worker_schema": "1"}


def frames(**changes):
    return (
        json.dumps(READY)
        + "\n"
        + json.dumps(
            {
                "event": "result",
                "worker_schema": "1",
                "state": "SUCCESS",
                "dns": "ok",
                "tcp": "ok",
                "addresses": ["172.20.0.2"],
                "dns_equivalent": True,
                **changes,
            }
        )
    ).encode()


class StageClient(FakeClient):
    def __init__(self, failure=None):
        super().__init__(failure)
        self.live_helpers = {}
        self.wait_limits = []
        self.created_tokens = []

    def create(self, image, **config):
        if self.failure == "create":
            from docker.errors import APIError

            raise APIError("https://u:secret@engine?token=secret")
        self.created.append(config)
        mode = json.loads(config["command"][-1])["mode"]
        helper_id = "helper-" + mode
        self.created_tokens.append(config["labels"])
        payload = (
            {"dns": "ok", "tcp": "ok", "addresses": ["172.20.0.2"], "dns_equivalent": True}
            if mode == "connect"
            else {"listener_addresses": ["0.0.0.0"], "listener_verified": True}
        )
        result = {"event": "result", "worker_schema": "1", "state": "SUCCESS", **payload}
        exit_code = 7 if self.failure == "execution" else 0
        state = {"Status": "exited", "Running": False, "ExitCode": exit_code}
        attrs = {
            "Image": "sha256:" + "a" * 64,
            "Config": {"Labels": config["labels"]},
            "State": state,
        }

        def start():
            if self.failure == "start":
                raise RuntimeError("secret stderr")

        def wait(**kwargs):
            self.wait_limits.append(kwargs["timeout"])
            if self.failure == "wait_completed":
                from requests.exceptions import ConnectionError

                raise ConnectionError(TimeoutError("secret response"))
            if self.failure == "timeout":
                attrs["State"] = {"Status": "running", "Running": True, "ExitCode": 0}
                raise TimeoutError()
            if self.failure == "cancel":
                raise KeyboardInterrupt()
            return {"StatusCode": exit_code}

        def logs(**kwargs):
            if kwargs.get("stderr") and not kwargs.get("stdout"):
                return b"Traceback: https://alice:secret@db/private?token=secret\nAPI_KEY=secret\nRuntimeError"
            if self.failure == "invalid":
                return b"not JSON; secret=never-show"
            if self.failure == "no_ready":
                attrs["State"] = {"Status": "running", "Running": True, "ExitCode": 0}
                return b""
            return (json.dumps(READY) + "\n" + json.dumps(result) + "\n").encode()

        def remove(**kwargs):
            if self.failure == "cleanup":
                raise RuntimeError("secret cleanup error")
            self.removed.append(helper_id)

        helper = SimpleNamespace(
            id=helper_id,
            attrs=attrs,
            start=start,
            wait=wait,
            logs=logs,
            reload=lambda: None,
            remove=remove,
        )
        self.live_helpers[helper_id] = helper
        return helper

    def get(self, identifier):
        if identifier in self.live_helpers:
            return self.live_helpers[identifier]
        if identifier.startswith("dockroute-probe-"):
            from docker.errors import NotFound

            raise NotFound("absent")
        return super().get(identifier)


def execute(client, **options):
    # These lifecycle regressions deliberately inspect both helpers. The separate
    # conditional-policy suite verifies the default optimization and diagnoses.
    options.setdefault("schedule", "sequential")
    return Prober(client, "shop", **options).check(
        Connection("app-id", "app", "api", 8000), [node("app"), node("api")]
    )


def test_successful_result_survives_lost_wait_response():
    client = StageClient("wait_completed")
    result = execute(client)
    assert result.state == "SUCCESS" and result.tcp == "ok" and result.dns == "ok"
    assert result.listener_verified and len(client.removed) == 2
    assert any(t.stage == "execution" and t.recovered for t in result.trace)


@pytest.mark.parametrize(
    "failure,want",
    [
        ("create", "HELPER_CREATE_FAILED"),
        ("start", "HELPER_START_FAILED"),
        ("execution", "HELPER_EXECUTION_FAILED"),
        ("invalid", "INVALID_WORKER_OUTPUT"),
        ("timeout", "HELPER_TIMEOUT"),
        ("no_ready", "HELPER_TIMEOUT"),
    ],
)
def test_infrastructure_failure_stage_is_explicit_and_never_a_network_timeout(failure, want):
    result = execute(StageClient(failure), startup_timeout=0.01, timeout=0.01)
    assert result.state == want
    assert result.dns_equivalent is None
    finding = diagnose(Connection("app-id", "app", "api", 8000), [node("app"), node("api")], result)
    assert finding.status == "PROBE_UNAVAILABLE" and finding.code == "UNKNOWN"
    assert "use --probe" not in finding.remediation.lower()
    assert result.failure_stage


def test_probe_trace_never_serializes_raw_worker_stderr_or_sensitive_configuration():
    result = execute(StageClient("execution"))
    finding = diagnose(Connection("app-id", "app", "api", 8000), [node("app"), node("api")], result)
    report = make_report("shop", [node("app"), node("api")], [finding], probe=True)
    for rendered in (render_json(report), render_terminal(report, verbose=True)):
        assert "secret" not in rendered and "alice" not in rendered and "API_KEY" not in rendered
        assert "execution" in rendered and "7" in rendered


def test_configurable_startup_timeout_is_separate_from_execution_budget():
    result = execute(StageClient(), startup_timeout=20, timeout=1)
    assert result.state == "SUCCESS"
    assert result.startup_timeout == 20 and result.execution_timeout == 1


def test_concurrent_execution_ownership_never_removes_another_run():
    client = StageClient()
    one, two = Prober(client, "shop"), Prober(client, "shop")
    assert one.execution_id != two.execution_id
    execute(client)
    labels = client.created_tokens
    assert labels[0]["io.dockroute.execution"] == labels[1]["io.dockroute.execution"]
    assert labels[0]["io.dockroute.run"] != labels[1]["io.dockroute.run"]


def test_static_compatible_is_not_verified_reachable():
    edge = Connection("app-id", "app", "api", 8000)
    containers = [node("app"), node("api", health="healthy")]
    static = diagnose(edge, containers)
    assert static.status == "NO_STATIC_ISSUES_FOUND" and static.code == "UNKNOWN"
    active = diagnose(edge, containers, ProbeResult(dns="ok", tcp="ok", dns_equivalent=True))
    assert active.status == "REACHABLE"
    refused = diagnose(edge, containers, ProbeResult(dns="ok", tcp="refused", dns_equivalent=True))
    assert refused.status == "NETWORK_FAILURE"


def test_resolver_comparison_unavailable_is_unknown_not_false(monkeypatch, tmp_path):
    import dockroute._probe_worker as worker
    from dockroute._probe_worker import run

    monkeypatch.setattr(worker, "tcp_check", lambda *a: {"dns": "ok", "tcp": "ok", "addresses": []})
    result = run(
        {"mode": "connect", "host": "api", "port": 8000, "timeout": 1, "dns_files": {}},
        resolver_dir=tmp_path,
    )
    assert result["dns_equivalent"] is None
    result = run(
        {
            "mode": "connect",
            "host": "api",
            "port": 8000,
            "timeout": 1,
            "dns_files": {"hosts": "x", "resolv.conf": "y"},
        },
        resolver_dir=tmp_path,
    )
    assert result["dns_equivalent"] is None


@pytest.mark.parametrize(
    "bad",
    [
        {"state": "SUCCESS", "tcp": "refused"},
        {"dns_equivalent": "secret"},
        {"addresses": ["secret:not-ip"]},
        {"unexpected_environment": "secret"},
    ],
)
def test_invalid_or_contradictory_worker_output_is_not_accepted(bad):
    from dockroute.probe_protocol import InvalidWorkerOutput, decode_worker_output

    payload = {
        "event": "result",
        "worker_schema": "1",
        "state": "SUCCESS",
        "dns": "ok",
        "tcp": "ok",
        **bad,
    }
    output = (json.dumps(READY) + "\n" + json.dumps(payload)).encode()
    with pytest.raises(InvalidWorkerOutput):
        decode_worker_output(output, "connect")


def test_foreign_execution_helper_is_never_removed():
    from dockroute.probes import ProbeCleanupError

    client = StageClient()
    create = client.create

    def foreign(image, **config):
        helper = create(image, **config)
        helper.attrs["Config"]["Labels"] = {
            **config["labels"],
            "io.dockroute.execution": "another-session",
        }
        return helper

    client.containers.create = foreign
    with pytest.raises(ProbeCleanupError, match="nothing was removed"):
        execute(client)
    assert not client.removed


def test_missing_image_reports_prerequisite_failure_without_creating_helpers():
    from docker.errors import ImageNotFound

    client = StageClient()

    def absent(image, **configuration):
        raise ImageNotFound("secret image configuration")

    client.containers.create = absent
    result = execute(client)
    assert result.state == "HELPER_IMAGE_UNAVAILABLE" and result.failure_stage == "create"
    assert result.dns_equivalent is None and not client.created


def test_cancelled_worker_is_owned_and_cleaned():
    client = StageClient("cancel")
    with pytest.raises(KeyboardInterrupt):
        execute(client)
    assert client.removed == ["helper-connect"]


def test_worker_finishing_between_empty_logs_and_inspect_preserves_result():
    client = StageClient()
    create = client.create

    def raced(image, **config):
        helper = create(image, **config)
        logs = helper.logs
        reads = 0

        def snapshot(**kwargs):
            nonlocal reads
            if kwargs.get("stdout"):
                reads += 1
                if reads == 1:
                    return b""
            return logs(**kwargs)

        helper.logs = snapshot
        return helper

    client.containers.create = raced
    result = execute(client)
    assert result.state == "SUCCESS" and result.tcp == "ok"
    assert result.listener_verified and len(client.removed) == 2


@pytest.mark.parametrize("field", ["state", "dns", "tcp", "timeout_stage", "error_type"])
@pytest.mark.parametrize("value", [[], {}])
def test_malformed_worker_field_types_are_structured_failures(field, value):
    from dockroute.probe_protocol import InvalidWorkerOutput, decode_worker_output

    output = frames(**{field: value})
    with pytest.raises(InvalidWorkerOutput):
        decode_worker_output(output, "connect")
    client = StageClient()
    create = client.create

    def malformed(image, **config):
        helper = create(image, **config)
        helper.logs = lambda **kw: output if kw.get("stdout") else b""
        return helper

    client.containers.create = malformed
    result = execute(client)
    assert result.state == "INVALID_WORKER_OUTPUT" and len(client.removed) == 1


def test_dns_watchdog_timeout_is_network_observation_with_unknown_cause(monkeypatch, capsys):
    import dockroute._probe_worker as worker
    from dockroute.probe_protocol import decode_worker_output

    def stalled(payload, observations):
        observations.update(_phase="dns", dns_equivalent=True)
        raise TimeoutError()

    monkeypatch.setattr(worker, "run", stalled)
    monkeypatch.setattr(worker.sys, "argv", ["worker", json.dumps({"timeout": 0.01})])
    monkeypatch.setattr(worker.signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(worker.signal, "ITIMER_REAL", 0, raising=False)
    monkeypatch.setattr(worker.signal, "signal", lambda *a: None)
    monkeypatch.setattr(worker.signal, "setitimer", lambda *a: None, raising=False)
    worker.main()
    data = decode_worker_output(capsys.readouterr().out.encode(), "connect")
    assert data["state"] == "DNS_FAILURE" and data["dns"] == "timeout"
    edge = Connection("app-id", "app", "api", 8000)
    result = ProbeResult(state=data["state"], dns=data["dns"], dns_equivalent=True)
    finding = diagnose(edge, [node("app"), node("api")], result)
    assert finding.status == "NETWORK_FAILURE" and finding.code == "DNS_FAILURE"
    assert "deadline" in finding.explanation and "startup" not in finding.remediation
    unconfirmed = diagnose(
        edge,
        [node("app"), node("api")],
        ProbeResult(state=data["state"], dns=data["dns"], dns_equivalent=None),
    )
    assert unconfirmed.status == "UNKNOWN"


def test_resolver_comparison_preserves_crlf_and_unreadable_text_is_unknown(monkeypatch, tmp_path):
    import dockroute._probe_worker as worker

    monkeypatch.setattr(worker, "tcp_check", lambda *a: {"dns": "ok", "tcp": "ok", "addresses": []})
    files = {"hosts": "127.0.0.1 localhost\r\n", "resolv.conf": "nameserver 127.0.0.11\r\n"}
    for name, content in files.items():
        (tmp_path / name).write_bytes(content.encode())
    payload = {"mode": "connect", "host": "api", "port": 8000, "timeout": 1, "dns_files": files}
    assert worker.run(payload, resolver_dir=tmp_path)["dns_equivalent"] is True
    (tmp_path / "hosts").write_bytes(b"\xff")
    assert worker.run(payload, resolver_dir=tmp_path)["dns_equivalent"] is None
