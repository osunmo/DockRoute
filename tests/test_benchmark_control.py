import json
import threading


def test_private_lease_records_ownership_before_creation_and_never_payloads(tmp_path):
    from dockroute.benchmark_control import BenchmarkControl

    control = BenchmarkControl(tmp_path, "a" * 32, "fresh-project", interrupt=lambda: None)
    labels = {
        "io.dockroute.helper": "true",
        "io.dockroute.project": "fresh-project",
        "io.dockroute.run": "b" * 32,
        "io.dockroute.execution": "a" * 32,
    }
    control.note_helper("dockroute-probe-" + "b" * 32, labels)
    saved = json.loads((tmp_path / "lease.json").read_text())
    assert saved == {
        "execution_id": "a" * 32,
        "project": "fresh-project",
        "helpers": [{"name": "dockroute-probe-" + "b" * 32, "labels": labels}],
    }
    assert "environment" not in saved and "payload" not in saved
    control.close()
    assert not control.thread.is_alive()


def test_cancel_marker_is_cooperative_without_a_windows_console(tmp_path):
    from dockroute.benchmark_control import BenchmarkControl

    interrupted = threading.Event()
    control = BenchmarkControl(tmp_path, "a" * 32, "fresh-project", interrupt=interrupted.set)
    (tmp_path / "cancel").touch()
    assert interrupted.wait(2), "cancellation marker did not reach the child interruption handler"
    control.close()
    assert not control.thread.is_alive()
