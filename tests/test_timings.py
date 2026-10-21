from types import SimpleNamespace

import pytest


def test_request_paths_remove_identifiers_and_every_query_value():
    from dockroute.timings import normalize_path

    assert (
        normalize_path("/v1.56/containers/secret-id/logs?tail=4&token=secret")
        == "/containers/{id}/logs"
    )
    assert normalize_path("/v1.56/containers/json?filters=secret-label") == "/containers/json"
    assert normalize_path("/v1.56/images/python:secret/json") == "/images/{id}/json"
    assert normalize_path("/v1.56/private/secret-name") == "/other"


def test_response_hook_attributes_hidden_requests_and_detaches_without_touching_other_hooks():
    from dockroute.timings import RequestTimings

    def foreign(*a, **kw):
        return None

    api = SimpleNamespace(hooks={"response": [foreign]})
    timing = RequestTimings(api)
    response = SimpleNamespace(
        request=SimpleNamespace(
            method="GET", path_url="/v1.56/containers/password/logs?token=secret"
        ),
        status_code=200,
        elapsed=SimpleNamespace(total_seconds=lambda: 0.125),
    )
    with timing.stage("source", "worker_startup"):
        for hook in api.hooks["response"]:
            hook(response)
        response.request.path_url = "/v1.56/containers/password/json"
        for hook in api.hooks["response"]:
            hook(response)
    summary = timing.summary()
    assert summary == [
        {
            "role": "source",
            "stage": "worker_startup",
            "method": "GET",
            "path": "/containers/{id}/json",
            "count": 1,
            "total_ms": 125.0,
            "max_ms": 125.0,
            "status_counts": {"200": 1},
        },
        {
            "role": "source",
            "stage": "worker_startup",
            "method": "GET",
            "path": "/containers/{id}/logs",
            "count": 1,
            "total_ms": 125.0,
            "max_ms": 125.0,
            "status_counts": {"200": 1},
        },
    ]
    assert timing.count("source", "worker_startup") == 2
    assert "secret" not in repr(summary) and "password" not in repr(summary)
    timing.close()
    assert api.hooks["response"] == [foreign]


def test_derived_clock_arithmetic_uses_container_and_daemon_clocks_only():
    from dockroute.timings import ready_metrics

    ready = {"wall_ts": 1704067200.15, "import_ms": 20.0, "ready_ms": 21.0}
    metrics = ready_metrics(ready, "2024-01-01T00:00:00.000000000Z", 2000.0)
    assert metrics["vm_startup_ms"] == pytest.approx(150.0, abs=0.001)
    assert metrics["observation_overhead_ms"] == pytest.approx(1850.0, abs=0.001)
    assert metrics["host_ready_ms"] == 2000.0 and metrics["derived"] is True
    assert ready_metrics(ready, "", 2000.0)["vm_startup_ms"] is None
    assert ready_metrics(ready, "2024-01-01T00:00:00Z", 5.0)["observation_overhead_ms"] == 0


def test_hook_thread_stage_context_cannot_attribute_another_helpers_request():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from dockroute.timings import RequestTimings

    api = SimpleNamespace(hooks={"response": []})
    timing = RequestTimings(api)
    barrier = Barrier(2)

    def request(role):
        with timing.stage(role, "create"):
            barrier.wait(timeout=5)
            api.hooks["response"][0](
                SimpleNamespace(
                    request=SimpleNamespace(method="POST", path_url="/v1.56/containers/create"),
                    status_code=201,
                    elapsed=SimpleNamespace(total_seconds=lambda: 0.01),
                )
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(request, ["source", "destination"]))
    assert timing.count("source", "create") == timing.count("destination", "create") == 1
    timing.close()
