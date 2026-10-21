"""Round-trip reduction keeps image, timeout, identity, and cleanup guarantees."""

import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from docker.errors import ImageNotFound
from requests.exceptions import Timeout
from test_core import node
from test_probe_v02 import StageClient, execute

from dockroute.diagnostics import diagnose
from dockroute.models import Connection
from dockroute.probes import Prober


def test_create_pins_returned_image_without_image_lookup_or_pull():
    client = StageClient()
    image_arguments = []
    create = client.create

    def forbidden(*args, **kwargs):
        pytest.fail("helper creation must not perform an image GET or automatic pull")

    def pinned(image, **configuration):
        image_arguments.append(image)
        helper = create(image, **configuration)
        helper.attrs["Image"] = "sha256:" + "a" * 64
        return helper

    client.images.get = forbidden
    client.images.pull = forbidden
    client.containers.create = pinned
    result = execute(client)
    assert result.state == "SUCCESS" and result.listener_verified
    assert image_arguments == ["python:3.12-alpine", "sha256:" + "a" * 64]
    assert all(
        step.helper_configuration["image"] == "sha256:" + "a" * 64
        for step in result.trace
        if step.stage == "create"
    )
    assert not any(step.stage == "image_availability" for step in result.trace)
    assert len(client.removed) == 2


def test_create_missing_image_retains_prerequisite_state_without_pull():
    client = StageClient()
    attempted = []

    def absent(image, **configuration):
        attempted.append(image)
        raise ImageNotFound("private image body")

    client.containers.create = absent
    client.images.pull = lambda *a, **kw: pytest.fail("image availability must not trigger a pull")
    result = execute(client)
    assert attempted == ["python:3.12-alpine"]
    assert result.state == "HELPER_IMAGE_UNAVAILABLE" and result.failure_stage == "create"
    assert "locally" in " ".join(result.notes)
    assert result.dns_equivalent is None and not client.created
    assert "private image body" not in repr(result)


@pytest.mark.parametrize("image", [None, "malformed", "sha256:" + "a" * 63])
def test_missing_created_image_identity_prevents_start_and_still_cleans(image):
    client = StageClient()
    create = client.create
    starts = []

    def unverified(image_argument, **configuration):
        helper = create(image_argument, **configuration)
        helper.attrs["Image"] = image
        helper.start = lambda: starts.append(helper.id)
        return helper

    client.containers.create = unverified
    result = execute(client)
    assert result.state == "HELPER_CREATE_FAILED"
    assert starts == []
    assert client.removed == ["helper-connect"]


def test_unbudgeted_api_call_waits_until_temporary_timeout_is_restored():
    api = SimpleNamespace(timeout=5.0)
    prober = Prober(SimpleNamespace(api=api), "shop")
    held = threading.Event()
    release = threading.Event()
    second_started = threading.Event()
    second_entered = threading.Event()
    observed = []

    def bounded():
        held.set()
        assert release.wait(2)

    def unbudgeted():
        second_started.set()

        def body():
            observed.append(api.timeout)
            second_entered.set()

        prober._request(body)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(prober._request, bounded, 0.2)
        assert held.wait(2)
        second = executor.submit(unbudgeted)
        assert second_started.wait(2)
        try:
            assert not second_entered.wait(0.1)
        finally:
            release.set()
        first.result(timeout=2)
        second.result(timeout=2)
    assert observed == [5.0] and api.timeout == 5.0


def test_expired_queued_api_budget_never_issues_a_request():
    api = SimpleNamespace(timeout=5.0, _dockroute_request_lock=threading.RLock())
    prober = Prober(SimpleNamespace(api=api), "shop")
    issued = []
    lock = api._dockroute_request_lock
    lock.acquire()
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(prober._request, lambda: issued.append(True), 0.03)
            try:
                with pytest.raises(Timeout):
                    future.result(timeout=0.3)
            finally:
                lock.release()
    finally:
        if issued:
            # The obsolete implementation issued the callback only after release.
            assert api.timeout == 5.0
    assert issued == []


def test_request_failure_restores_timeout_before_next_operation():
    api = SimpleNamespace(timeout=5.0)
    prober = Prober(SimpleNamespace(api=api), "shop")

    def failed():
        assert 0 < api.timeout <= 0.2
        raise RuntimeError("request failed")

    with pytest.raises(RuntimeError):
        prober._request(failed, 0.2)
    assert prober._request(lambda: api.timeout) == 5.0


def test_cached_static_diagnosis_is_resolved_after_source_helper_cleanup():
    client = StageClient()
    selected = [node("app", networks=("front",)), node("api", networks=("back",))]
    edge = Connection("app-id", "app", "api", 8000)
    static = diagnose(edge, selected)
    calls = []

    def cached():
        assert client.removed == ["helper-connect"]
        calls.append(True)
        return static

    result = Prober(client, "shop", schedule="conditional").check(
        edge, selected, static_finding=cached
    )
    assert calls == [True]
    assert result.listener_skipped and len(client.created) == 1


def test_second_helper_cannot_start_with_a_different_image_than_pinned():
    client = StageClient()
    create = client.create
    starts = []

    def changed(image, **configuration):
        helper = create(image, **configuration)
        helper.attrs["Image"] = "sha256:" + ("a" if len(client.created) == 1 else "b") * 64
        helper.start = lambda: starts.append(helper.id)
        return helper

    client.containers.create = changed
    result = execute(client)
    assert starts == ["helper-connect"]
    assert result.listener_state == "HELPER_CREATE_FAILED"
    assert len(client.removed) == 2
