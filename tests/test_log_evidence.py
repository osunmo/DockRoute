"""Application logs are bounded observations, never current network proof."""

import json
import time
from dataclasses import asdict, replace
from datetime import UTC, datetime
from threading import Event

import pytest

from dockroute import log_evidence
from dockroute.models import Container, Network

START = "2026-10-14T12:00:00.123456700Z"
STAMP = "2026-10-14T12:00:01.000000000Z"
NOW = datetime(2026, 10, 14, 12, 1, tzinfo=UTC)


def source(**changes):
    return replace(
        Container(
            "source-id",
            "demo-web-1",
            "demo",
            "web",
            state="exited",
            networks={"front": Network("front", "front-id")},
            depends_on=("api",),
        ),
        **changes,
    )


def destination(**changes):
    return replace(
        Container(
            "destination-id",
            "demo-api-1",
            "demo",
            "api",
            state="running",
            networks={"back": Network("back", "back-id", aliases=("upstream",))},
        ),
        **changes,
    )


def parse(message, *, src=None, containers=None, stamp=STAMP, started_at=START):
    src = src or source()
    return log_evidence.parse_log_line(
        f"{stamp} {message}",
        src,
        containers or [src, destination()],
        started_at=started_at,
        until=NOW,
    )


@pytest.mark.parametrize(
    ("message", "signature", "host", "port"),
    [
        (
            '2026/10/14 12:00:01 [emerg] 1#1: host not found in upstream "api:8000" in /etc/nginx/nginx.conf:8',
            "NGINX_UPSTREAM_DNS",
            "api",
            8000,
        ),
        (
            'nginx: [emerg] host not found in upstream "missing-api" in /etc/nginx/conf.d/default.conf:4',
            "NGINX_UPSTREAM_DNS",
            "missing-api",
            None,
        ),
        ("Error: getaddrinfo ENOTFOUND upstream", "NODE_DNS", "upstream", None),
        ("Error: connect ECONNREFUSED api:5432", "TCP_REFUSED", "api", 5432),
        (
            'could not translate host name "upstream" to address: Name or service not known',
            "POSTGRES_DNS",
            "upstream",
            None,
        ),
    ],
)
def test_known_errors_extract_only_endpoint_and_fixed_signature(message, signature, host, port):
    hint = parse(message)
    assert hint is not None
    assert (hint.signature, hint.host, hint.port) == (signature, host, port)
    assert hint.observed_at == STAMP
    serialized = json.dumps(asdict(hint))
    assert "/etc/" not in serialized
    assert message not in serialized


def test_selected_project_alias_and_network_evidence_are_correlated():
    hint = parse("Error: getaddrinfo ENOTFOUND upstream")
    assert hint.destination_ids == ("destination-id",)
    assert hint.shared_network_ids == ()
    shared = destination(networks={"renamed": Network("renamed", "front-id", ("upstream",))})
    hint = parse("Error: getaddrinfo ENOTFOUND upstream", containers=[source(), shared])
    assert hint.shared_network_ids == ("front-id",)


def test_unknown_single_label_is_retained_without_guessing_a_destination():
    hint = parse('nginx: [emerg] host not found in upstream "api-typo:8000"')
    assert hint is not None
    assert hint.destination_ids == ()
    assert hint.host == "api-typo"


@pytest.mark.parametrize(
    "message",
    [
        'host not found in upstream "api:8000" is an example from documentation',
        "Recovered from ECONNREFUSED; connected to api:8000",
        "Error: ECONNREFUSED",
        "Error: connect ECONNREFUSED api:70000",
        "Error: getaddrinfo ENOTFOUND https://user:password@api:8000/private?token=secret",
        'nginx: [emerg] host not found in upstream "user:password@api:8000"',
        'nginx: [emerg] host not found in upstream "api:8000/private?token=secret"',
        'nginx: [emerg] host not found in upstream "api\u001b[31m:8000"',
        'nginx: [emerg] host not found in upstream "${UPSTREAM}:8000"',
        'nginx: [emerg] host not found in upstream "https://example.com"',
        "Error: getaddrinfo ENOTFOUND external.example.com",
        "Error: connect ECONNREFUSED 203.0.113.1:5432",
    ],
)
def test_misleading_unbounded_or_external_text_is_not_an_endpoint(message):
    assert parse(message) is None


def test_known_secret_values_do_not_become_hostname_evidence():
    src = source(env={"DATABASE_PASSWORD": "super-secret-token"})
    assert parse("Error: getaddrinfo ENOTFOUND super-secret-token", src=src) is None


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-10-14T11:59:59.999999999Z",
        "2026-10-14T12:00:00.123456699Z",
        "2026-10-14T12:02:00Z",
        "nonsense",
        "",
        "0001-01-01T00:00:00Z",
    ],
)
def test_only_timestamped_current_start_observations_are_used(stamp):
    assert parse("Error: getaddrinfo ENOTFOUND api", stamp=stamp) is None


@pytest.mark.parametrize(
    "src",
    [
        source(state="running", health="healthy"),
        source(state="running", health="none"),
        source(state="created"),
    ],
)
def test_healthy_or_never_started_sources_do_not_supply_stale_log_findings(src):
    assert parse("Error: getaddrinfo ENOTFOUND api", src=src) is None


def test_unhealthy_source_can_supply_observation_without_runtime_verification_claim():
    hint = parse(
        "Error: getaddrinfo ENOTFOUND api", src=source(state="running", health="unhealthy")
    )
    assert hint is not None
    evidence = hint.evidence()
    assert evidence.kind == "container_log"
    assert "historical" in evidence.detail.lower()
    assert "raw log omitted" in evidence.detail


class Response:
    def __init__(self, payload, *, pieces=13, fail=False):
        self.payload = payload
        self.pieces = pieces
        self.closed = False
        self.read_bytes = 0
        self.chunk_sizes = []
        self.fail = fail

    def iter_content(self, chunk_size):
        self.chunk_sizes.append(chunk_size)
        for index in range(0, len(self.payload), min(self.pieces, chunk_size)):
            if self.fail:
                raise OSError("password=must-not-escape")
            chunk = self.payload[index : index + min(self.pieces, chunk_size)]
            self.read_bytes += len(chunk)
            yield chunk

    def close(self):
        self.closed = True


class API:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def _url(self, pattern, container_id):
        return pattern.format(container_id)

    def _get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response

    def _raise_for_status(self, response):
        pass


def frame(payload, stream=2):
    return bytes([stream, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload


def collect(payload, *, tty=False, **kwargs):
    response = Response(payload)
    api = API(response)
    result = log_evidence.read_log_evidence(
        api,
        source(),
        [source(), destination()],
        started_at=START,
        until=NOW,
        tty=tty,
        **kwargs,
    )
    return result, api, response


def test_bounded_sdk_stream_demultiplexes_split_headers_and_closes():
    line = f'{STAMP} nginx: [emerg] host not found in upstream "api:8000"\n'.encode()
    result, api, response = collect(frame(line[:23]) + frame(line[23:]))
    assert result.status == "collected"
    assert result.hints[0].host == "api"
    assert response.closed
    params = api.calls[0][1]["params"]
    assert params["tail"] == 100 and params["follow"] is False
    assert params["timestamps"] is True
    assert "since" in params and "until" in params
    assert api.calls[0][1]["stream"] is True
    assert max(api.calls[0][1]["timeout"]) <= 2


def test_tty_stream_is_parsed_without_docker_headers():
    result, _, response = collect(f"{STAMP} Error: getaddrinfo ENOTFOUND api\n".encode(), tty=True)
    assert result.hints[0].signature == "NODE_DNS"
    assert response.closed


def test_huge_frame_is_cut_off_before_payload_allocation():
    payload = b"x" * 2_000_000
    result, _, response = collect(frame(payload), max_bytes=512)
    assert result.hints == ()
    assert result.truncated and result.bytes_read <= 512
    assert response.read_bytes <= 512 + 4096
    assert response.closed


def test_line_count_bound_is_applied_even_when_server_ignores_tail():
    payload = (f"{STAMP} Error: getaddrinfo ENOTFOUND api\n" * 101).encode()
    result, _, response = collect(frame(payload), max_lines=3)
    assert result.lines_read == 3
    assert result.truncated
    assert response.closed


def test_partial_line_at_stream_limit_cannot_supply_a_hint():
    payload = f'{STAMP} nginx: [emerg] host not found in upstream "api:8000"'.encode()
    result, _, _ = collect(frame(payload), max_bytes=48)
    assert result.hints == ()


def test_stream_failure_is_sanitized_and_closed():
    response = Response(frame(b"payload"), fail=True)
    result = log_evidence.read_log_evidence(
        API(response), source(), [source()], started_at=START, until=NOW
    )
    assert result.status == "unavailable"
    assert "must-not-escape" not in repr(result)
    assert response.closed


def test_source_must_exist_in_selected_project_before_sdk_read():
    api = API(Response(b""))
    result = log_evidence.read_log_evidence(
        api, source(), [destination(project="other")], started_at=START, until=NOW
    )
    assert result.status == "skipped"
    assert api.calls == []


def test_mixed_project_snapshot_is_refused():
    api = API(Response(b""))
    result = log_evidence.read_log_evidence(
        api, source(), [source(), destination(project="other")], started_at=START, until=NOW
    )
    assert result.status == "skipped"
    assert api.calls == []


def test_malformed_multiplex_header_closes_without_guessing_payload():
    result, _, response = collect(b"secret\x00\x00not a Docker log frame")
    assert result.status == "unavailable"
    assert result.hints == ()
    assert response.closed


def test_stdout_and_stderr_cannot_be_spliced_into_a_fabricated_endpoint():
    payload = frame(f'{STAMP} nginx: [emerg] host not found in upstream "'.encode(), stream=1)
    payload += frame(b'api:8000"\n', stream=2)
    result, _, response = collect(payload)
    assert result.hints == ()
    assert response.closed


def test_full_stderr_line_survives_an_unfinished_stdout_line():
    payload = frame(b"unfinished stdout", stream=1)
    payload += frame(f"{STAMP} Error: getaddrinfo ENOTFOUND api\n".encode(), stream=2)
    result, _, _ = collect(payload)
    assert len(result.hints) == 1
    assert result.hints[0].host == "api"


def test_oversize_line_is_discarded_and_next_small_line_still_parses():
    payload = ("x" * 9000 + f"\n{STAMP} Error: getaddrinfo ENOTFOUND api\n").encode()
    result, _, _ = collect(frame(payload))
    assert len(result.hints) == 1
    assert result.lines_read == 2


def test_absolute_deadline_returns_and_closes_a_stalled_stream():
    released = Event()

    class Stalled(Response):
        def iter_content(self, chunk_size):
            released.wait(2)
            yield b""

        def close(self):
            self.closed = True
            released.set()

    response = Stalled(b"")
    before = time.monotonic()
    result = log_evidence.read_log_evidence(
        API(response), source(), [source()], started_at=START, until=NOW, timeout=0.05
    )
    assert time.monotonic() - before < 1
    assert result.status == "timeout" and result.hints == ()
    assert released.wait(0.5)
    assert response.closed


def test_timestamp_at_current_start_is_allowed_without_rounding_to_microseconds():
    assert parse("Error: getaddrinfo ENOTFOUND api", stamp=START) is not None


@pytest.mark.parametrize("started_at", ["", "0001-01-01T00:00:00Z", "2026-10-14T13:00:00Z"])
def test_missing_or_future_start_skips_transport(started_at):
    api = API(Response(b""))
    result = log_evidence.read_log_evidence(
        api, source(), [source()], started_at=started_at, until=NOW
    )
    assert result.status == "skipped" and not api.calls


def test_url_userinfo_secrets_are_not_reclassified_as_hostname_evidence():
    src = source(env={"DATABASE_URL": "postgres://user:super-secret-token@db:5432/app"})
    assert parse("Error: getaddrinfo ENOTFOUND super-secret-token", src=src) is None


def test_shared_alias_retains_all_candidates_instead_of_picking_one():
    src = source()
    first = destination()
    second = destination(id="replica", service="replica")
    hint = parse("Error: getaddrinfo ENOTFOUND upstream", containers=[src, first, second])
    assert hint.destination_ids == ("destination-id", "replica")
