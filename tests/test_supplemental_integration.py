"""Integration boundaries for mounted configuration and recent error evidence."""

from dataclasses import replace
from datetime import UTC, datetime

from dockroute.config_extractors import ConfigDocument, extract_configs
from dockroute.diagnostics import diagnose
from dockroute.discovery import discover
from dockroute.docker import container_from_inspect
from dockroute.log_evidence import parse_log_line
from dockroute.models import Container, Network


def _nginx_source(host: str, *, state: str = "exited") -> Container:
    hints = extract_configs(
        [
            ConfigDocument(
                "nginx",
                "/etc/nginx/nginx.conf",
                f"events {{}} http {{ server {{ location / {{ proxy_pass http://{host}:8080; }} }} }}".encode(),
            )
        ]
    ).hints
    return Container(
        "web-id",
        "proj-web-1",
        "proj",
        "web",
        state=state,
        networks={"webnet": Network("webnet", "web-net", ("web",))},
        depends_on=("backend",),
        config_hints=hints,
    )


def _backend(network: str = "webnet") -> Container:
    return Container(
        "back-id",
        "proj-backend-1",
        "proj",
        "backend",
        state="running",
        networks={
            network: Network(
                network, "web-net" if network == "webnet" else "back-net", ("backend",)
            )
        },
    )


def test_exited_nginx_typo_uses_config_and_current_start_log() -> None:
    source = _nginx_source("backned")
    dest = _backend()
    hint = parse_log_line(
        '2026-10-20T12:00:01Z 2026/10/20 [emerg] 1#1: host not found in upstream "backned" in /etc/nginx/nginx.conf:1',
        source,
        [source, dest],
        started_at="2026-10-20T12:00:00Z",
        until=datetime(2026, 10, 20, 12, 0, 2, tzinfo=UTC),
    )
    assert hint is not None
    source = replace(source, log_hints=(hint,))
    edges = discover([source, dest])
    edge = next(e for e in edges if e.host == "backned" and e.port == 8080)
    finding = diagnose(edge, [source, dest])
    assert finding.code == "INVALID_SERVICE_HOSTNAME"
    assert finding.verification == "static"
    assert finding.status != "REACHABLE"
    assert any(e.kind == "container_log" for e in finding.observations)


def test_exited_nginx_network_split_requires_logged_failure() -> None:
    source = _nginx_source("backend")
    dest = _backend("backnet")
    hint = parse_log_line(
        '2026-10-20T12:00:01Z 2026/10/20 [emerg] 1#1: host not found in upstream "backend" in /etc/nginx/nginx.conf:1',
        source,
        [source, dest],
        started_at="2026-10-20T12:00:00Z",
        until=datetime(2026, 10, 20, 12, 0, 2, tzinfo=UTC),
    )
    assert hint is not None
    edge = next(e for e in discover([source, dest]) if e.host == "backend" and e.port == 8080)
    assert diagnose(edge, [source, dest]).code == "UNKNOWN"
    source = replace(source, log_hints=(hint,))
    finding = diagnose(edge, [source, dest])
    assert finding.code == "NETWORK_ISOLATION"
    assert finding.verification == "static"
    assert finding.confidence != "high"


def test_inspection_retains_only_selected_metadata_for_supplemental_reads() -> None:
    attrs = {
        "Id": "web-id",
        "Name": "/proj-web-1",
        "Config": {
            "Labels": {"com.docker.compose.project": "proj", "com.docker.compose.service": "web"},
            "Tty": False,
        },
        "State": {"Status": "exited", "StartedAt": "2026-10-20T12:00:00Z"},
        "Mounts": [
            {"Type": "bind", "Source": "C:/private/site", "Destination": "/etc/nginx/nginx.conf"}
        ],
    }
    container = container_from_inspect(attrs)
    assert container is not None
    assert container.started_at == "2026-10-20T12:00:00Z"
    assert container.mounts[0]["Destination"] == "/etc/nginx/nginx.conf"
    assert "C:/private/site" not in repr(container)
