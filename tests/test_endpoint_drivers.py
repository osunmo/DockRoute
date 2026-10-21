"""Database driver and result-backend wrappers preserve network endpoint semantics."""

import json

import pytest

from dockroute.discovery import discover
from dockroute.endpoints import parse_endpoint
from dockroute.models import Container


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("postgresql+psycopg://user:private-password@database/app", ("database", 5432)),
        ("POSTGRESQL+ASYNCpg://db:5433/app?token=private-token", ("db", 5433)),
        ("mysql+pymysql://db/app", ("db", 3306)),
        ("mysql+mysqlconnector://db:3307/app", ("db", 3307)),
        ("db+postgresql://db/app", ("db", 5432)),
        ("db+postgresql+psycopg2://db/app", ("db", 5432)),
        ("postgresql+psycopg://user:p%40ss@[fd00::2]:5432/app", ("fd00::2", 5432)),
        ("sqlite+aiosqlite:///secret/db.sqlite", None),
        ("redis+sentinel://redis", None),
        ("http+unix://socket/path", None),
        ("madeup+postgresql://db/app", None),
        ("db+http://api/path", None),
        ("postgresql+://db/app", None),
        ("postgresql+psycopg+extra://db/app", None),
        ("postgresql+psycopg://db:99999/app", None),
        ("postgresql+psycopg://db\n.invalid/app", None),
    ],
)
def test_driver_url_endpoint(value, expected):
    assert parse_endpoint(value) == expected


def test_driver_url_discovery_omits_credentials_and_query_values():
    service = Container(
        "a",
        "app-1",
        "test",
        "app",
        env={
            "DATABASE_URL": "postgresql+psycopg://alice:special-password@db/app?token=special-token",
        },
    )
    edges = discover([service])
    assert [(edge.host, edge.port) for edge in edges] == [("db", 5432)]
    rendered = json.dumps([evidence.detail for edge in edges for evidence in edge.evidence])
    assert "alice" not in rendered
    assert "special-password" not in rendered
    assert "special-token" not in rendered
