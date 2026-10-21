"""Explicit configuration roles must not be mistaken for outgoing connections."""

import json
from pathlib import Path

import pytest

from dockroute.discovery import discover
from dockroute.models import Container, Network, Port

FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures" / "discovery-roles.json").read_text(encoding="utf-8")
)["cases"]


def source_for(case):
    return Container(
        "source-id",
        "service-container",
        "generic-study",
        "service",
        env=case.get("env", {}),
        healthcheck=tuple(case.get("healthcheck", ())),
        depends_on=tuple(case.get("depends_on", ())),
        ports=tuple(Port(**port) for port in case.get("ports", ())),
        networks={"default": Network("default", "network-id", tuple(case.get("aliases", ())))},
    )


@pytest.mark.parametrize("case", FIXTURES, ids=lambda case: case["id"])
def test_permanent_generic_role_fixtures(case):
    edges = discover([source_for(case)])
    assert [[edge.host, edge.port] for edge in edges] == case["expected"]


def test_public_endpoint_reference_remains_remote_healthcheck_evidence_without_environment_intention():
    source = source_for(
        {
            "env": {"PUBLIC_URL": "http://target:8080/private"},
            "healthcheck": ["CMD-SHELL", "curl $PUBLIC_URL"],
            "depends_on": ["target"],
        }
    )
    target = Container("target-id", "target-container", "generic-study", "target")
    edges = discover([source, target])
    assert [(edge.host, edge.port) for edge in edges] == [("target", 8080)]
    assert {e.kind for e in edges[0].evidence} == {"healthcheck", "depends_on"}
    assert "private" not in " ".join(e.detail for e in edges[0].evidence)


def test_public_endpoint_without_an_explicit_healthcheck_reference_does_not_become_a_candidate():
    source = source_for(
        {
            "env": {"PUBLIC_URL": "http://target:8080/private"},
            "healthcheck": ["CMD-SHELL", "test -n $PUBLIC_URL_SUFFIX"],
        }
    )
    assert discover([source]) == []


def test_public_endpoint_reference_to_own_alias_is_a_self_check():
    source = source_for(
        {
            "aliases": ["own-alias"],
            "env": {"PUBLIC_URL": "http://own-alias:8080/private"},
            "healthcheck": ["CMD-SHELL", "curl ${PUBLIC_URL}"],
        }
    )
    assert discover([source]) == []


def test_shared_alias_is_ambiguous_and_not_silently_classified_as_a_self_check():
    source = source_for(
        {"aliases": ["shared"], "healthcheck": ["CMD", "curl", "http://shared:8080"]}
    )
    other = Container(
        "other-id",
        "other-container",
        "generic-study",
        "other",
        networks={"default": Network("default", "network-id", ("shared",))},
    )
    assert [(e.host, e.port) for e in discover([source, other])] == [("shared", 8080)]


def test_loopback_client_with_no_own_port_keeps_unconfirmed_dependency_evidence():
    source = source_for(
        {"env": {"UPSTREAM_URL": "http://localhost:8080"}, "depends_on": ["target"]}
    )
    edges = discover([source])
    assert [(edge.host, edge.port) for edge in edges] == [("localhost", 8080)]
    assert {e.kind for e in edges[0].evidence} == {"environment", "depends_on"}
    assert "unconfirmed" in next(e.detail for e in edges[0].evidence if e.kind == "depends_on")


def test_unrecognized_self_environment_url_remains_unclassified_instead_of_guessed():
    source = source_for({"env": {"APP_URL": "http://service:8080"}, "ports": [{"container": 8080}]})
    assert [(e.host, e.port) for e in discover([source])] == [("service", 8080)]
