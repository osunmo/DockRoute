"""Synthetic post-holdout regressions for explicit configuration consumer roles.

These fixtures encode general roles, not repository identities or sampled ports.
They exercise discovery through its public interface, with literal expectations.
"""

import pytest

from dockroute.discovery import discover
from dockroute.models import Container, Network


def source_for(env, *, healthcheck=(), depends_on=()):
    return Container(
        "source-id",
        "source-container",
        "configuration-study",
        "source",
        env=env,
        healthcheck=healthcheck,
        depends_on=depends_on,
        networks={"default": Network("default", "network-id")},
    )


def endpoints(source):
    return [(edge.host, edge.port) for edge in discover([source])]


@pytest.mark.parametrize(
    "env, expected",
    [
        pytest.param(
            {"SERVICE_JWT_ISSUER": "https://issuer.example:9441"}, [], id="jwt-issuer-identifier"
        ),
        pytest.param(
            {
                "SERVICE_JWT_ISSUER": "http://localhost:9141/claims",
                "API_EXTERNAL_URL": "http://localhost:9141/links",
            },
            [],
            id="local-jwt-origin-context",
        ),
        pytest.param(
            {"ISSUER_URL": "http://issuer.example:9142"},
            [("issuer.example", 9142)],
            id="unqualified-issuer-unknown",
        ),
        pytest.param(
            {"OIDC_CLIENT_ISSUER_URL": "https://identity.example:9442"},
            [("identity.example", 9442)],
            id="oidc-client-preserved",
        ),
        pytest.param(
            {"JWT_JWKS_URL": "https://keys.example:9443/keys"},
            [("keys.example", 9443)],
            id="jwt-jwks-client-preserved",
        ),
        pytest.param(
            {"JWT_DISCOVERY_URL": "https://identity.example:9444/discovery"},
            [("identity.example", 9444)],
            id="jwt-discovery-preserved",
        ),
        pytest.param(
            {"JWT_ISSUER_CLIENT_URL": "https://identity.example:9445"},
            [("identity.example", 9445)],
            id="explicit-issuer-client-preserved",
        ),
        pytest.param(
            {"JWT_OIDC_ISSUER_URL": "https://identity.example:9451"},
            [("identity.example", 9451)],
            id="jwt-oidc-issuer-client-preserved",
        ),
        pytest.param(
            {"JWT_JWKS_ISSUER_URL": "https://keys.example:9452"},
            [("keys.example", 9452)],
            id="jwt-jwks-issuer-client-preserved",
        ),
        pytest.param(
            {"JWT_DISCOVERY_ISSUER_URL": "https://identity.example:9453"},
            [("identity.example", 9453)],
            id="jwt-discovery-issuer-client-preserved",
        ),
        pytest.param(
            {
                "SERVICE_JWT_ISSUER": "http://localhost:9143",
                "API_BASE_URL": "http://localhost:9143/client",
            },
            [("localhost", 9143)],
            id="issuer-does-not-hide-explicit-api-client",
        ),
        pytest.param(
            {
                "SERVICE_JWT_ISSUER": "http://localhost:9144",
                "DATABASE_SERVER_HOST": "localhost",
                "DATABASE_SERVER_PORT": "9144",
            },
            [("localhost", 9144)],
            id="issuer-does-not-hide-database-client",
        ),
        pytest.param(
            {"API_EXTERNAL_URL": "http://remote.example:9145"},
            [("remote.example", 9145)],
            id="external-name-alone-is-not-public-proof",
        ),
        pytest.param(
            {
                "SERVICE_JWT_ISSUER": "http://localhost:9146",
                "API_EXTERNAL_URL": "http://remote.example:9146",
            },
            [("remote.example", 9146)],
            id="local-issuer-does-not-hide-remote-target",
        ),
        pytest.param(
            {
                "SERVICE_JWT_ISSUER": "http://localhost:9147",
                "API_EXTERNAL_URL": "http://localhost:9148",
            },
            [("localhost", 9148)],
            id="issuer-context-does-not-explain-another-port",
        ),
    ],
)
def test_jwt_identifier_context_preserves_outgoing_client_roles(env, expected):
    assert endpoints(source_for(env)) == expected


def test_remote_healthcheck_of_jwt_identifier_is_explicit_request_evidence():
    source = source_for(
        {"SERVICE_JWT_ISSUER": "http://issuer.example:9454/private"},
        healthcheck=("CMD-SHELL", "curl $SERVICE_JWT_ISSUER"),
    )
    edges = discover([source])
    assert [(edge.host, edge.port) for edge in edges] == [("issuer.example", 9454)]
    assert {e.kind for e in edges[0].evidence} == {"healthcheck"}


@pytest.mark.parametrize(
    "env, expected",
    [
        pytest.param(
            {"APP_ADMIN_SERVER_HOST": "localhost", "APP_ADMIN_SERVER_PORT": "9211"},
            [],
            id="local-admin-server-listener",
        ),
        pytest.param(
            {"ADMIN_SERVER_HOST": "127.0.0.1", "ADMIN_SERVER_PORT": "9212"},
            [],
            id="unprefixed-local-admin-listener",
        ),
        pytest.param(
            {"APP_ADMIN_SERVER_HOST": "::1", "APP_ADMIN_SERVER_PORT": "9213"},
            [],
            id="ipv6-admin-listener",
        ),
        pytest.param(
            {"APP_ADMIN_SERVER_HOST": "0.0.0.0", "APP_ADMIN_SERVER_PORT": "9214"},
            [],
            id="wildcard-admin-listener",
        ),
        pytest.param(
            {"APP_ADMIN_SERVER_HOST": "admin.example", "APP_ADMIN_SERVER_PORT": "9215"},
            [("admin.example", 9215)],
            id="remote-admin-server-ambiguous-preserved",
        ),
        pytest.param(
            {"ADMIN_API_URL": "http://admin.example:9216"},
            [("admin.example", 9216)],
            id="remote-admin-api-client-preserved",
        ),
        pytest.param(
            {"DATABASE_SERVER_HOST": "localhost", "DATABASE_SERVER_PORT": "9217"},
            [("localhost", 9217)],
            id="database-server-client-preserved",
        ),
        pytest.param(
            {"ADMINISTRATIVE_SERVER_HOST": "localhost", "ADMINISTRATIVE_SERVER_PORT": "9218"},
            [("localhost", 9218)],
            id="admin-is-an-exact-token",
        ),
    ],
)
def test_local_admin_listener_does_not_generalize_to_server_clients(env, expected):
    assert endpoints(source_for(env)) == expected


@pytest.mark.parametrize("disabled", ["false", "FALSE", " False ", "0", "no", "off"])
def test_explicit_false_endpoint_namespace_is_dormant(disabled):
    source = source_for(
        {"SEARCH_ENABLED": disabled, "SEARCH_HOST": "localhost", "SEARCH_PORT": "9321"}
    )
    assert endpoints(source) == []


@pytest.mark.parametrize("enabled", ["true", "TRUE", "1", "yes", "on", "unknown", "", "unset"])
def test_enabled_or_unknown_flag_keeps_endpoint_intention(enabled):
    source = source_for(
        {"SEARCH_ENABLED": enabled, "SEARCH_HOST": "localhost", "SEARCH_PORT": "9322"}
    )
    assert endpoints(source) == [("localhost", 9322)]


@pytest.mark.parametrize(
    "env, expected",
    [
        pytest.param(
            {"CACHE_ENABLED": "false", "CACHE_URL": "redis://cache:9323"}, [], id="disabled-url"
        ),
        pytest.param(
            {"SEARCH_ENABLED": "false", "SEARCH_API_URL": "http://remote.example:9324"},
            [("remote.example", 9324)],
            id="no-parent-prefix-guess",
        ),
        pytest.param(
            {"SEARCH_ENABLED": "false", "SEARCHER_HOST": "localhost", "SEARCHER_PORT": "9325"},
            [("localhost", 9325)],
            id="no-substring-prefix-guess",
        ),
        pytest.param(
            {
                "SEARCH_ENABLED": "false",
                "DATABASE_SERVER_HOST": "localhost",
                "DATABASE_SERVER_PORT": "9326",
            },
            [("localhost", 9326)],
            id="unrelated-flag-does-not-hide-client",
        ),
        pytest.param(
            {"SEARCH_DISABLED": "true", "SEARCH_HOST": "localhost", "SEARCH_PORT": "9327"},
            [("localhost", 9327)],
            id="no-negative-flag-semantics-guess",
        ),
    ],
)
def test_disabled_endpoint_matching_requires_exact_enabled_namespace(env, expected):
    assert endpoints(source_for(env)) == expected


def test_disabled_endpoint_retains_dependency_only_uncertainty():
    source = source_for(
        {"SEARCH_ENABLED": "false", "SEARCH_HOST": "localhost", "SEARCH_PORT": "9331"},
        depends_on=("search",),
    )
    edges = discover([source])
    assert [(edge.host, edge.port) for edge in edges] == [("search", None)]
    assert {e.kind for e in edges[0].evidence} == {"depends_on"}


@pytest.mark.parametrize(
    "healthcheck",
    [
        ("CMD-SHELL", "curl $SEARCH_URL"),
        ("CMD", "curl", "http://remote.example:9332/health"),
    ],
    ids=["explicit-environment-reference", "explicit-literal-request"],
)
def test_remote_healthcheck_is_independent_evidence_despite_disabled_namespace(healthcheck):
    source = source_for(
        {"SEARCH_ENABLED": "false", "SEARCH_URL": "http://remote.example:9332/private"},
        healthcheck=healthcheck,
    )
    edges = discover([source])
    assert [(edge.host, edge.port) for edge in edges] == [("remote.example", 9332)]
    assert {e.kind for e in edges[0].evidence} == {"healthcheck"}
    assert "private" not in " ".join(e.detail for e in edges[0].evidence)
