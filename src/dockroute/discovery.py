"""Discover intentions without treating configuration or dependencies as traffic."""

import ipaddress
import re

from dockroute.endpoints import DEFAULT_PORTS as DEFAULT_PORTS
from dockroute.endpoints import parse_endpoint as parse_endpoint
from dockroute.models import Connection, Container, Evidence
from dockroute.safety import is_loopback, safe_key, valid_host

_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>;)]+")


def _credential_key(key: str) -> bool:
    return any(
        word in key.upper()
        for word in (
            "PASS",
            "PWD",
            "SECRET",
            "TOKEN",
            "KEY",
            "CREDENTIAL",
            "AUTH",
            "SESSION",
            "COOKIE",
            "CERT",
            "SIGNATURE",
        )
    )


def _configuration_role(key: str) -> str | None:
    """Recognize explicit address roles; unknown naming conventions stay unknown."""
    upper = key.upper()
    tokens = set(re.split(r"[^A-Z0-9]+", upper))
    if "TEMPLATE" in tokens and tokens & {"URL", "URI"}:
        return "template"
    if "ADVERTISED" in tokens:
        return "advertised"
    if tokens & {"BIND", "LISTEN", "LISTENER", "LISTENERS"}:
        return "listener"
    if {"JWT", "ISSUER"} <= tokens and not tokens & {"OIDC", "JWKS", "DISCOVERY", "CLIENT"}:
        return "identifier"
    if (
        "PUBLIC" in tokens
        or upper in {"SITEURL", "SITE_URL"}
        or upper.endswith(("_SITEURL", "_SITE_URL"))
    ):
        return "public"
    return None


def _unspecified(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return False


def _disabled_endpoint(key: str, source: Container) -> bool:
    """Honor an explicit enable flag for this exact endpoint namespace only."""
    match = re.fullmatch(r"(.+)_(?:HOST|URL|URI|ADDRESS|ENDPOINT)", key, re.IGNORECASE)
    if not match:
        return False
    enabled = source.env.get(match[1] + "_ENABLED", "")
    return enabled.strip().lower() in {"false", "0", "no", "off"}


def _local_admin_listener(key: str, endpoint: tuple[str, int]) -> bool:
    upper = key.upper()
    return (upper == "ADMIN_SERVER_HOST" or upper.endswith("_ADMIN_SERVER_HOST")) and (
        is_loopback(endpoint[0]) or _unspecified(endpoint[0])
    )


def _jwt_origin_context(key: str, endpoint: tuple[str, int], source: Container) -> bool:
    # An external origin matching a JWT issuer is metadata context, not client evidence.
    tokens = set(re.split(r"[^A-Z0-9]+", key.upper()))
    if "EXTERNAL" not in tokens or not tokens & {"URL", "URI"}:
        return False
    if tokens & {"CLIENT", "BASE", "UPSTREAM", "DATABASE", "OIDC", "JWKS", "DISCOVERY"}:
        return False
    scheme = source.env[key].strip().partition("://")[0].lower()
    if scheme not in {"http", "https"}:
        return False
    return any(
        not _credential_key(issuer_key)
        and _configuration_role(issuer_key) == "identifier"
        and parse_endpoint(value) == endpoint
        and value.strip().partition("://")[0].lower() == scheme
        for issuer_key, value in source.env.items()
    )


def _own_loopback_port(endpoint: tuple[str, int], source: Container) -> bool:
    # Own listener/public URLs are ambiguous, not evidence for another dependency.
    return is_loopback(endpoint[0]) and any(
        port.protocol.lower() == "tcp" and endpoint[1] in {port.container, port.host}
        for port in source.ports
    )


def _declared_local_ports(source: Container) -> set[int]:
    """Find local address declarations that make inherited loopback values ambiguous."""
    ports = set()
    for key, value in source.env.items():
        if _credential_key(key) or _disabled_endpoint(key, source):
            continue
        endpoint = parse_endpoint(value)
        if not endpoint and key.upper().endswith("_HOST") and valid_host(value.strip()):
            port_value = source.env.get(key[:-5] + "_PORT", "")
            if port_value.isdecimal() and 1 <= int(port_value) <= 65535:
                endpoint = (value.strip().lower(), int(port_value))
        if endpoint:
            role = _configuration_role(key)
            if (
                _unspecified(endpoint[0])
                or role == "listener"
                or _local_admin_listener(key, endpoint)
                or role in {"public", "advertised", "template"}
                and is_loopback(endpoint[0])
            ):
                ports.add(endpoint[1])
    return ports


def _ambiguous_loopback_environment(
    key: str, endpoint: tuple[str, int], source: Container, local_ports: set[int]
) -> bool:
    # Bare local BASE_URL is a canonical origin convention, not a known client role.
    return is_loopback(endpoint[0]) and (
        key.upper() == "BASE_URL"
        or endpoint[1] in local_ports
        or _own_loopback_port(endpoint, source)
        or _jwt_origin_context(key, endpoint, source)
    )


def _remote_health_endpoint(endpoint: tuple[str, int], source, containers) -> bool:
    if is_loopback(endpoint[0]) or _unspecified(endpoint[0]):
        return False
    matches = resolve_hostname(endpoint[0], containers)
    # A shared alias remains ambiguous; only a uniquely identified self check is omitted.
    return not matches or any(container.id != source.id for container in matches)


def _health_references(health: str, key: str) -> bool:
    return bool(
        re.search(
            r"(?:\$\{?" + re.escape(key) + r"\b|environ\[['\"]" + re.escape(key) + r"['\"]\])",
            health,
        )
    )


def discover(containers: list[Container]) -> list[Connection]:
    result: list[Connection] = []
    for c in sorted(containers, key=lambda c: (c.service, c.id)):
        edges: dict[tuple[str, int | None], list[Evidence]] = {}
        local_ports = _declared_local_ports(c)

        def add(endpoint, evidence):
            edges.setdefault(endpoint, [])
            if evidence not in edges[endpoint]:
                edges[endpoint].append(evidence)

        for key, value in sorted(c.env.items()):
            # Do not reinterpret a token or password as a destination.
            if _credential_key(key) or _configuration_role(key) or _disabled_endpoint(key, c):
                continue
            endpoint = parse_endpoint(value)
            if (
                endpoint
                and not _unspecified(endpoint[0])
                and not _local_admin_listener(key, endpoint)
                and not _ambiguous_loopback_environment(key, endpoint, c, local_ports)
            ):
                add(
                    endpoint,
                    Evidence(
                        "environment",
                        f"{safe_key(key)} specifies {endpoint[0]}:{endpoint[1]} (value omitted)",
                    ),
                )
            if key.upper().endswith("_HOST") and valid_host(value.strip()):
                port_value = c.env.get(key[:-5] + "_PORT", "")
                if port_value.isdecimal() and 1 <= int(port_value) <= 65535:
                    paired = (value.strip().lower(), int(port_value))
                    if (
                        _unspecified(paired[0])
                        or _local_admin_listener(key, paired)
                        or _ambiguous_loopback_environment(key, paired, c, local_ports)
                    ):
                        continue
                    add(
                        paired,
                        Evidence(
                            "environment",
                            f"{safe_key(key)} and {safe_key(key[:-5] + '_PORT')} specify a host and port (values omitted)",
                        ),
                    )
        for hint in c.config_hints:
            add((hint.host, hint.port), hint.evidence)
        for hint in c.log_hints:
            if hint.source_id != c.id:
                continue
            # Logs are historical observations, not configuration intentions.
            # A matching config edge supplies the intended port when a log omits it.
            if hint.port is not None and (hint.host, hint.port) not in edges:
                add(
                    (hint.host, hint.port),
                    Evidence(
                        "container_log",
                        "Recent application error mentions this endpoint; intended traffic is unconfirmed",
                    ),
                )
        health = " ".join(c.healthcheck)
        for value in _URL.findall(health):
            endpoint = parse_endpoint(value)
            if endpoint and _remote_health_endpoint(endpoint, c, containers):
                add(
                    endpoint,
                    Evidence(
                        "healthcheck",
                        "Configured healthcheck contains this remote endpoint (command omitted)",
                    ),
                )
        for key, value in sorted(c.env.items()):
            if _credential_key(key) or _configuration_role(key) == "template":
                continue
            endpoint = parse_endpoint(value)
            if (
                endpoint
                and _health_references(health, key)
                and _remote_health_endpoint(endpoint, c, containers)
            ):
                add(
                    endpoint,
                    Evidence(
                        "healthcheck", f"Healthcheck references {safe_key(key)} (command omitted)"
                    ),
                )
        supported_dependencies: set[str] = set()
        for observed_endpoint in list(edges):
            matches = resolve_hostname(observed_endpoint[0], containers)
            if any(d.service in c.depends_on for d in matches):
                supported_dependencies.update(
                    d.service for d in matches if d.service in c.depends_on
                )
                add(
                    observed_endpoint,
                    Evidence(
                        "depends_on",
                        "Compose dependency supports this intention; it does not prove traffic",
                    ),
                )
            elif len(c.depends_on) == 1 and (
                is_loopback(observed_endpoint[0])
                or not matches
                and "." not in observed_endpoint[0]
                and ":" not in observed_endpoint[0]
            ):
                supported_dependencies.add(c.depends_on[0])
                add(
                    observed_endpoint,
                    Evidence(
                        "depends_on",
                        "A single Compose dependency suggests a possible intended target; this association is unconfirmed",
                    ),
                )
        for dep in c.depends_on:
            if dep in supported_dependencies:
                continue
            if not any(
                any(d.service == dep for d in resolve_hostname(h, containers)) for h, _ in edges
            ):
                add(
                    (dep, None),
                    Evidence(
                        "depends_on",
                        "Compose dependency only; destination port and network intention are unconfirmed",
                    ),
                )
        for (host, port), evidence in sorted(
            edges.items(), key=lambda item: (item[0][0], item[0][1] or 0)
        ):
            result.append(Connection(c.id, c.service, host, port, tuple(evidence)))
    return result


def resolve_hostname(host: str, containers: list[Container]) -> list[Container]:
    host = host.lower().rstrip(".")
    return [
        c
        for c in containers
        if host
        in {
            c.service.lower(),
            c.name.lower(),
            *(a.lower() for n in c.networks.values() for a in (*n.aliases, *n.addresses)),
        }
    ]


def shared_networks(source: Container, destination: Container) -> tuple[str, ...]:
    # Network IDs are authoritative. Names alone may collide across snapshots.
    return tuple(
        sorted(
            n.name
            for n in source.networks.values()
            if n.id and any(n.id == d.id for d in destination.networks.values())
        )
    )


def reachable_alias(host: str, source: Container, destination: Container) -> bool:
    common = shared_networks(source, destination)
    host = host.lower().rstrip(".")
    return any(
        n.name in common
        and host
        in {
            destination.service.lower(),
            destination.name.lower(),
            *(x.lower() for x in (*n.aliases, *n.addresses)),
        }
        for n in destination.networks.values()
    )
