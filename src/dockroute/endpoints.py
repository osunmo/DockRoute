"""Parse connection endpoints without importing Docker or diagnostic components."""

import re
from urllib.parse import urlsplit

from dockroute.safety import valid_host

DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "postgres": 5432,
    "postgresql": 5432,
    "redis": 6379,
    "rediss": 6379,
    "mysql": 3306,
    "mongodb": 27017,
    "amqp": 5672,
    "amqps": 5671,
    "tcp": None,
}


def _network_scheme(scheme: str) -> str | None:
    """Normalize SQLAlchemy drivers and Celery's SQL result-backend wrapper."""
    scheme = scheme.lower()
    if scheme in DEFAULT_PORTS:
        return scheme
    wrapped = scheme.startswith("db+")
    if wrapped:
        scheme = scheme[3:]
    dialect, separator, driver = scheme.partition("+")
    # A '+' can change transport semantics (redis+sentinel, http+unix). Only
    # the supported SQL dialects use this convention for a client driver.
    if dialect not in {"postgres", "postgresql", "mysql"}:
        return None
    if separator and not re.fullmatch(r"[a-z][a-z0-9_.-]*", driver):
        return None
    return dialect if separator or wrapped else None


def parse_endpoint(value: str) -> tuple[str, int] | None:
    value = value.strip()
    if any(ord(c) < 32 for c in value):
        return None
    try:
        u = urlsplit(value if "://" in value else "//" + value)
        scheme = _network_scheme(u.scheme) if u.scheme else ""
        if u.scheme and scheme is None:
            return None
        host = u.hostname
        port = u.port if u.port is not None else DEFAULT_PORTS.get(scheme or "")
        if not host or not valid_host(host) or not port or not 1 <= port <= 65535:
            return None
        return host.rstrip(".").lower(), port
    except ValueError:
        return None
