"""Keep untrusted metadata bounded and credentials out of output."""

import ipaddress
import re
from urllib.parse import urlsplit

_HOST = re.compile(r"^[a-zA-Z0-9_.-]{1,253}$")
_KEY = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,127}$")


def safe_text(value: str, limit: int = 256) -> str:
    """Strip terminal control characters. This does not sanitize arbitrary secrets."""
    return "".join(c for c in str(value) if c.isprintable())[:limit]


def valid_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOST.fullmatch(host)) and not host.startswith("-")


def is_loopback(host: str) -> bool:
    if host.rstrip(".").lower() in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def safe_key(key: str) -> str:
    return key if _KEY.fullmatch(key) else "[environment variable]"


def safe_endpoint(value: str) -> str:
    """Allowlist only host and numeric port; omit userinfo, path, query and fragment."""
    try:
        u = urlsplit(value if "://" in value else "//" + value)
        if u.hostname and valid_host(u.hostname):
            host = u.hostname.lower()
            host = f"[{host}]" if ":" in host else host
            port = u.port
            return f"{host}:{port}" if port else host
    except ValueError:
        pass
    return "[redacted endpoint]"
