"""DockRoute: local-first Docker Compose connection diagnostics."""

from dockroute.docker import DockerUnavailable, diagnose_socket_access, diagnoseSocketAccess
from dockroute.endpoints import (
    NPIPE_GUIDANCE,
    UnsupportedSchemeError,
    parse_endpoint,
    validate_endpoint_scheme,
)

__version__ = "0.4.1"

__all__ = [
    "DockerUnavailable",
    "NPIPE_GUIDANCE",
    "UnsupportedSchemeError",
    "__version__",
    "diagnoseSocketAccess",
    "diagnose_socket_access",
    "parse_endpoint",
    "validate_endpoint_scheme",
]
