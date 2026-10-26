"""DockRoute: local-first Docker Compose connection diagnostics."""

__version__ = "0.4.0"

__all__ = [
    "__version__",
    "DockerUnavailable",
    "diagnose_socket_access",
    "diagnoseSocketAccess",
]


def __getattr__(name):
    if name in {"DockerUnavailable", "diagnose_socket_access", "diagnoseSocketAccess"}:
        from dockroute.docker import DockerUnavailable, diagnose_socket_access, diagnoseSocketAccess

        return {
            "DockerUnavailable": DockerUnavailable,
            "diagnose_socket_access": diagnose_socket_access,
            "diagnoseSocketAccess": diagnoseSocketAccess,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
