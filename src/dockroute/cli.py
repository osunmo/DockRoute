"""CLI orchestration. Static mode never creates, starts, execs or removes containers."""

import argparse
import sys
from pathlib import Path

from dockroute import __version__


def connect(*, timeout: float = 5):
    """Load the SDK only for a validated command; retain a narrow injection seam."""
    from dockroute.docker import connect as docker_connect

    return docker_connect(timeout=timeout)


def diagnose(connection, containers, probe=None):
    """Keep static analysis lazy and independently replaceable by CLI consumers."""
    from dockroute.diagnostics import diagnose as diagnose_connection

    return diagnose_connection(connection, containers, probe)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(4, f"dockroute: {message}\n")


def _seconds(text):
    try:
        value = float(text)
        if 0.1 <= value <= 60:
            return value
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("timeout must be between 0.1 and 60 seconds")


def parser() -> Parser:
    root = Parser(
        description="Lint Docker Compose network configuration and optionally probe TCP reachability."
    )
    root.add_argument("--version", action="version", version=f"DockRoute {__version__}")
    sub = root.add_subparsers(dest="command", required=True, parser_class=Parser)
    for name, description in (
        ("doctor", "Discover intended connections in the current Compose project."),
        ("check", "Investigate an explicit source service and HOST:PORT endpoint."),
    ):
        cmd = sub.add_parser(name, description=description, help=description)
        if name == "check":
            cmd.add_argument(
                "source",
                help="Service name, container name or container ID in the selected project",
            )
            cmd.add_argument(
                "target",
                help="HOST:PORT (bracket IPv6); URL credentials and paths are not accepted",
            )
        cmd.add_argument(
            "--project",
            help="Exact Compose project name; required when directory matching is absent or ambiguous",
        )
        cmd.add_argument("--format", choices=("terminal", "json"), default="terminal")
        cmd.add_argument(
            "--probe",
            action="store_true",
            help="Opt in to bounded temporary helper containers for DNS/TCP/listener checks",
        )
        cmd.add_argument(
            "--timeout",
            type=_seconds,
            default=5.0,
            help="Worker network/execution deadline in seconds after readiness (default: 5)",
        )
        cmd.add_argument(
            "--dns-timeout",
            type=_seconds,
            default=2.0,
            help="DNS lookup deadline within the total execution budget (default: 2)",
        )
        cmd.add_argument(
            "--connect-timeout",
            type=_seconds,
            default=1.0,
            help="Each TCP connection deadline within the total execution budget (default: 1)",
        )
        cmd.add_argument(
            "--startup-timeout",
            type=_seconds,
            default=15.0,
            help="Helper readiness deadline, independent of network execution (default: 15)",
        )
        cmd.add_argument(
            "--verbose",
            action="store_true",
            help="Show sanitized probe stage, configuration, timing, stderr and cleanup details",
        )
        cmd.add_argument(
            "--timing",
            action="store_true",
            help="Include worker clocks and normalized Docker request timings",
        )
        cmd.add_argument(
            "--observe",
            choices=("poll",),
            default="poll",
            help="Worker readiness observation transport",
        )
        cmd.add_argument(
            "--schedule",
            choices=("sequential", "conditional"),
            default="conditional",
            help="Source/destination scheduling; conditional skips unnecessary listener checks (default: conditional)",
        )
        cmd.add_argument("--_benchmark-control", type=Path, help=argparse.SUPPRESS)
        cmd.add_argument(
            "--api-timeout",
            type=_seconds,
            default=5.0,
            help="Docker API request timeout in seconds (default: 5)",
        )
        cmd.add_argument(
            "--probe-image",
            default="python:3.12-alpine",
            help="Locally available Linux Python helper image; never pulled automatically",
        )
    return root


def _error(args, code, message, exit_code, trace=()):
    if args.format == "json":
        import json
        from dataclasses import asdict

        print(
            json.dumps(
                {
                    "schema_version": "3.0",
                    "dockroute_version": __version__,
                    "error": {"code": code, "message": message},
                    **({"probe_trace": [asdict(t) for t in trace]} if trace else {}),
                }
            )
        )
    else:
        print(f"dockroute: {message}", file=sys.stderr)
        if args.verbose:
            for step in trace:
                print(
                    f"  {step.role}.{step.stage}: {step.state}; cleanup={step.cleanup or 'unknown'}; error={step.error_type or 'none'}",
                    file=sys.stderr,
                )
    return exit_code


def main(argv: list[str] | None = None) -> int:
    from time import perf_counter

    began = perf_counter()
    root = parser()
    args = root.parse_args(argv)
    endpoint = None
    if args.command == "check":
        if any(x in args.target for x in ("/", "@", "?", "#")):
            root.error("target must be HOST:PORT without credentials or a URL path")
        from dockroute.endpoints import parse_endpoint

        endpoint = parse_endpoint(args.target)
        if not endpoint:
            root.error("target must be a valid HOST:PORT, with port 1 through 65535")
    from dockroute.compose import ProjectError, select_project
    from dockroute.discovery import discover
    from dockroute.docker import DockerUnavailable
    from dockroute.models import Connection, Evidence
    from dockroute.reporting import make_report, render_json, render_terminal, report_exit_code

    inspector, prober, timing, control = None, None, None, None
    try:
        inspector = connect(timeout=args.api_timeout)
        if args.timing:
            from dockroute.timings import RequestTimings

            timing = RequestTimings(getattr(inspector.client, "api", None))
        project = select_project(inspector.identities(), cwd=Path.cwd(), requested=args.project)
        containers = inspector.snapshot(project)
        if not containers:
            raise ProjectError(
                "The selected project has no inspectable service containers. Retry after Compose starts."
            )
        # The official Inspector adds only bounded selected-project evidence.
        # Some SDK-free embedders inject a minimal inspector in this test seam.
        supplement = getattr(inspector, "supplement_snapshot", None)
        if supplement is not None:
            containers = supplement(containers)
        if args.command == "doctor":
            edges = discover(containers)
        else:
            assert endpoint is not None
            sources = [c for c in containers if args.source in {c.service, c.id, c.name}]
            if len(sources) != 1:
                return _error(
                    args,
                    "SOURCE_SELECTION",
                    "Source is missing or ambiguous in the selected project. Use a full container name or ID for replicas.",
                    4,
                )
            edges = [
                Connection(
                    sources[0].id,
                    sources[0].service,
                    endpoint[0],
                    endpoint[1],
                    (Evidence("manual", "User explicitly requested this endpoint"),),
                    True,
                )
            ]
        version = inspector.version()
        if args.probe:
            from dockroute.probes import Prober

            prober = Prober(
                inspector.client,
                project,
                timeout=args.timeout,
                dns_timeout=args.dns_timeout,
                connect_timeout=args.connect_timeout,
                startup_timeout=args.startup_timeout,
                image=args.probe_image,
                engine_os=version.get("Os", "unknown"),
                timings=timing or False,
                observe=args.observe,
                schedule=args.schedule,
            )
            if args._benchmark_control:
                from dockroute.benchmark_control import BenchmarkControl

                try:
                    control = BenchmarkControl(
                        args._benchmark_control, prober.execution_id, project
                    )
                except (OSError, ValueError):
                    return _error(
                        args,
                        "BENCHMARK_CONTROL",
                        "Private benchmark control could not be initialized; no probe helpers were created.",
                        4,
                    )
                prober.benchmark_control = control
            import math
            import os

            override = os.environ.get("DOCKROUTE_HELPER_CPUS")
            if override is not None:
                try:
                    cpus = float(override)
                    if not math.isfinite(cpus) or not 0 <= cpus <= 64:
                        raise ValueError()
                except ValueError:
                    return _error(
                        args,
                        "INVALID_DEBUG_OVERRIDE",
                        "DOCKROUTE_HELPER_CPUS must be finite and between 0 and 64; 0 means unlimited.",
                        4,
                    )
                prober.cpu_limit = cpus
                print(
                    "Warning: debug-only DOCKROUTE_HELPER_CPUS overrides the helper CPU safety limit for this execution.",
                    file=sys.stderr,
                )
        if prober:
            # Only pure snapshot analysis enters this thread. Engine operations
            # stay on the main thread so cancellation still reaches owned cleanup.
            from concurrent.futures import ThreadPoolExecutor

            findings = []
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="dockroute-static") as pool:
                for edge in edges:
                    static = pool.submit(diagnose, edge, containers)
                    checked = prober.check(edge, containers, static_finding=static.result)
                    static.result()
                    findings.append(diagnose(edge, containers, checked))
        else:
            findings = [diagnose(edge, containers) for edge in edges]
        report = make_report(
            project,
            containers,
            findings,
            probe=args.probe,
            docker_version=version.get("Version", "unknown"),
            total_ms=(perf_counter() - began) * 1000,
            timing=args.timing,
            requests=timing.summary() if timing else [],
        )
        print(
            render_json(report)
            if args.format == "json"
            else render_terminal(report, verbose=args.verbose),
            end="",
        )
        return report_exit_code(report)
    except DockerUnavailable as exc:
        return _error(args, "DOCKER_UNAVAILABLE", str(exc), 3)
    except ProjectError as exc:
        return _error(args, "PROJECT_SELECTION", str(exc), 4)
    except RuntimeError as exc:
        from dockroute.probes import ProbeCleanupError

        if isinstance(exc, ProbeCleanupError):
            return _error(args, "PROBE_CLEANUP", str(exc), 5, trace=exc.trace)
        raise
    except KeyboardInterrupt:
        return _error(args, "CANCELLED", "Cancelled; temporary helper cleanup was attempted.", 130)
    finally:
        if control:
            control.close()
        if prober:
            prober.close()
        if timing:
            timing.close()
        if inspector:
            inspector.close()
