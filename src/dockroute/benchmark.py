"""Reproducible synthetic-fixture runner with measured behavior before diagnosis grading."""

import argparse
import contextlib
import io
import json
import platform
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from dockroute import __version__, cli
from dockroute.discovery import parse_endpoint
from dockroute.docker import DockerUnavailable, connect
from dockroute.safety import is_loopback


class FixtureSafetyError(ValueError):
    pass


def validate_fixture(config: dict, *, allow_fixed_ports=False, project=None):
    """Fail closed before creating resources; operate on Compose's resolved config."""
    if config.get("volumes") or config.get("secrets") or config.get("configs"):
        raise FixtureSafetyError(
            "Volumes, secrets and configs are refused by the benchmark runner."
        )
    for network in (config.get("networks") or {}).values():
        if (
            network.get("external")
            or network.get("driver", "bridge") != "bridge"
            or network.get("driver_opts")
        ):
            raise FixtureSafetyError("External networks and custom network drivers are refused.")
        name = network.get("name")
        if name and (not project or not name.startswith(project + "_")):
            raise FixtureSafetyError("Network names must belong to this fresh test project.")
    if not config.get("services"):
        raise FixtureSafetyError("Fixture contains no services.")
    for service in config["services"].values():
        if any(
            service.get(k)
            for k in (
                "volumes",
                "volumes_from",
                "devices",
                "device_cgroup_rules",
                "privileged",
                "cap_add",
                "network_mode",
                "pid",
                "ipc",
                "container_name",
                "build",
                "secrets",
                "configs",
                "external_links",
                "links",
                "extra_hosts",
                "extends",
            )
        ):
            raise FixtureSafetyError(
                "Shared namespaces, mounts, builds and fixed/shared resources are refused."
            )
        for port in service.get("ports") or []:
            if not isinstance(port, dict):
                raise FixtureSafetyError("Use resolved Compose JSON for port validation.")
            if port.get("host_ip") != "127.0.0.1":
                raise FixtureSafetyError("Benchmark host ports must bind only 127.0.0.1.")
            if port.get("published") and str(port["published"]) != "0" and not allow_fixed_ports:
                raise FixtureSafetyError(
                    "Fixed host ports require --allow-fixed-ports; ensure the port is unused."
                )


def validate_behavior(expected: str, observed: dict) -> bool:
    """A prewritten label is an expectation, never a measured result."""
    failed = observed.get("app_request") == "failed"
    if expected == "TCP_REACHABLE":
        return observed.get("app_request") == "ok" and observed.get("source_tcp") == "ok"
    if expected == "NETWORK_ISOLATION":
        return (
            failed
            and not observed.get("shared_networks")
            and observed.get("matched_destination") is True
        )
    if expected == "WRONG_LOCALHOST":
        return failed and is_loopback(observed.get("target_host", ""))
    if expected == "HOST_PORT_INSTEAD_OF_CONTAINER_PORT":
        return (
            failed
            and observed.get("port_mapping_match") is True
            and observed.get("source_tcp") != "ok"
        )
    if expected == "LOOPBACK_ONLY_LISTENER":
        addresses = observed.get("listener_addresses") or []
        return (
            failed
            and observed.get("listener_verified") is True
            and bool(addresses)
            and all(is_loopback(x) for x in addresses)
        )
    if expected == "INVALID_SERVICE_HOSTNAME":
        return (
            failed
            and observed.get("matched_destination") is False
            and observed.get("source_dns") == "failed"
        )
    return False


_REQUEST_OBSERVER = r"""
import json,os,signal,socket,sys,urllib.request
from urllib.parse import urlsplit
def expire(*args): raise TimeoutError()
signal.signal(signal.SIGALRM, expire)
signal.alarm(7)
result={"app_request":"unknown","source_dns":"unknown","source_tcp":"unknown"}
try:
    u=urlsplit(os.environ[json.loads(sys.argv[1])["variable"]])
    port=u.port or (443 if u.scheme=="https" else 80)
    try:
        socket.getaddrinfo(u.hostname,port,type=socket.SOCK_STREAM)
        result["source_dns"]="ok"
    except socket.gaierror: result["source_dns"]="failed"
    try:
        with socket.create_connection((u.hostname,port),timeout=2): pass
        result["source_tcp"]="ok"
    except ConnectionRefusedError: result["source_tcp"]="refused"
    except TimeoutError: result["source_tcp"]="timeout"
    except OSError: result["source_tcp"]="failed"
    try:
        with urllib.request.urlopen(os.environ[json.loads(sys.argv[1])["variable"]],timeout=2) as r:
            result["app_request"]="ok" if r.status==200 else "failed"
    except Exception: result["app_request"]="failed"
except Exception: pass
print(json.dumps(result),flush=True)
"""


def _command(arguments, *, timeout=180):
    return subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)


def _exec_json(container, program, payload):
    result = container.exec_run(["python", "-I", "-c", program, json.dumps(payload)])
    if result.exit_code != 0 or len(result.output) > 65536:
        raise RuntimeError("fixture observer failed")
    if payload.get("mode") in {"connect", "listen"}:
        from dockroute.probe_protocol import decode_worker_output

        return decode_worker_output(result.output, payload["mode"])
    return json.loads(result.output)


def _observe(inspector, project, expected):
    snapshot = inspector.snapshot(project)
    intended = expected["intended_edge"]
    source = next(c for c in snapshot if c.service == intended["source_service"])
    destination = next(c for c in snapshot if c.service == intended["destination_service"])
    variable = expected["observed_config"]["env_name"]
    endpoint = parse_endpoint(source.env[variable])
    assert endpoint is not None
    host, port = endpoint
    # These exec calls run only in fixture containers created by this runner.
    observed = _exec_json(
        inspector.client.containers.get(source.id), _REQUEST_OBSERVER, {"variable": variable}
    )
    program = Path(__file__).with_name("_probe_worker.py").read_text(encoding="utf-8")
    listener = _exec_json(
        inspector.client.containers.get(destination.id),
        program,
        {"mode": "listen", "port": intended["destination_port"], "timeout": 3},
    )
    aliases = {destination.service, destination.name}
    aliases.update(x for n in destination.networks.values() for x in (*n.aliases, *n.addresses))
    observed.update(listener)
    observed.update(
        {
            "target_host": host,
            "target_port": port,
            "source_health": source.health,
            "destination_health": destination.health,
            "shared_networks": sorted(set(source.networks) & set(destination.networks)),
            "matched_destination": host in aliases,
            "port_mapping_match": any(
                p.host == port and p.container != port and p.protocol == "tcp"
                for p in destination.ports
            ),
        }
    )
    return observed


def _diagnose(project, *, probe=False, binary=None):
    output = io.StringIO()
    arguments = ["doctor", "--project", project, "--format", "json"]
    if probe:
        arguments.append("--probe")
    if binary:
        result = _command([str(binary), *arguments], timeout=180)
        return {"exit_code": result.returncode, "report": json.loads(result.stdout)}
    with contextlib.redirect_stdout(output):
        exit_code = cli.main(arguments)
    return {"exit_code": exit_code, "report": json.loads(output.getvalue())}


def run_scenario(inspector, scenario: Path, *, allow_fixed_ports=False, binary=None):
    expected = yaml.safe_load((scenario / "expected.yaml").read_text(encoding="utf-8"))
    category = expected["expected_diagnosis"]
    project = "dockroute-test-" + uuid.uuid4().hex[:16]
    result = {
        "scenario": scenario.name,
        "project": project,
        "expected_diagnosis": category,
        "status": "failed",
        "behavior_validated": False,
        "cleanup": "not_needed",
    }
    compose = ["docker", "compose", "-p", project, "-f", str(scenario / "compose.yaml")]
    existing = inspector.client.api.containers(
        all=True, filters={"label": f"com.docker.compose.project={project}"}
    )
    if existing:
        raise FixtureSafetyError(
            "Generated test project unexpectedly already exists; refusing to reuse it."
        )
    configured = _command([*compose, "config", "--format", "json"], timeout=20)
    if configured.returncode:
        result["reason"] = "Compose could not resolve this fixture; raw output omitted."
        return result
    config = json.loads(configured.stdout)
    try:
        validate_fixture(config, allow_fixed_ports=allow_fixed_ports, project=project)
    except FixtureSafetyError as exc:
        result.update(status="skipped", reason=str(exc))
        return result
    # Freeze the reviewed normalized configuration; no re-reading mutable YAML at up/down.
    with tempfile.TemporaryDirectory(prefix="dockroute-test-") as directory:
        frozen = Path(directory) / "compose.json"
        frozen.write_text(json.dumps(config), encoding="utf-8")
        compose = ["docker", "compose", "-p", project, "-f", str(frozen)]
        try:
            result["cleanup"] = "pending"
            started = _command([*compose, "up", "-d"])
            if started.returncode:
                result["reason"] = (
                    "Compose up failed (image availability or host resource conflict); raw output omitted."
                )
                return result
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                snapshot = inspector.snapshot(project)
                if snapshot and all(
                    c.state == "running" and c.health not in {"starting", "none"} for c in snapshot
                ):
                    break
                time.sleep(0.5)
            else:
                result["reason"] = "Fixture healthchecks did not settle before the deadline."
                return result
            # Observe first, grade later. Expected labels never enter the diagnostic engine.
            observations = _observe(inspector, project, expected)
            result["observations"] = observations
            result["behavior_validated"] = validate_behavior(category, observations)
            result["static"] = _diagnose(project, binary=binary)
            result["active"] = _diagnose(project, probe=True, binary=binary)
            intended = expected["intended_edge"]

            def target_codes(track):
                return [
                    f["code"]
                    for f in track["report"].get("findings", [])
                    if f["source"] == intended["source_service"] and f["port"] is not None
                ]

            static_codes = target_codes(result["static"])
            active_codes = target_codes(result["active"])
            result["static_expected_observed"] = category in static_codes
            result["active_expected_observed"] = category in active_codes
            # Static TCP_REACHABLE/LOOPBACK results require evidence it cannot acquire. UNKNOWN is correct.
            static_ok = category in static_codes or (
                category in {"TCP_REACHABLE", "LOOPBACK_ONLY_LISTENER"}
                and static_codes
                and set(static_codes) == {"UNKNOWN"}
            )
            no_false_positive = category != "TCP_REACHABLE" or set(active_codes) == {
                "TCP_REACHABLE"
            }
            result["status"] = (
                "passed"
                if result["behavior_validated"]
                and static_ok
                and category in active_codes
                and no_false_positive
                else "failed"
            )
            return result
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, StopIteration):
            result["reason"] = (
                "Scenario observation or diagnosis failed; no benchmark result was inferred."
            )
            return result
        finally:
            if result["cleanup"] == "pending":
                try:
                    cleaned = _command([*compose, "down", "--timeout", "5"], timeout=30)
                    result["cleanup"] = "complete" if cleaned.returncode == 0 else "failed"
                except (OSError, subprocess.SubprocessError):
                    result["cleanup"] = "failed"
                if result["cleanup"] == "failed":
                    result["status"] = "failed"
                    result["reason"] = (
                        "Cleanup failed; inspect only resources labeled with this result's project name."
                    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenarios", type=Path, default=Path("scenarios"))
    parser.add_argument("--scenario", help="Run one scenario directory by name")
    parser.add_argument(
        "--binary", type=Path, help="Test this standalone executable instead of the source CLI"
    )
    parser.add_argument("--output", type=Path, default=Path("outputs/benchmark.json"))
    parser.add_argument(
        "--allow-fixed-ports",
        action="store_true",
        help="Allow fixture localhost host-port binds; ensure port 18000 is unused",
    )
    args = parser.parse_args(argv)
    scenarios = sorted(
        p.parent
        for p in args.scenarios.glob("*/expected.yaml")
        if (p.parent / "compose.yaml").is_file()
    )
    if args.scenario:
        scenarios = [s for s in scenarios if s.name == args.scenario]
    report: dict = {
        "schema_version": "1.0",
        "suite": "synthetic-starter-fixtures",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": platform.platform(),
        "versions": {"dockroute": __version__, "docker": None, "compose": None},
        "status": "failed",
        "results": [],
    }
    inspector = None
    exit_code = 1
    try:
        try:
            compose_version = _command(["docker", "compose", "version", "--short"], timeout=10)
            if compose_version.returncode == 0:
                report["versions"]["compose"] = compose_version.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        if not scenarios:
            report["reason"] = "No matching fixture directories found."
            return 4
        inspector = connect(timeout=10)
        report["versions"]["docker"] = inspector.version().get("Version")
        if not report["versions"]["compose"]:
            raise DockerUnavailable("Docker Compose CLI is required for this suite.")
        for scenario in scenarios:
            print(f"Measuring {scenario.name} ...", flush=True)
            report["results"].append(
                run_scenario(
                    inspector,
                    scenario.resolve(),
                    allow_fixed_ports=args.allow_fixed_ports,
                    binary=args.binary.resolve() if args.binary else None,
                )
            )
        statuses = {r["status"] for r in report["results"]}
        report["status"] = (
            "passed"
            if statuses == {"passed"}
            else "incomplete"
            if "skipped" in statuses and "failed" not in statuses
            else "failed"
        )
        exit_code = (
            0 if report["status"] == "passed" else 2 if report["status"] == "incomplete" else 1
        )
    except DockerUnavailable:
        report["status"] = "unavailable"
        report["results"] = [
            {
                "scenario": s.name,
                "status": "skipped",
                "behavior_validated": False,
                "reason": "Docker Engine or Compose is unavailable; runtime behavior was not verified.",
            }
            for s in scenarios
        ]
        exit_code = 3
    except KeyboardInterrupt:
        report["status"] = "cancelled"
        exit_code = 130
    finally:
        if inspector:
            inspector.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Benchmark report: {args.output} ({report['status']})", flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
