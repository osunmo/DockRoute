"""Prepare and optionally execute consumed faults in the validated private Mongo carrier.

Preparation copies only the registered private carrier; it starts no Docker resources.
Execution is sequential through run_corpus_live. Unknown/failed diagnostics are retained;
manual checks never count as automatic discovery. A published-host-port mutation is
explicitly unsupported because the safe runner allocates that port only during up.
"""

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import sys
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import run_corpus_live as live  # noqa: E402

KINDS = ("localhost", "wrong_hostname", "network_isolation", "loopback_listener")
EXPECTED_CODES = {
    "localhost": "WRONG_LOCALHOST",
    "wrong_hostname": "INVALID_SERVICE_HOSTNAME",
    "network_isolation": "NETWORK_ISOLATION",
    "loopback_listener": "LOOPBACK_ONLY_LISTENER",
}


class FaultSafetyError(ValueError):
    pass


def _write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _argument(value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if isinstance(value, dict):
        raw = json.dumps(value, sort_keys=True).encode()
        return copy.deepcopy(value), {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "scope": "canonical_json",
        }
    path = Path(value)
    raw = path.read_bytes()
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise FaultSafetyError("input_not_json_object")
    return parsed, {
        "path": str(path.absolute()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "scope": "file_bytes",
    }


def _private_path(destination: Path) -> Path:
    work = live._canonical(ROOT / "work")
    absolute = Path(os.path.abspath(destination))
    ancestor = absolute
    while not ancestor.exists():
        ancestor = ancestor.parent
    canonical_ancestor = live._canonical(ancestor)
    result = canonical_ancestor / absolute.relative_to(ancestor)
    if result == work or not result.is_relative_to(work):
        raise FaultSafetyError("destination_outside_private_work")
    return result


def _source_index(root: Path) -> dict[str, str]:
    result = {}
    for current, directories, files in os.walk(root, followlinks=False):
        for name in (*directories, *files):
            path = Path(current) / name
            attrs = path.lstat()
            if stat.S_ISLNK(attrs.st_mode) or getattr(attrs, "st_file_attributes", 0) & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024
            ):
                raise FaultSafetyError("carrier_links_unsupported")
            if path.is_file():
                result[path.relative_to(root).as_posix()] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
    return result


def _baseline(recipe: dict[str, Any], baseline: dict[str, Any]) -> dict[str, str]:
    http = baseline.get("http") or {}
    if (
        baseline.get("id") != recipe.get("id")
        or baseline.get("status") != "complete"
        or not http.get("ready")
        or http.get("http_status") != 200
        or http.get("body_pattern_matched") is not True
        or (baseline.get("cleanup") or {}).get("cleanup") != "complete"
    ):
        raise FaultSafetyError("baseline_not_application_validated")
    if not live.PROJECT_KEY.fullmatch(baseline.get("project", "")):
        raise FaultSafetyError("baseline_project_not_owned")
    if any(
        (baseline.get("provenance") or {}).get(key) != recipe.get(key)
        for key in ("upstream", "revision", "source_compose_sha256")
    ):
        raise FaultSafetyError("baseline_provenance_mismatch")
    fingerprints = []
    for phase in ("static", "probe"):
        diagnostic = (baseline.get("automatic") or {}).get(phase) or {}
        source = diagnostic.get("source") or {}
        hashes = (source.get("before") or {}).get("product_source_sha256")
        if (
            diagnostic.get("valid_for_grading") is not True
            or source.get("stable") is not True
            or not hashes
            or hashes != (source.get("after") or {}).get("product_source_sha256")
        ):
            raise FaultSafetyError("baseline_diagnostic_not_frozen")
        fingerprints.append(hashes)
    if fingerprints[0] != fingerprints[1]:
        raise FaultSafetyError("baseline_source_mismatch")
    return fingerprints[0]


def _consumers(config: dict[str, Any], root: Path) -> list[dict[str, str]]:
    try:
        web = config["services"]["web"]
        backend = config["services"]["backend"]
        if (
            web["environment"]["FLASK_SERVER_ADDR"] != "backend:9091"
            or backend["environment"]["FLASK_SERVER_PORT"] != "9091"
        ):
            raise FaultSafetyError("carrier_endpoint_changed")
        template = root / "nginx" / "nginx.conf"
        server = root / "flask" / "server.py"
        template_bytes, server_bytes = template.read_bytes(), server.read_bytes()
        command = web.get("command") or []
        command = command if isinstance(command, str) else " ".join(command)
        if (
            b"proxy_pass http://$FLASK_SERVER_ADDR;" not in template_bytes
            or "envsubst" not in command
        ):
            raise FaultSafetyError("carrier_endpoint_not_consumed")
        if (
            server_bytes.count(b"app.run(host='0.0.0.0'") != 1
            or b'os.environ.get("FLASK_SERVER_PORT"' not in server_bytes
            or b"client.admin.command('ismaster')" not in server_bytes
            or b"Hello from the MongoDB client" not in server_bytes
        ):
            raise FaultSafetyError("carrier_listener_or_database_consumer_changed")
        if not any(
            mount.get("target") == "/tmp/nginx.conf"
            and live._path(mount["source"], root) == live._canonical(template)
            for mount in web.get("volumes", [])
        ):
            raise FaultSafetyError("template_not_mounted")
        if live._path(
            backend["build"]["context"], root, directory=True, allow_root=True
        ) != live._canonical(root / "flask"):
            raise FaultSafetyError("backend_build_context_changed")
        return [
            {
                "path": "nginx/nginx.conf",
                "sha256": hashlib.sha256(template_bytes).hexdigest(),
                "consumes": "FLASK_SERVER_ADDR through envsubst proxy_pass",
            },
            {
                "path": "flask/server.py",
                "sha256": hashlib.sha256(server_bytes).hexdigest(),
                "consumes": "literal app.run host, FLASK_SERVER_PORT, Mongo admin command before success response",
            },
        ]
    except (KeyError, TypeError, OSError, live.SafetyError):
        raise FaultSafetyError("carrier_consumer_unavailable") from None


def _rebase(config: dict[str, Any], original: Path, copied: Path) -> dict[str, Any]:
    result = copy.deepcopy(config)

    def path(value: str, *, base: Path = original) -> str:
        source = Path(value)
        if not source.is_absolute():
            source = base / source
        resolved = live._path(source, original, allow_root=True)
        return str(copied / resolved.relative_to(original))

    for category in ("configs", "secrets"):
        for resource in result.get(category, {}).values():
            resource["file"] = path(resource["file"])
    for service in result["services"].values():
        build = service.get("build")
        if build:
            old_context = live._path(build["context"], original, directory=True, allow_root=True)
            build["context"] = path(str(old_context))
            if Path(build.get("dockerfile", "Dockerfile")).is_absolute():
                build["dockerfile"] = path(build["dockerfile"], base=old_context)
        for mount in service.get("volumes", []):
            if mount.get("type") == "bind":
                mount["source"] = path(mount["source"])
    return result


def prepare_fault_suite(
    carrier_recipe: Any, baseline_report: Any, destination: Path
) -> dict[str, Any]:
    recipe, recipe_artifact = _argument(carrier_recipe)
    baseline, baseline_artifact = _argument(baseline_report)
    pin = _baseline(recipe, baseline)
    try:
        original = live._canonical(recipe["root"])
        config_file = live._path(recipe["compose_file"], original)
        config = json.loads(config_file.read_text(encoding="utf-8"))
        sources = _source_index(original)
        evidence = _consumers(config, original)
        live.prepare_config(config, "dockroute-corpus-" + uuid.uuid4().hex, original)
    except (live.SafetyError, OSError, KeyError, TypeError):
        raise FaultSafetyError("carrier_not_private_normalized_configuration") from None
    destination = _private_path(destination)
    if destination.is_relative_to(original):
        raise FaultSafetyError("destination_inside_carrier")
    if destination.exists():
        raise FaultSafetyError("destination_already_exists")
    destination.mkdir(parents=True, exist_ok=False)
    baseline_link = {
        "id": baseline["id"],
        "project": baseline["project"],
        "artifact": baseline_artifact,
        "validated_http": baseline["http"],
        "application_validation": "HTTP success body is returned only after the source Mongo admin command succeeds",
    }
    manifest: dict[str, Any] = {
        "schema_version": "corpus-faults-1",
        "root": str(destination),
        "baseline": baseline_link,
        "carrier_recipe": recipe_artifact,
        "carrier_source_sha256": sources,
        "product_source_sha256": pin,
        "runner_sha256": hashlib.sha256(Path(live.__file__).read_bytes()).hexdigest(),
        "fault_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "mutations": [],
        "unsupported": [
            {
                "id": "published_host_port",
                "executed": False,
                "reason": "Dynamic localhost host ports are assigned only during creation; no same-project observed mapping can be safely consumed before up without changing the frozen lifecycle.",
            }
        ],
    }
    for kind in KINDS:
        scratch = destination / kind
        shutil.copytree(original, scratch)
        adapted = _rebase(config, original, scratch)
        fault_recipe = copy.deepcopy(recipe)
        fault_recipe.update(
            id=recipe["id"] + "-fault-" + kind,
            root=str(scratch),
            compose_file=str(scratch / "resolved-compose.json"),
            expected_body_pattern=None,
            readiness_timeout=15,
        )
        fault_recipe["annotations"] = [
            *recipe.get("annotations", []),
            f"Synthetic consumed upstream fault: {kind}; baseline {baseline['project']} artifact {baseline_artifact['sha256']}.",
        ]
        changes: list[dict[str, Any]] = []
        target = "backend:9091"
        intended_service = config["services"]["web"]["environment"]["FLASK_SERVER_ADDR"].rsplit(
            ":", 1
        )[0]
        if kind in {"localhost", "wrong_hostname"}:
            target = "127.0.0.1:9091" if kind == "localhost" else "backned:9091"
            adapted["services"]["web"]["environment"]["FLASK_SERVER_ADDR"] = target
            changes.append(
                {
                    "field": "services.web.environment.FLASK_SERVER_ADDR",
                    "before": "backend:9091",
                    "after": target,
                }
            )
            if kind == "wrong_hostname":
                fault_recipe["approved_external_endpoints"] = ["backned"]
        elif kind == "network_isolation":
            old_networks = copy.deepcopy(adapted["services"]["web"]["networks"])
            adapted["services"]["web"]["networks"] = {"fault_frontend": None}
            adapted.setdefault("networks", {})["fault_frontend"] = {"name": "fault_frontend"}
            changes.append(
                {
                    "field": "services.web.networks",
                    "before": old_networks,
                    "after": {"fault_frontend": None},
                }
            )
        else:
            server = scratch / "flask" / "server.py"
            before = server.read_bytes()
            after = before.replace(b"app.run(host='0.0.0.0'", b"app.run(host='127.0.0.1'", 1)
            server.write_bytes(after)
            changes.append(
                {
                    "file": "flask/server.py",
                    "before_sha256": hashlib.sha256(before).hexdigest(),
                    "after_sha256": hashlib.sha256(after).hexdigest(),
                    "before": "app.run host=0.0.0.0",
                    "after": "app.run host=127.0.0.1",
                }
            )
        unavailable = kind in {"wrong_hostname", "network_isolation"}
        fault_recipe["expected_statuses"] = [200] if unavailable else [502]
        fault_recipe["checks"] = [
            {"source": "backend", "target": "mongo:27017"},
            {"source": "web", "target": target},
        ]
        spec: dict[str, Any] = {
            "id": kind,
            "kind": kind,
            "synthetic": True,
            "changes": changes,
            "consumer_evidence": evidence,
            "recipe_file": str(scratch / "recipe.json"),
            "expected": {
                "http": "unavailable" if unavailable else 502,
                "source_state": "exited" if unavailable else "running",
                "source": "web",
                "host": target.rsplit(":", 1)[0],
                "port": 9091,
                "destination_service": intended_service,
                "diagnostic_code": EXPECTED_CODES[kind],
            },
        }
        fault_recipe["fault"] = {
            "kind": kind,
            "synthetic": True,
            "baseline": baseline_link,
            "changes": changes,
        }
        live.prepare_config(
            adapted,
            "dockroute-corpus-" + uuid.uuid4().hex,
            scratch,
            approved_external_endpoints=fault_recipe.get("approved_external_endpoints"),
        )
        _write(Path(fault_recipe["compose_file"]), adapted)
        _write(Path(spec["recipe_file"]), fault_recipe)
        spec["configuration_sha256"] = hashlib.sha256(
            Path(fault_recipe["compose_file"]).read_bytes()
        ).hexdigest()
        spec["prepared_source_sha256"] = _source_index(scratch)
        manifest["mutations"].append(spec)
    _write(destination / "manifest.json", manifest)
    return manifest


def _listener_proof(row: dict[str, Any], report: dict[str, Any], expected: dict[str, Any]) -> bool:
    """Bind listener evidence to this project's source and intended destination."""
    probe = row.get("probe") or {}
    project = expected.get("project")
    destination_service = expected.get("destination_service")
    if (
        not isinstance(project, str)
        or not live.PROJECT_KEY.fullmatch(project)
        or report.get("project") != project
        or not destination_service
        or row.get("destination_service") != destination_service
        or probe.get("listener_state") != "SUCCESS"
    ):
        return False
    execution = probe.get("execution_id")
    if not isinstance(execution, str) or not re.fullmatch(r"[0-9a-f]{32}", execution):
        return False
    tcp = probe.get("tcp")
    source_result_state = (
        {"refused": "TCP_REFUSED", "timeout": "TCP_TIMEOUT"}.get(tcp)
        if isinstance(tcp, str)
        else None
    )
    if source_result_state is None or probe.get("state") != source_result_state:
        return False
    services = report.get("services") or []
    trace = probe.get("trace") or []
    for role, service_name in (
        ("source", expected["source"]),
        ("destination", destination_service),
    ):
        matches = [service for service in services if service.get("service") == service_name]
        if len(matches) != 1:
            return False
        service = matches[0]
        identifier = service.get("container_id")
        if (
            service.get("state") != "running"
            or not isinstance(identifier, str)
            or not re.fullmatch(r"[0-9a-f]{64}", identifier)
            or role == "source"
            and row.get("source_container") != identifier
        ):
            return False
        completed = [
            step for step in trace if step.get("role") == role and step.get("state") == "SUCCESS"
        ]
        if not any(step.get("stage") == "namespace" for step in completed):
            return False
        result_state = source_result_state if role == "source" else "SUCCESS"
        if not any(
            step.get("role") == role
            and step.get("stage") == "result_parsing"
            and step.get("state") == result_state
            for step in trace
        ):
            return False
        if not any(
            step.get("stage") == "create"
            and (step.get("helper_configuration") or {}).get("network_mode")
            == "container:" + identifier
            and (step.get("helper_configuration") or {}).get("execution_id") == execution
            for step in completed
        ):
            return False
    addresses = probe.get("listener_addresses") or []
    try:
        return bool(
            probe.get("listener_verified") is True
            and addresses
            and all(ipaddress.ip_address(address).is_loopback for address in addresses)
            and probe.get("dns") == "ok"
            and probe.get("tcp") in {"refused", "timeout"}
        )
    except (TypeError, ValueError):
        return False


def _classify(
    diagnostic: dict[str, Any], expected: dict[str, Any], pin: dict[str, str]
) -> dict[str, Any]:
    source = diagnostic.get("source") or {}
    if diagnostic.get("valid_for_grading") is not True or source.get("stable") is not True:
        return {"classification": "ungraded", "missed_root_cause": None}
    if (source.get("before") or {}).get("product_source_sha256") != pin or (
        source.get("after") or {}
    ).get("product_source_sha256") != pin:
        return {"classification": "source_mismatch", "missed_root_cause": None}
    rows = [
        row
        for row in (diagnostic.get("report") or {}).get("findings", [])
        if row.get("source") == expected["source"]
        and row.get("destination") == expected["host"]
        and row.get("port") == expected["port"]
    ]
    correct = [row for row in rows if row.get("code") == expected["diagnostic_code"]]
    classification = (
        "missed_discovery"
        if not rows
        else "abstained"
        if all(row.get("code") == "UNKNOWN" for row in rows)
        else "different_diagnosis"
    )
    if correct:
        classification = "correct_root_cause"
        if expected["diagnostic_code"] == "LOOPBACK_ONLY_LISTENER":
            verified = any(
                _listener_proof(row, diagnostic.get("report") or {}, expected) for row in correct
            )
            if not verified:
                classification = "unverified_root_cause"
    return {
        "classification": classification,
        "missed_root_cause": classification != "correct_root_cause",
        "matching_codes": [row.get("code") for row in rows],
    }


def _manual_source(check: dict[str, Any]) -> str | None:
    if check.get("source_service"):
        return check["source_service"]
    if isinstance(check.get("source"), str):
        return check["source"]
    command = check.get("command") or []
    if "check" in command and command.index("check") + 1 < len(command):
        return command[command.index("check") + 1]
    sources = {row.get("source") for row in (check.get("report") or {}).get("findings", [])}
    return next(iter(sources)) if len(sources) == 1 else None


def assess_fault(case: dict[str, Any], raw: dict[str, Any], pin: dict[str, str]) -> dict[str, Any]:
    expected = {**case["expected"], "project": raw.get("project")}
    http = raw.get("http") or {}
    states = [
        service.get("state")
        for phase in (raw.get("automatic") or {}).values()
        for service in (phase.get("report") or {}).get("services", [])
        if service.get("service") == expected["source"]
    ]
    states.extend(
        container.get("state")
        for container in (raw.get("safety") or {}).get("inspected_containers", [])
        if container.get("service") == expected["source"]
    )
    observed = (
        (not http.get("ready") and "exited" in states)
        if expected["http"] == "unavailable"
        else bool(http.get("ready") and http.get("http_status") == expected["http"])
    )

    def grade(diagnostic: dict[str, Any]) -> dict[str, Any]:
        match = _classify(diagnostic, expected, pin)
        result = {**match, "diagnostic_match": match["classification"]}
        if not observed:
            result.update(classification="unvalidated_fault", missed_root_cause=None)
        return result

    return {
        "application_fault_observed": observed,
        "execution_class": "fault_execution_failure"
        if observed and expected["http"] == "unavailable"
        else "fault_http_failure"
        if observed
        else "fault_not_validated",
        "cleanup": (raw.get("cleanup") or {}).get("cleanup"),
        "automatic": {phase: grade(value) for phase, value in (raw.get("automatic") or {}).items()},
        "manual": [
            grade(check)
            for check in raw.get("manual_checks", [])
            if _manual_source(check) == expected["source"]
            and check.get("target") == f"{expected['host']}:{expected['port']}"
        ],
        "manual_counts_as_automatic_discovery": False,
    }


def run_fault_suite(
    manifest: dict[str, Any], *, allow_build=False, allow_pull=False
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": "corpus-faults-results-1",
        "baseline": manifest["baseline"],
        "product_source_sha256": manifest["product_source_sha256"],
        "cases": [],
        "unsupported": manifest["unsupported"],
        "not_run": [],
        "status": "complete",
    }
    if hashlib.sha256(Path(live.__file__).read_bytes()).hexdigest() != manifest["runner_sha256"]:
        raise FaultSafetyError("runner_changed_since_preparation")
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != manifest["fault_script_sha256"]:
        raise FaultSafetyError("fault_script_changed_since_preparation")
    root = _private_path(Path(manifest["root"]))
    for index, case in enumerate(manifest["mutations"]):
        recipe_file = live._path(case["recipe_file"], root)
        recipe = json.loads(recipe_file.read_text(encoding="utf-8"))
        recipe_root = live._canonical(recipe["root"])
        if recipe_root == root or not recipe_root.is_relative_to(root):
            raise FaultSafetyError("prepared_recipe_root_outside_suite")
        compose_file = live._path(recipe["compose_file"], recipe_root)
        if _source_index(recipe_root) != case["prepared_source_sha256"]:
            raise FaultSafetyError("prepared_source_changed")
        if hashlib.sha256(compose_file.read_bytes()).hexdigest() != case["configuration_sha256"]:
            raise FaultSafetyError("prepared_configuration_changed")
        raw = live.run_case(recipe, allow_build=allow_build, allow_pull=allow_pull)
        assessment = assess_fault(case, raw, manifest["product_source_sha256"])
        report["cases"].append({"mutation": case, "raw": raw, "assessment": assessment})
        _write(root / "results.json", report)
        if (raw.get("cleanup") or {}).get("cleanup") != "complete":
            report["status"] = "failed"
            report["not_run"] = [
                {"id": remaining["id"], "reason": "prior_cleanup_uncertain"}
                for remaining in manifest["mutations"][index + 1 :]
            ]
            break
        if not assessment["application_fault_observed"]:
            report["status"] = "failed"
    _write(root / "results.json", report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--carrier", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--allow-build", action="store_true")
    parser.add_argument("--allow-pull", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.manifest and not all((args.carrier, args.baseline, args.destination)):
        parser.error("provide --manifest or --carrier, --baseline and --destination")
    try:
        manifest = (
            json.loads(args.manifest.read_text(encoding="utf-8"))
            if args.manifest
            else prepare_fault_suite(args.carrier, args.baseline, args.destination)
        )
        report = (
            run_fault_suite(manifest, allow_build=args.allow_build, allow_pull=args.allow_pull)
            if args.execute
            else manifest
        )
    except (FaultSafetyError, live.SafetyError, OSError, KeyError, TypeError) as error:
        report = {
            "schema_version": "corpus-faults-results-1",
            "status": "refused",
            "error": str(error)
            if isinstance(error, FaultSafetyError)
            else "fault_boundary_failure",
        }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        _write(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("status", "complete") == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
