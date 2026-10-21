"""Consumed upstream mutations and honest scoring, with no Docker execution."""

import copy
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from dockroute.diagnostics import diagnose
from dockroute.models import Connection, Container, Network, Port, ProbeResult, ProbeTrace
from dockroute.reporting import make_report


@pytest.fixture
def faults():
    path = Path(__file__).resolve().parents[1] / "scripts" / "run_corpus_faults.py"
    assert path.is_file(), "reproducible consumed fault runner is missing"
    spec = importlib.util.spec_from_file_location("corpus_faults", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def carrier(tmp_path):
    root = tmp_path / "carrier"
    (root / "flask").mkdir(parents=True)
    (root / "nginx").mkdir()
    (tmp_path / "work").mkdir()
    (root / "flask" / "server.py").write_bytes(
        b"client.admin.command('ismaster')\n"
        b'return "Hello from the MongoDB client!\\n"\n'
        b"app.run(host='0.0.0.0', port=os.environ.get(\"FLASK_SERVER_PORT\", 9090), debug=True)\n"
    )
    (root / "flask" / "Dockerfile").write_text('FROM scratch\nCMD ["python3", "server.py"]\n')
    (root / "nginx" / "nginx.conf").write_text("proxy_pass http://$FLASK_SERVER_ADDR;\n")
    config = {
        "services": {
            "web": {
                "image": "nginx",
                "command": ["envsubst < /tmp/nginx.conf > /etc/nginx/conf.d/default.conf && nginx"],
                "environment": {"FLASK_SERVER_ADDR": "backend:9091"},
                "depends_on": {"backend": {"condition": "service_started"}},
                "networks": {"default": None},
                "ports": [{"target": 80, "published": "80"}],
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(root / "nginx" / "nginx.conf"),
                        "target": "/tmp/nginx.conf",
                    }
                ],
            },
            "backend": {
                "build": {"context": str(root / "flask"), "dockerfile": "Dockerfile"},
                "environment": {"FLASK_SERVER_PORT": "9091"},
                "networks": {"default": None},
                "volumes": [{"type": "bind", "source": str(root / "flask"), "target": "/src"}],
            },
            "mongo": {"image": "mongo", "networks": {"default": None}},
        },
        "networks": {"default": {"name": "old-default"}},
    }
    compose = root / "resolved-compose.json"
    compose.write_text(json.dumps(config))
    recipe = {
        "id": "awesome-nginx-flask-mongo",
        "upstream": "https://github.com/docker/awesome-compose",
        "revision": "a" * 40,
        "source_compose_sha256": "b" * 64,
        "root": str(root),
        "compose_file": str(compose),
        "incoming_service": "web",
        "incoming_port": 80,
        "expected_statuses": [200],
        "expected_body_pattern": "Hello from the MongoDB client",
        "checks": [
            {"source": "backend", "target": "mongo:27017"},
            {"source": "web", "target": "backend:9091"},
        ],
    }
    state = {"product_source_sha256": {"cli.py": "c" * 64}}
    diagnostic = {
        "valid_for_grading": True,
        "source": {"stable": True, "before": state, "after": state},
    }
    baseline = {
        "id": recipe["id"],
        "project": "dockroute-corpus-" + "d" * 32,
        "status": "complete",
        "http": {"ready": True, "http_status": 200, "body_pattern_matched": True},
        "cleanup": {"cleanup": "complete"},
        "provenance": {
            key: recipe[key] for key in ("upstream", "revision", "source_compose_sha256")
        },
        "automatic": {"static": copy.deepcopy(diagnostic), "probe": copy.deepcopy(diagnostic)},
    }
    return recipe, baseline


def prepared(faults, carrier, tmp_path, monkeypatch):
    monkeypatch.setattr(faults, "ROOT", tmp_path)
    recipe, baseline = carrier
    return faults.prepare_fault_suite(recipe, baseline, tmp_path / "work" / "faults")


def test_faults_mutate_consumed_fields_and_rebase_all_source_paths(
    faults, carrier, tmp_path, monkeypatch
):
    original = Path(carrier[0]["compose_file"]).read_bytes()
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    cases = {case["id"]: case for case in manifest["mutations"]}
    assert set(cases) == {"localhost", "wrong_hostname", "network_isolation", "loopback_listener"}
    for case in cases.values():
        recipe = json.loads(Path(case["recipe_file"]).read_text())
        config = json.loads(Path(recipe["compose_file"]).read_text())
        scratch = Path(recipe["root"])
        assert Path(config["services"]["backend"]["build"]["context"]).is_relative_to(scratch)
        for service in config["services"].values():
            for mount in service.get("volumes", []):
                assert Path(mount["source"]).is_relative_to(scratch)
        assert recipe["fault"]["synthetic"] is True
        assert case["consumer_evidence"]
    localhost_recipe = json.loads(Path(cases["localhost"]["recipe_file"]).read_text())
    localhost = json.loads(Path(localhost_recipe["compose_file"]).read_text())
    assert localhost["services"]["web"]["environment"]["FLASK_SERVER_ADDR"] == "127.0.0.1:9091"
    assert localhost_recipe["checks"][1]["target"] == "127.0.0.1:9091"
    assert localhost_recipe["expected_statuses"] == [502]
    assert localhost_recipe["expected_body_pattern"] is None
    wrong_recipe = json.loads(Path(cases["wrong_hostname"]["recipe_file"]).read_text())
    assert wrong_recipe["approved_external_endpoints"] == ["backned"]
    isolated_recipe = json.loads(Path(cases["network_isolation"]["recipe_file"]).read_text())
    isolated = json.loads(Path(isolated_recipe["compose_file"]).read_text())
    assert set(isolated["services"]["web"]["networks"]).isdisjoint(
        isolated["services"]["backend"]["networks"]
    )
    loopback_recipe = json.loads(Path(cases["loopback_listener"]["recipe_file"]).read_text())
    assert (
        b"app.run(host='127.0.0.1'"
        in (Path(loopback_recipe["root"]) / "flask" / "server.py").read_bytes()
    )
    assert Path(carrier[0]["compose_file"]).read_bytes() == original
    assert (
        b"app.run(host='0.0.0.0'" in (Path(carrier[0]["root"]) / "flask" / "server.py").read_bytes()
    )
    assert manifest["unsupported"][0]["id"] == "published_host_port"
    assert manifest["unsupported"][0]["executed"] is False


@pytest.mark.parametrize(
    "failure", ["http", "source", "cleanup", "consumer", "outside_destination", "outside_mount"]
)
def test_unvalidated_baselines_unused_env_and_unconfined_paths_are_refused(
    faults, carrier, tmp_path, monkeypatch, failure
):
    recipe, baseline = carrier
    destination = tmp_path / "work" / "faults"
    monkeypatch.setattr(faults, "ROOT", tmp_path)
    if failure == "http":
        baseline["http"]["body_pattern_matched"] = False
    elif failure == "source":
        baseline["automatic"]["probe"]["source"]["stable"] = False
    elif failure == "cleanup":
        baseline["cleanup"]["cleanup"] = "failed"
    elif failure == "consumer":
        (Path(recipe["root"]) / "nginx" / "nginx.conf").write_text(
            "proxy_pass http://backend:9091;"
        )
    elif failure == "outside_destination":
        destination = tmp_path / "outside"
    else:
        config = json.loads(Path(recipe["compose_file"]).read_text())
        config["services"]["web"]["volumes"][0]["source"] = str(tmp_path / "outside-secret")
        Path(recipe["compose_file"]).write_text(json.dumps(config))
    with pytest.raises(faults.FaultSafetyError):
        faults.prepare_fault_suite(recipe, baseline, destination)
    assert not destination.exists()


def diagnostic(code, source="web", destination="backend", port=9091):
    return {
        "valid_for_grading": True,
        "cleanup": "complete",
        "source": {
            "stable": True,
            "before": {"product_source_sha256": {"cli.py": "c" * 64}},
            "after": {"product_source_sha256": {"cli.py": "c" * 64}},
        },
        "report": {
            "findings": [
                {
                    "source": source,
                    "destination": destination,
                    "port": port,
                    "code": code,
                    "status": "UNKNOWN" if code == "UNKNOWN" else "NETWORK_FAILURE",
                }
            ],
            "services": [{"service": "web", "state": "exited"}],
        },
    }


def verified_listener_diagnostic():
    result = diagnostic("LOOPBACK_ONLY_LISTENER")
    project = "dockroute-corpus-" + "d" * 32
    source = Container(
        "a" * 64,
        "web-container",
        project,
        "web",
        state="running",
        networks={"default": Network("default", "network-id", ("web",), ("10.0.0.2",))},
    )
    destination = Container(
        "b" * 64,
        "backend-container",
        project,
        "backend",
        state="running",
        networks={"default": Network("default", "network-id", ("backend",), ("10.0.0.3",))},
        ports=(Port(9091),),
    )
    trace = tuple(
        step
        for role, identifier in (("source", source.id), ("destination", destination.id))
        for step in (
            ProbeTrace(role, "namespace", "SUCCESS", 1.0),
            ProbeTrace(
                role,
                "create",
                "SUCCESS",
                1.0,
                helper_configuration={
                    "network_mode": "container:" + identifier,
                    "execution_id": "e" * 32,
                },
            ),
            ProbeTrace(
                role, "result_parsing", "TCP_REFUSED" if role == "source" else "SUCCESS", 1.0
            ),
        )
    )
    probe = ProbeResult(
        dns="ok",
        tcp="refused",
        addresses=("10.0.0.3",),
        dns_equivalent=True,
        listener_addresses=("127.0.0.1",),
        listener_verified=True,
        listener_state="SUCCESS",
        state="TCP_REFUSED",
        execution_id="e" * 32,
        trace=trace,
    )
    edge = Connection(source.id, source.service, "backend", 9091, explicit=True)
    finding = diagnose(edge, [source, destination], probe)
    assert finding.code == "LOOPBACK_ONLY_LISTENER"
    result["report"] = make_report(project, [source, destination], [finding], probe=True)
    return result


def test_exited_fault_and_unknown_diagnostic_are_retained_as_automatic_abstention(
    faults, carrier, tmp_path, monkeypatch
):
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    case = next(c for c in manifest["mutations"] if c["id"] == "network_isolation")
    raw = {
        "status": "failed",
        "http": {"ready": False},
        "cleanup": {"cleanup": "complete"},
        "automatic": {"static": diagnostic("UNKNOWN"), "probe": diagnostic("UNKNOWN")},
        "manual_checks": [
            {
                "source": "web",
                "target": "backend:9091",
                "discovery": "manual_only",
                **diagnostic("NETWORK_ISOLATION"),
            }
        ],
    }
    assessment = faults.assess_fault(case, raw, manifest["product_source_sha256"])
    assert assessment["application_fault_observed"] is True
    assert assessment["execution_class"] == "fault_execution_failure"
    assert assessment["automatic"]["probe"]["classification"] == "abstained"
    assert assessment["automatic"]["probe"]["missed_root_cause"] is True
    assert assessment["manual"][0]["classification"] == "correct_root_cause"
    assert raw["automatic"]["probe"]["report"]["findings"][0]["code"] == "UNKNOWN"


def test_manual_only_success_is_a_missed_automatic_discovery(
    faults, carrier, tmp_path, monkeypatch
):
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    case = next(c for c in manifest["mutations"] if c["id"] == "localhost")
    automatic = diagnostic("UNKNOWN", destination="127.0.0.1")
    automatic["report"]["findings"] = []
    raw = {
        "project": "dockroute-corpus-" + "d" * 32,
        "http": {"ready": True, "http_status": 502},
        "cleanup": {"cleanup": "complete"},
        "automatic": {"probe": automatic},
        "manual_checks": [
            {
                "source": "web",
                "target": "127.0.0.1:9091",
                "discovery": "manual_only",
                **diagnostic("WRONG_LOCALHOST", destination="127.0.0.1"),
            }
        ],
    }
    assessment = faults.assess_fault(case, raw, manifest["product_source_sha256"])
    assert assessment["automatic"]["probe"]["classification"] == "missed_discovery"
    assert assessment["manual"][0]["classification"] == "correct_root_cause"


def test_listener_label_requires_destination_listener_evidence(
    faults, carrier, tmp_path, monkeypatch
):
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    case = next(c for c in manifest["mutations"] if c["id"] == "loopback_listener")
    finding = diagnostic("LOOPBACK_ONLY_LISTENER")
    raw = {
        "project": "dockroute-corpus-" + "d" * 32,
        "http": {"ready": True, "http_status": 502},
        "cleanup": {"cleanup": "complete"},
        "automatic": {"probe": finding},
    }
    assessed = faults.assess_fault(case, raw, manifest["product_source_sha256"])
    assert assessed["automatic"]["probe"]["classification"] == "unverified_root_cause"
    raw["automatic"]["probe"] = verified_listener_diagnostic()
    assessed = faults.assess_fault(case, raw, manifest["product_source_sha256"])
    assert assessed["automatic"]["probe"]["classification"] == "correct_root_cause"


def test_suite_preserves_raw_cases_and_stops_after_uncertain_cleanup(
    faults, carrier, tmp_path, monkeypatch
):
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    called = []
    raw = {
        "status": "failed",
        "cleanup": {"cleanup": "failed"},
        "automatic": {},
        "http": {"ready": False},
    }

    def run(recipe, **kwargs):
        called.append(recipe["fault"]["kind"])
        return copy.deepcopy(raw)

    monkeypatch.setattr(faults.live, "run_case", run)
    report = faults.run_fault_suite(manifest)
    assert called == ["localhost"]
    assert report["cases"][0]["raw"] == raw
    assert report["status"] == "failed"
    assert len(report["not_run"]) == 3


def test_prepared_source_changes_are_refused_before_any_fault_launch(
    faults, carrier, tmp_path, monkeypatch
):
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    first = manifest["mutations"][0]
    recipe = json.loads(Path(first["recipe_file"]).read_text())
    (Path(recipe["root"]) / "flask" / "server.py").write_text("# unexpectedly changed")
    calls = []
    monkeypatch.setattr(faults.live, "run_case", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(faults.FaultSafetyError):
        faults.run_fault_suite(manifest)
    assert calls == []


def test_destination_inside_carrier_is_refused_before_recursive_copy(
    faults, carrier, tmp_path, monkeypatch
):
    monkeypatch.setattr(faults, "ROOT", tmp_path)
    recipe, baseline = carrier
    original = Path(recipe["root"])
    relocated = tmp_path / "work" / "carrier"
    shutil.copytree(original, relocated)
    config = faults._rebase(
        json.loads(Path(recipe["compose_file"]).read_text()), original, relocated
    )
    recipe.update(root=str(relocated), compose_file=str(relocated / "resolved-compose.json"))
    Path(recipe["compose_file"]).write_text(json.dumps(config))
    copied = []
    monkeypatch.setattr(faults.shutil, "copytree", lambda *args, **kwargs: copied.append(args))
    with pytest.raises(faults.FaultSafetyError):
        faults.prepare_fault_suite(recipe, baseline, relocated / "nested")
    assert copied == []


def test_execution_root_is_restricted_to_private_work_before_any_results_write(
    faults, carrier, tmp_path, monkeypatch
):
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    outside = tmp_path / "outside-work"
    outside.mkdir()
    manifest.update(root=str(outside), mutations=[])
    with pytest.raises(faults.FaultSafetyError, match="destination_outside_private_work"):
        faults.run_fault_suite(manifest)
    assert not (outside / "results.json").exists()


def test_changed_fault_driver_is_rejected_before_launch(faults, carrier, tmp_path, monkeypatch):
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    manifest["fault_script_sha256"] = "0" * 64
    calls = []
    monkeypatch.setattr(
        faults.live,
        "run_case",
        lambda *a, **k: (
            calls.append(a)
            or {
                "cleanup": {"cleanup": "complete"},
                "http": {"ready": False},
            }
        ),
    )
    with pytest.raises(faults.FaultSafetyError, match="fault_script_changed"):
        faults.run_fault_suite(manifest)
    assert calls == []


def test_recipe_root_confinement_precedes_source_indexing(faults, carrier, tmp_path, monkeypatch):
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    first = manifest["mutations"][0]
    path = Path(first["recipe_file"])
    recipe = json.loads(path.read_text())
    recipe["root"] = str(Path(carrier[0]["root"]))
    path.write_text(json.dumps(recipe))
    indexed = []
    monkeypatch.setattr(faults, "_source_index", lambda value: indexed.append(value) or {})
    with pytest.raises(faults.FaultSafetyError, match="prepared_recipe_root_outside_suite"):
        faults.run_fault_suite(manifest)
    assert indexed == []


def test_correct_diagnostic_match_is_not_credited_when_application_fault_was_not_observed(
    faults, carrier, tmp_path, monkeypatch
):
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    case = next(c for c in manifest["mutations"] if c["id"] == "localhost")
    raw = {
        "http": {"ready": True, "http_status": 200},
        "cleanup": {"cleanup": "complete"},
        "automatic": {"probe": diagnostic("WRONG_LOCALHOST", destination="127.0.0.1")},
    }
    result = faults.assess_fault(case, raw, manifest["product_source_sha256"])
    assert result["application_fault_observed"] is False
    assert result["automatic"]["probe"]["classification"] == "unvalidated_fault"
    assert result["automatic"]["probe"]["diagnostic_match"] == "correct_root_cause"
    assert result["automatic"]["probe"]["missed_root_cause"] is None


@pytest.mark.parametrize(
    "inconsistency",
    ["destination_service", "destination_namespace", "source_namespace", "execution_id", "project"],
)
def test_listener_credit_requires_the_expected_service_and_verified_namespaces(
    faults, carrier, tmp_path, monkeypatch, inconsistency
):
    manifest = prepared(faults, carrier, tmp_path, monkeypatch)
    case = next(c for c in manifest["mutations"] if c["id"] == "loopback_listener")
    finding = verified_listener_diagnostic()
    row = finding["report"]["findings"][0]
    if inconsistency == "destination_service":
        row["destination_service"] = "mongo"
    elif inconsistency.endswith("namespace"):
        role = inconsistency.removesuffix("_namespace")
        step = next(
            s for s in row["probe"]["trace"] if s["role"] == role and s["stage"] == "create"
        )
        step["helper_configuration"]["network_mode"] = "container:" + "c" * 64
    elif inconsistency == "execution_id":
        row["probe"]["execution_id"] = "f" * 32
    else:
        finding["report"]["project"] = "dockroute-corpus-" + "f" * 32
    raw = {
        "project": "dockroute-corpus-" + "d" * 32,
        "http": {"ready": True, "http_status": 502},
        "cleanup": {"cleanup": "complete"},
        "automatic": {"probe": finding},
    }
    result = faults.assess_fault(case, raw, manifest["product_source_sha256"])
    assert result["application_fault_observed"] is True
    assert result["automatic"]["probe"]["classification"] == "unverified_root_cause"
    assert result["automatic"]["probe"]["missed_root_cause"] is True
