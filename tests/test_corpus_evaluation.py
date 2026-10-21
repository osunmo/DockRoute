"""Files-only evaluation must preserve uncertainty and keep private values private."""

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


def assert_private_streams_omitted(value):
    # Match the actual secret sentinels, not macOS's legitimate /private/ path.
    rendered = json.dumps(value)
    for marker in (
        "private-secret",
        "private-stdout",
        "private-warning",
        "private-config-fragment",
        "private-process-failure",
        "private-crash-output",
        "private-crash-stderr",
        "private-invalid-json",
        "private-parser-stderr",
        "private-partial",
        "private-timeout",
        "private-command-message",
        "private-exception-message",
    ):
        assert marker not in rendered


@pytest.fixture
def evaluator():
    path = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_corpus.py"
    assert path.is_file(), "the files-only corpus evaluator is missing"
    spec = importlib.util.spec_from_file_location("corpus_evaluation", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalized_config():
    return {
        "services": {
            "app": {
                "environment": {
                    "DATABASE_URL": "postgres://alice:private-password@database:5432/demo?secret=query",
                    "EXTERNAL_URL": "https://outside.example/path?secret=another-private-value",
                    "LOCAL_URL": "http://localhost:8080/private",
                    "REDIS_HOST": "cache",
                    "REDIS_PORT": "6379",
                    "TOKEN": "http://credential.example:9999",
                },
                "depends_on": {"db": {"condition": "service_healthy"}, "cache": {}},
                "networks": {"backend": None},
                "profiles": ["optional"],
                "healthcheck": {
                    "test": ["CMD-SHELL", "curl https://monitor:8443/private?token=private-health"]
                },
                "extra_hosts": {"outside.example": "host-gateway"},
            },
            "db": {
                "networks": {"backend": {"aliases": ["database"]}},
                "ports": [
                    {
                        "target": 5432,
                        "published": "15432",
                        "protocol": "tcp",
                        "host_ip": "127.0.0.1",
                    }
                ],
                "expose": ["5432", "5433/udp"],
            },
            "cache": {"networks": {"backend": {}}, "expose": ["6379"]},
            "monitor": {"network_mode": "host", "extra_hosts": ["custom=127.0.0.1"]},
        },
        "networks": {"backend": {"name": "configured-backend", "external": True}},
    }


def test_files_only_reads_known_mounted_config_inside_case_root(evaluator, tmp_path):
    source = tmp_path / "nginx.conf"
    source.write_text(
        "events {} http { server { location / { proxy_pass http://backend:8080; } } }"
    )
    config = {
        "services": {
            "web": {
                "volumes": [
                    {"type": "bind", "source": str(source), "target": "/etc/nginx/nginx.conf"}
                ]
            },
            "backend": {"expose": ["8080"]},
        }
    }
    report = evaluator.discover_configuration(config, "study", case_root=tmp_path)
    assert any(
        i["source"] == "web" and i["host"] == "backend" and i["port"] == 8080
        for i in report["intentions"]
    )


def test_files_only_refuses_host_config_outside_case_root(evaluator, tmp_path):
    case = tmp_path / "case"
    case.mkdir()
    outside = tmp_path / "nginx.conf"
    outside.write_text(
        "events {} http { server { location / { proxy_pass http://secret:8080; } } }"
    )
    config = {
        "services": {
            "web": {
                "volumes": [
                    {"type": "bind", "source": str(outside), "target": "/etc/nginx/nginx.conf"}
                ]
            }
        }
    }
    report = evaluator.discover_configuration(config, "study", case_root=case)
    assert all(i["host"] != "secret" for i in report["intentions"])
    assert "CONFIG_OUTSIDE_CASE_ROOT" in report["configuration_issues"]


def test_adapter_preserves_configured_topology_without_runtime_facts(evaluator):
    containers = {
        c.service: c for c in evaluator.configuration_containers(normalized_config(), "study")
    }
    app, db = containers["app"], containers["db"]
    assert app.id.startswith("config-only:")
    assert app.state == "unknown" and app.health == "unknown"
    assert db.networks["backend"].aliases == ("database",)
    assert db.networks["backend"].addresses == ()
    assert db.networks["backend"].id.startswith("config-only:")
    assert app.depends_on == ("cache", "db")
    assert app.env["REDIS_PORT"] == "6379"
    assert {(p.container, p.protocol, p.host, p.host_ip) for p in db.ports} == {
        (5432, "tcp", 15432, "127.0.0.1"),
        (5432, "tcp", None, ""),
        (5433, "udp", None, ""),
    }
    assert containers["monitor"].network_mode == "host"
    assert containers["monitor"].networks == {}
    assert containers["monitor"].extra_hosts == ("custom:127.0.0.1",)


def test_discovery_reports_intentions_redacts_values_and_exposes_ambiguity(evaluator):
    report = evaluator.discover_configuration(normalized_config(), "study")
    assert report["scope"] == "files-only"
    assert report["kind"] == "connection-intentions"
    assert report["runtime_observed"] is False
    edges = {(e["source"], e["host"], e["port"]): e for e in report["intentions"]}
    database = edges[("app", "database", 5432)]
    assert database["matched_services"] == ["db"]
    assert database["context"]["destination_kind"] == "internal"
    assert database["context"]["configured_shared_networks"] == ["configured-backend"]
    assert database["context"]["external_networks"] == ["configured-backend"]
    assert edges[("app", "localhost", 8080)]["context"]["destination_kind"] == "loopback"
    outside = edges[("app", "outside.example", 443)]
    assert outside["context"]["destination_kind"] == "external-or-unknown"
    assert outside["context"]["extra_hosts_match"] is True
    assert edges[("app", "monitor", 8443)]["context"]["host_network"] is True
    assert report["services"][0]["profiles"] == ["optional"]
    rendered = json.dumps(report)
    for private in (
        "alice",
        "private-password",
        "/demo",
        "query",
        "another-private-value",
        "private-health",
        "credential.example",
    ):
        assert private not in rendered
    for runtime_field in (
        "diagnosis",
        "health",
        "restart_count",
        "tcp",
        "listener_state",
        "TCP_REACHABLE",
    ):
        assert runtime_field not in report and runtime_field not in database


def test_dependency_only_intentions_remain_unconfirmed_and_empty_dependencies_add_nothing(
    evaluator,
):
    report = evaluator.discover_configuration(
        {"services": {"app": {"depends_on": {"db": {}}}, "db": {}, "empty": {"depends_on": {}}}},
        "study",
    )
    assert len(report["intentions"]) == 1
    edge = report["intentions"][0]
    assert (edge["source"], edge["host"], edge["port"]) == ("app", "db", None)
    assert edge["dependency_only"] is True
    assert edge["connection_confirmed"] is False


def test_unresolved_environment_is_retained_as_a_sanitized_skip(evaluator):
    config = {
        "services": {
            "app": {
                "environment": {
                    "DATABASE_URL": "postgres://${PRIVATE_REQUIRED}:5432/private",
                    "API_URL": "https://known.example/",
                }
            }
        }
    }
    report = evaluator.discover_configuration(config, "study")
    assert {(e["host"], e["port"]) for e in report["intentions"]} == {("known.example", 443)}
    assert report["unresolved"] == [
        {
            "service": "app",
            "field": "environment",
            "key": "DATABASE_URL",
            "reason": "unresolved_interpolation",
        }
    ]
    assert "PRIVATE_REQUIRED" not in json.dumps(report)


def test_ambiguous_aliases_and_network_namespace_mode_are_explicit(evaluator):
    config = {
        "services": {
            "app": {
                "environment": {"API_URL": "http://shared:8080"},
                "network_mode": "service:other",
            },
            "one": {"networks": {"default": {"aliases": ["shared"]}}},
            "two": {"networks": {"default": {"aliases": ["shared"]}}},
        }
    }
    report = evaluator.discover_configuration(config, "study")
    edge = report["intentions"][0]
    assert edge["matched_services"] == ["one", "two"]
    assert edge["context"]["ambiguous_match"] is True
    assert "network_namespace_mode" in edge["context"]["limitations"]


def case_at(tmp_path):
    (tmp_path / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (tmp_path / "sample.env").write_text("PASSWORD=private-file-secret\n", encoding="utf-8")
    return {
        "id": "example",
        "repo": "https://github.com/example/project",
        "revision": "a" * 40,
        "root": str(tmp_path),
        "compose_files": ["compose.yaml"],
        "env_file": "sample.env",
        "profiles": ["*"],
        "split": "development",
        "oracle_coverage": "partial",
    }


def test_normalizer_uses_explicit_files_env_and_profiles_with_bounded_deadline(
    evaluator, monkeypatch, tmp_path
):
    case = case_at(tmp_path)

    def command(argv, **kwargs):
        assert argv[:2] == ["docker", "compose"]
        assert argv[argv.index("--project-directory") + 1] == str(tmp_path.resolve())
        assert argv[argv.index("--env-file") + 1] == str((tmp_path / "sample.env").resolve())
        assert argv[argv.index("-f") + 1] == str((tmp_path / "compose.yaml").resolve())
        assert argv[argv.index("--profile") + 1] == "*"
        assert argv[-3:] == ["config", "--format", "json"]
        assert kwargs["timeout"] == 9
        assert "DATABASE_URL" not in kwargs["env"]
        return SimpleNamespace(returncode=0, stdout=json.dumps(normalized_config()), stderr="")

    monkeypatch.setenv("DATABASE_URL", "postgres://private-ambient-secret")
    monkeypatch.setattr(evaluator.subprocess, "run", command)
    result = evaluator.normalize_compose(case, timeout=9)
    assert result["status"] == "normalized"
    assert len(result["config"]["services"]) == 4
    with pytest.raises(ValueError):
        evaluator.normalize_compose(case, timeout=0)


@pytest.mark.parametrize(
    "failure,error",
    [
        ("required variable PRIVATE: private-secret", "required_interpolation"),
        ("yaml: invalid private-secret", "invalid_compose"),
        ("unknown private-secret failure", "compose_config_failed"),
    ],
)
def test_normalization_errors_never_include_stderr(
    evaluator, monkeypatch, tmp_path, failure, error
):
    monkeypatch.setattr(
        evaluator.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="private-stdout", stderr=failure),
    )
    result = evaluator.normalize_compose(case_at(tmp_path))
    assert result["status"] == "skipped" and result["error_class"] == error
    assert_private_streams_omitted(result)


def test_normalization_timeout_and_blank_interpolation_are_preserved(
    evaluator, monkeypatch, tmp_path
):
    case = case_at(tmp_path)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            "private command", 1, output="private stdout", stderr="private stderr"
        )

    monkeypatch.setattr(evaluator.subprocess, "run", timeout)
    assert evaluator.normalize_compose(case)["error_class"] == "compose_timeout"
    monkeypatch.setattr(
        evaluator.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=0,
            stdout='{"services":{}}',
            stderr='The "PRIVATE_VAR" variable is not set. Defaulting to a blank string.',
        ),
    )
    result = evaluator.normalize_compose(case)
    assert result["status"] == "skipped"
    assert result["error_class"] == "unresolved_interpolation"
    assert "PRIVATE_VAR" not in json.dumps(result)


def test_manifest_retains_failures_hashes_split_and_never_publishes_raw_config(
    evaluator, monkeypatch, tmp_path
):
    case = case_at(tmp_path)
    skipped = {**case, "id": "failed"}
    holdout = {**case, "id": "sealed", "split": "holdout", "root": str(tmp_path / "must-not-open")}
    visited = []

    def normalize(current, **kwargs):
        visited.append(current["id"])
        if current["id"] == "failed":
            return {"status": "skipped", "error_class": "required_interpolation", "duration_ms": 1}
        return {"status": "normalized", "config": normalized_config(), "duration_ms": 1}

    monkeypatch.setattr(evaluator, "normalize_compose", normalize)
    report = evaluator.evaluate_manifest({"cases": [case, skipped, holdout]}, split="development")
    assert visited == ["example", "failed"]
    assert len(report["attempts"]) == 2
    assert len(report["results"]) == 1
    assert report["attempts"][1]["error_class"] == "required_interpolation"
    assert report["attempts"][0]["revision"] == "a" * 40
    assert len(report["attempts"][0]["input_hashes"]["compose.yaml"]) == 64
    assert len(report["metadata"]["evaluator_sha256"]) == 64
    assert report["selection"]["excluded_cases"] == [{"id": "sealed", "reason": "split_filter"}]
    assert "private-file-secret" not in json.dumps(report)
    assert "private-password" not in json.dumps(report)
    assert "config" not in report["attempts"][0]


def test_scoring_counts_wrong_target_misses_and_unreviewed_honestly(evaluator):
    edges = [
        {"source": "app", "host": "db", "port": 5432, "dependency_only": False},
        {"source": "app", "host": "wrong", "port": 8080, "dependency_only": False},
        {"source": "app", "host": "public.example", "port": 443, "dependency_only": False},
        {"source": "app", "host": "unknown", "port": 1234, "dependency_only": False},
        {"source": "app", "host": "dependency", "port": None, "dependency_only": True},
    ]
    results = [{"case_id": "example", "oracle_coverage": "partial", "intentions": edges}]
    labels = [
        {"case_id": "example", "source": "app", "host": "db", "port": 5432, "label": "correct"},
        {
            "case_id": "example",
            "source": "app",
            "host": "wrong",
            "port": 8080,
            "label": "wrong-target",
        },
        {
            "case_id": "example",
            "source": "app",
            "host": "public.example",
            "port": 443,
            "label": "not-a-connection",
        },
        {"case_id": "example", "source": "app", "host": "hidden", "port": 7777, "label": "missed"},
        {
            "case_id": "example",
            "source": "app",
            "host": "dependency",
            "port": None,
            "label": "correct",
        },
    ]
    score = evaluator.score_predictions(results, labels)
    assert score["counts"] == {
        "correct": 1,
        "wrong-target": 1,
        "not-a-connection": 1,
        "missed": 1,
        "unreviewed": 1,
    }
    assert score["dependency_only_excluded"] == 1
    assert score["precision"] == {"numerator": 1, "denominator": 3, "value": pytest.approx(1 / 3)}
    assert score["recall"] == {"numerator": 1, "denominator": 3, "value": pytest.approx(1 / 3)}
    assert score["recall_scope"] == "reviewed-oracle-only"
    assert score["oracle_coverage_complete"] is False
    assert score["prediction_review_coverage"] == {"reviewed": 3, "eligible": 4}


def test_scoring_rejects_stale_and_duplicate_reviews(evaluator):
    results = [{"case_id": "example", "intentions": []}]
    stale = {"case_id": "example", "source": "app", "host": "db", "port": 5432, "label": "correct"}
    with pytest.raises(ValueError, match="does not match"):
        evaluator.score_predictions(results, [stale])
    missed = {**stale, "label": "missed"}
    with pytest.raises(ValueError, match="duplicate"):
        evaluator.score_predictions(results, [missed, missed])


def test_unset_normalized_environment_is_a_retained_uncertainty(evaluator):
    report = evaluator.discover_configuration(
        {"services": {"app": {"environment": {"API_URL": None}}}}, "study"
    )
    assert report["intentions"] == []
    assert report["unresolved"] == [
        {"service": "app", "field": "environment", "key": "API_URL", "reason": "unset_environment"}
    ]


def test_manifest_requires_explicit_root_and_cannot_escape_it(evaluator, tmp_path):
    with pytest.raises(ValueError, match="root"):
        evaluator._case_paths({"compose_files": ["compose.yaml"]})
    with pytest.raises(ValueError, match="within"):
        evaluator._case_paths({"root": str(tmp_path), "compose_files": ["../outside.yaml"]})


def test_partial_output_preserves_skipped_environment_fields(evaluator, monkeypatch, tmp_path):
    case = case_at(tmp_path)
    monkeypatch.setattr(
        evaluator,
        "normalize_compose",
        lambda *a, **k: {
            "status": "normalized",
            "config": {"services": {"app": {"environment": {"API_URL": None}}}},
        },
    )
    report = evaluator.evaluate_manifest({"cases": [case]})
    assert report["attempts"][0]["status"] == "partial"
    assert report["summary"]["partial_cases"] == 1
    assert report["results"][0]["unresolved"][0]["reason"] == "unset_environment"


def test_complete_oracle_does_not_hide_skipped_cases_in_recall_scope(evaluator):
    report = {
        "results": [{"case_id": "normalized", "oracle_coverage": "complete", "intentions": []}],
        "attempts": [
            {"case_id": "normalized", "oracle_coverage": "complete", "status": "normalized"},
            {"case_id": "unresolved", "oracle_coverage": "complete", "status": "skipped"},
        ],
    }
    score = evaluator.score_predictions(report, [])
    assert score["evaluated_case_coverage"] == {
        "evaluated": 1,
        "selected": 2,
        "skipped_or_partial": 1,
    }
    assert score["corpus_recall_complete"] is False


def test_real_compose_normalizes_anchors_env_aliases_profiles_and_ports(evaluator, tmp_path):
    # This narrowly verifies our Compose boundary assumption, not a YAML parser.
    (tmp_path / "compose.yaml").write_text(
        """x-environment: &connection
  DATABASE_URL: ${DATABASE_URL:?required}
services:
  app:
    image: example/app
    environment: *connection
    profiles: [optional]
    depends_on:
      db:
        condition: service_started
  db:
    image: example/db
    networks:
      default:
        aliases: [database]
    ports: ['127.0.0.1:15432:5432']
    expose: [5432]
""",
        encoding="utf-8",
    )
    (tmp_path / "sample.env").write_text(
        "DATABASE_URL=postgres://private:private@database:5432/private\n", encoding="utf-8"
    )
    case = {
        "id": "compose-boundary",
        "root": str(tmp_path),
        "compose_files": ["compose.yaml"],
        "env_file": "sample.env",
        "profiles": ["*"],
    }
    normalized = evaluator.normalize_compose(case, timeout=60)
    if normalized.get("error_class") == "compose_or_input_unavailable":
        pytest.skip("installed Compose CLI unavailable")
    assert normalized["status"] == "normalized", normalized
    report = evaluator.discover_configuration(normalized["config"], "study")
    assert [(e["source"], e["host"], e["port"]) for e in report["intentions"]] == [
        ("app", "database", 5432)
    ]
    assert report["intentions"][0]["matched_services"] == ["db"]
    assert report["services"][0]["profiles"] == ["optional"]
    assert "private:private" not in json.dumps(report)


def test_normalizer_respects_explicit_profiles_and_records_scope(evaluator, monkeypatch, tmp_path):
    case = {**case_at(tmp_path), "profiles": ["api", "worker"]}

    def command(argv, **kwargs):
        if "config" in argv:
            assert [
                argv[index + 1] for index, value in enumerate(argv) if value == "--profile"
            ] == ["api", "worker"]
            return SimpleNamespace(returncode=0, stdout='{"services":{}}', stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(evaluator.subprocess, "run", command)
    report = evaluator.evaluate_manifest({"cases": [case]})
    assert report["attempts"][0]["requested_profiles"] == ["api", "worker"]
    assert report["attempts"][0]["profile_scope"] == "explicit"


def test_default_project_directory_is_the_nested_first_compose_parent(
    evaluator, monkeypatch, tmp_path
):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    case = {"id": "nested", "root": str(tmp_path), "compose_files": ["nested/compose.yaml"]}

    def command(argv, **kwargs):
        assert argv[argv.index("--project-directory") + 1] == str(nested.resolve())
        assert "--profile" not in argv
        return SimpleNamespace(returncode=0, stdout='{"services":{}}', stderr="")

    monkeypatch.setattr(evaluator.subprocess, "run", command)
    assert evaluator.normalize_compose(case)["status"] == "normalized"


def test_real_nested_compose_resolves_service_env_file_relative_to_first_file(evaluator, tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "compose.yaml").write_text(
        "services:\n  app:\n    image: example/app\n    env_file: [sample.env]\n  db:\n    image: example/db\n",
        encoding="utf-8",
    )
    (nested / "sample.env").write_text(
        "DATABASE_URL=postgres://private:private@db:5432/private\n", encoding="utf-8"
    )
    case = {
        "id": "nested",
        "root": str(tmp_path),
        "compose_files": ["nested/compose.yaml"],
        "env_file": "nested/sample.env",
    }
    normalized = evaluator.normalize_compose(case, timeout=60)
    if normalized.get("error_class") == "compose_or_input_unavailable":
        pytest.skip("installed Compose CLI unavailable")
    assert normalized["status"] == "normalized", normalized
    report = evaluator.discover_configuration(normalized["config"], "study")
    assert [(e["host"], e["port"]) for e in report["intentions"]] == [("db", 5432)]


def test_cli_parses_minimal_contract_and_writes_sanitized_results(evaluator, monkeypatch, tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": [case_at(tmp_path)]}), encoding="utf-8")
    output = tmp_path / "results.json"
    monkeypatch.setattr(
        evaluator,
        "normalize_compose",
        lambda *a, **k: {"status": "normalized", "config": normalized_config(), "duration_ms": 1},
    )
    assert (
        evaluator.main(
            ["--manifest", str(manifest), "--split", "development", "--output", str(output)]
        )
        == 0
    )
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["scope"] == "files-only"
    assert len(report["results"]) == 1
    assert "private-password" not in output.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "returncode,stdout,stderr,error",
    [
        (0, b'{"services":{}}', b"private-warning-\xff", None),
        (23, b"private-config-fragment", b"private-process-failure-\xff", "compose_config_failed"),
        (-11, b"private-crash-output", b"private-crash-stderr", "compose_config_failed"),
        (0, b"private-invalid-json", b"private-parser-stderr", "invalid_config_or_manifest"),
        (0, b'\xff{"services":{}}', b"", "invalid_config_or_manifest"),
    ],
)
def test_every_process_result_retains_exact_private_binary_streams_and_public_hashes(
    evaluator, monkeypatch, tmp_path, returncode, stdout, stderr, error
):
    case = {**case_at(tmp_path), "raw_log_directory": "raw"}

    def command(argv, **kwargs):
        assert kwargs.get("text", False) is False
        assert "encoding" not in kwargs and "errors" not in kwargs
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(evaluator.subprocess, "run", command)
    result = evaluator.normalize_compose(case)
    assert result["process_returncode"] == returncode
    assert result["process_duration_ms"] >= 0
    assert result["command_argv"][:2] == ["docker", "compose"]
    assert result["command_argv"][-3:] == ["config", "--format", "json"]
    logs = result["raw_logs"]
    assert logs["path_base"] == "case-root"
    log_directory = tmp_path / logs["directory"]
    assert (log_directory / logs["stdout"]["filename"]).read_bytes() == stdout
    assert (log_directory / logs["stderr"]["filename"]).read_bytes() == stderr
    assert logs["stdout"]["sha256"] == hashlib.sha256(stdout).hexdigest()
    assert logs["stderr"]["sha256"] == hashlib.sha256(stderr).hexdigest()
    assert logs["stdout"]["bytes"] == len(stdout)
    assert_private_streams_omitted({k: v for k, v in result.items() if k != "config"})
    if error:
        assert result["error_class"] == error
    else:
        assert result["status"] == "normalized"


def test_timeout_retains_partial_binary_streams_without_publishing_them(
    evaluator, monkeypatch, tmp_path
):
    case = {**case_at(tmp_path), "raw_log_directory": "raw"}

    def command(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            "private-command-message",
            1,
            output=b"private-partial-\xfe",
            stderr=b"private-timeout-\xff",
        )

    monkeypatch.setattr(evaluator.subprocess, "run", command)
    result = evaluator.normalize_compose(case)
    assert result["error_class"] == "compose_timeout"
    assert result["process_returncode"] is None
    logs = result["raw_logs"]
    directory = tmp_path / logs["directory"]
    assert (directory / logs["stdout"]["filename"]).read_bytes() == b"private-partial-\xfe"
    assert (directory / logs["stderr"]["filename"]).read_bytes() == b"private-timeout-\xff"
    assert_private_streams_omitted(result)


def test_failed_invocation_retains_empty_logs_and_repeated_attempts_never_overwrite(
    evaluator, monkeypatch, tmp_path
):
    case = {**case_at(tmp_path), "raw_log_directory": "raw"}

    def command(*args, **kwargs):
        raise FileNotFoundError("private-exception-message")

    monkeypatch.setattr(evaluator.subprocess, "run", command)
    first = evaluator.normalize_compose(case)
    second = evaluator.normalize_compose(case)
    assert first["raw_logs"]["directory"] != second["raw_logs"]["directory"]
    assert first["process_returncode"] is None
    assert first["raw_logs"]["stdout"]["bytes"] == 0
    assert first["raw_logs"]["stderr"]["bytes"] == 0
    assert_private_streams_omitted(first)


def test_raw_capture_rejects_paths_outside_case_root_and_workspace_work(
    evaluator, monkeypatch, tmp_path
):
    # pytest basetemp itself may live inside the real checkout's permitted work/.
    monkeypatch.setattr(evaluator, "ROOT", tmp_path / "isolated-checkout")
    case = {**case_at(tmp_path), "raw_log_directory": str(tmp_path.parent / "outside")}
    calls = []
    monkeypatch.setattr(evaluator.subprocess, "run", lambda *a, **k: calls.append(a))
    result = evaluator.normalize_compose(case)
    assert result["status"] == "skipped"
    assert result["error_class"] == "raw_log_directory_outside_scope"
    assert calls == []
    assert not (tmp_path.parent / "outside").exists()


def test_manifest_publishes_command_and_hashes_without_raw_config_and_records_actual_source(
    evaluator, monkeypatch, tmp_path
):
    case = {**case_at(tmp_path), "raw_log_directory": "raw"}

    def command(argv, **kwargs):
        if "config" in argv:
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(normalized_config()).encode(),
                stderr=b"private-warning",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(evaluator.subprocess, "run", command)
    report = evaluator.evaluate_manifest({"cases": [case]})
    attempt = report["attempts"][0]
    assert attempt["command_argv"][-3:] == ["config", "--format", "json"]
    assert attempt["process_returncode"] == 0
    assert "raw_logs" in attempt and "config" not in attempt
    assert "private-password" not in json.dumps(report)
    assert "private-warning" not in json.dumps(report)
    assert report["metadata"]["baseline_revision"] == "2a9060d67175635210ad09f2db4633335a0a3fac"
    assert "release_revision" not in report["metadata"]
    models_path = evaluator.ROOT / "src" / "dockroute" / "models.py"
    assert (
        report["metadata"]["evaluated_source_sha256"]["src/dockroute/models.py"]
        == hashlib.sha256(models_path.read_bytes()).hexdigest()
    )


def test_missing_input_still_records_the_normalization_command_and_private_failure_streams(
    evaluator, monkeypatch, tmp_path
):
    case = {
        **case_at(tmp_path),
        "compose_files": ["absent.yaml"],
        "raw_log_directory": "raw",
    }

    def command(argv, **kwargs):
        if "config" in argv:
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"no such file: private-marker")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(evaluator.subprocess, "run", command)
    report = evaluator.evaluate_manifest({"cases": [case]})
    attempt = report["attempts"][0]
    assert attempt["status"] == "skipped"
    assert attempt["error_class"] == "missing_input"
    assert attempt["process_returncode"] == 1
    assert attempt["command_argv"][-3:] == ["config", "--format", "json"]
    assert attempt["raw_logs"]["stderr"]["bytes"] == 28
    assert attempt["input_hash_errors"] == [
        {"filename": "absent.yaml", "error_class": "missing_input"}
    ]
    assert "private-marker" not in json.dumps(report)


def test_per_case_timing_distinguishes_normalization_discovery_and_total(
    evaluator, monkeypatch, tmp_path
):
    case = case_at(tmp_path)
    monkeypatch.setattr(
        evaluator,
        "normalize_compose",
        lambda *a, **k: {
            "status": "normalized",
            "config": normalized_config(),
            "duration_ms": 200.0,
        },
    )
    clock = iter([10.0, 10.1, 10.4, 11.0])
    monkeypatch.setattr(evaluator.time, "monotonic", lambda: next(clock))
    report = evaluator.evaluate_manifest({"cases": [case]})
    attempt = report["attempts"][0]
    assert attempt["normalization_duration_ms"] == 200.0
    assert attempt["discovery_duration_ms"] == pytest.approx(300.0)
    assert attempt["total_duration_ms"] == pytest.approx(1000.0)
    assert report["results"][0]["discovery_duration_ms"] == pytest.approx(300.0)


def test_skipped_cases_report_total_runtime_without_inventing_discovery_runtime(
    evaluator, monkeypatch, tmp_path
):
    case = case_at(tmp_path)
    monkeypatch.setattr(
        evaluator,
        "normalize_compose",
        lambda *a, **k: {
            "status": "skipped",
            "error_class": "required_interpolation",
            "duration_ms": 120.0,
        },
    )
    clock = iter([20.0, 20.5])
    monkeypatch.setattr(evaluator.time, "monotonic", lambda: next(clock))
    report = evaluator.evaluate_manifest({"cases": [case]})
    attempt = report["attempts"][0]
    assert attempt["normalization_duration_ms"] == 120.0
    assert attempt["discovery_duration_ms"] is None
    assert attempt["total_duration_ms"] == pytest.approx(500.0)
