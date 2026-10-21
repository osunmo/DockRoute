"""Hand-derived corpus accounting; no containers or source corpus are needed."""

import csv
import importlib
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def reporter():
    assert importlib.util.find_spec("scripts.report_corpus") is not None, "Reporter is missing"
    return importlib.import_module("scripts.report_corpus")


def files_fixture():
    return {
        "metadata": {"python_version": "3.12", "compose_version": "5", "private_env": "secret"},
        "selection": {"split": "development", "excluded_cases": []},
        "manifest": {
            "cases": [
                {
                    "id": "a",
                    "repo": "https://user:private@github.com/example/a?secret=private",
                    "revision": "a" * 40,
                    "compose_files": ["compose.yaml", "override.yaml"],
                    "split": "development",
                    "environment": {"PRIVATE": "secret"},
                }
            ]
        },
        "attempts": [
            {
                "case_id": "a",
                "status": "normalized",
                "normalization_duration_ms": 12,
                "discovery_duration_ms": 0,
                "total_duration_ms": 15,
                "command_argv": ["docker", "compose", "config", "--format", "json"],
                "process_returncode": 0,
            }
        ],
        "results": [
            {
                "case_id": "a",
                "oracle_coverage": "partial",
                "unresolved": [],
                "intentions": [
                    {"source": "app", "host": "db", "port": 5432},
                    {"source": "app", "host": "wrong", "port": 8080},
                    {"source": "app", "host": "example.com", "port": 443},
                    {"source": "app", "host": "unknown", "port": 1234},
                    {"source": "app", "host": "cache", "port": None, "dependency_only": True},
                ],
            }
        ],
    }


def reviews_fixture():
    return {
        "reviewer": "source-agent; not human reviewed",
        "frozen_oracle_sha256": "b" * 64,
        "labels": [
            {"case_id": "a", "source": "app", "host": "db", "port": 5432, "label": "correct"},
            {
                "case_id": "a",
                "source": "app",
                "host": "wrong",
                "port": 8080,
                "label": "wrong-target",
            },
            {
                "case_id": "a",
                "source": "app",
                "host": "example.com",
                "port": 443,
                "label": "not-a-connection",
            },
            {
                "case_id": "a",
                "source": "app",
                "host": "hidden",
                "port": 9999,
                "label": "missed",
                "notes": "Frozen source oracle.",
            },
            {"case_id": "a", "source": "app", "host": "cache", "port": None, "label": "correct"},
        ],
    }


def policy_fixture():
    return {
        "expectations": {
            "working_live_projects": "zero problem diagnoses",
            "problem_codes": ["NETWORK_ISOLATION", "DNS_FAILURE"],
            "abstention_codes": ["UNKNOWN"],
            "informational_codes": ["TCP_REACHABLE"],
        }
    }


def finding(code, host="db", port=5432):
    return {"code": code, "source": "app", "destination": host, "port": port}


def test_precision_and_recall_use_reviewed_subset_and_exclude_portless_dependencies():
    summary = reporter().summarize_evaluation(files_fixture(), reviews_fixture())
    assert summary["discovery"]["counts"] == {
        "correct": 1,
        "wrong-target": 1,
        "not-a-connection": 1,
        "unreviewed": 1,
        "missed": 1,
    }
    assert summary["discovery"]["precision"] == {
        "numerator": 1,
        "denominator": 3,
        "value": pytest.approx(1 / 3),
    }
    assert summary["discovery"]["recall"] == {
        "numerator": 1,
        "denominator": 3,
        "value": pytest.approx(1 / 3),
    }
    assert summary["discovery"]["dependency_only_excluded"] == 1
    assert summary["discovery"]["corpus_recall_complete"] is False
    assert summary["review_provenance"]["reviewer"] == "source-agent; not human reviewed"


def test_pipeline_preserves_crash_parse_unresolved_unsupported_and_missing_attempts():
    report = files_fixture()
    failures = [
        {
            "case_id": "crash",
            "status": "skipped",
            "process_returncode": -9,
            "error_class": "compose_config_failed",
        },
        {
            "case_id": "parse",
            "status": "skipped",
            "process_returncode": 1,
            "error_class": "invalid_compose",
        },
        {"case_id": "env", "status": "partial", "error_class": "unresolved_configuration_values"},
        {"case_id": "unsupported", "status": "skipped", "error_class": "unsupported_compose_cli"},
    ]
    report["attempts"].extend(failures)
    report["manifest"]["cases"].extend(
        {"id": case_id, "split": "development"}
        for case_id in ("crash", "parse", "env", "unsupported", "prep")
    )
    report["manifest"]["preparation_failures"] = [
        {"case_id": "prep", "error_class": "fetch_failed"}
    ]
    summary = reporter().summarize_evaluation(report, reviews_fixture())
    pipeline = summary["pipeline"]
    assert pipeline["selected_files"] == 6
    assert pipeline["attempted_files"] == 5
    assert pipeline["failure_rate"] == {
        "numerator": 5,
        "denominator": 6,
        "value": pytest.approx(5 / 6),
    }
    assert pipeline["failure_categories"] == {
        "crash": 1,
        "parse_failure": 1,
        "unresolved": 1,
        "unsupported": 1,
        "not_attempted": 1,
    }
    assert pipeline["preparation_failures"] == [{"case_id": "prep", "error_class": "fetch_failed"}]
    assert pipeline["nonzero_compose_exits"] == 1
    assert len(summary["runtime"]["per_file"]) == 6
    assert summary["runtime"]["per_file"][0]["discovery_duration_ms"] == 0
    assert summary["runtime"]["per_file"][0]["command_argv"] == [
        "docker",
        "compose",
        "config",
        "--format",
        "json",
    ]


def test_files_only_audit_has_no_diagnosis_or_invented_health_and_retains_misses():
    module = reporter()
    summary = module.summarize_evaluation(files_fixture(), reviews_fixture())
    rows = summary["audit_rows"]
    assert len(rows) == 6
    assert all(row["diagnosis_code"] is None for row in rows)
    assert all(row["finding_verdict"] == "NOT_RUN_FILES_ONLY" for row in rows)
    assert rows[4]["discovery_label"] == "dependency-only-unconfirmed"
    assert rows[5]["discovery_label"] == "missed"
    assert rows[5]["notes"] == "Frozen source oracle."
    assert rows[0]["repo"] == "https://github.com/example/a"
    assert rows[0]["compose_files"] == ["compose.yaml", "override.yaml"]
    assert "TCP_REACHABLE" not in json.dumps(summary)
    assert "private" not in json.dumps(summary).lower()
    assert "secret" not in json.dumps(summary).lower()
    stream = io.StringIO(newline="")
    module.export_audit_csv(summary, stream)
    csv_rows = list(csv.DictReader(io.StringIO(stream.getvalue())))
    assert csv_rows[0] == {
        "repo": "https://github.com/example/a",
        "commit": "a" * 40,
        "compose_files": "compose.yaml;override.yaml",
        "service": "app",
        "discovered_endpoint": "db:5432",
        "discovery_label": "correct",
        "diagnosis_code": "",
        "finding_verdict": "NOT_RUN_FILES_ONLY",
        "notes": "",
    }


def test_live_false_positive_denominator_includes_http_ready_probe_failure():
    records = [
        {
            "id": "live-a",
            "status": "complete",
            "http": {"ready": True},
            "cleanup": {"cleanup": "complete"},
            "automatic": {
                "static": {
                    "report": {"findings": [finding("NETWORK_ISOLATION"), finding("UNKNOWN")]},
                    "wall_ms": 33,
                    "command": ["python", "-m", "dockroute", "doctor"],
                },
                "probe": {
                    "report": {
                        "findings": [
                            finding("DNS_FAILURE"),
                            finding("TCP_REACHABLE", "cache", 6379),
                        ]
                    },
                    "wall_ms": 54,
                    "command": ["python", "-m", "dockroute", "doctor", "--probe"],
                },
            },
            "finding_reviews": [
                {"mode": "static", **finding("NETWORK_ISOLATION"), "verdict": "false positive"},
            ],
        },
        {
            "id": "live-b",
            "status": "failed",
            "http": {"ready": True},
            "cleanup": {"cleanup": "complete"},
            "automatic": {
                "probe": {"error": "child_report_missing", "report": None, "wall_ms": 90}
            },
        },
        {
            "id": "live-c",
            "status": "failed",
            "http": {"ready": False},
            "cleanup": {"cleanup": "complete"},
            "automatic": {"static": {"report": {"findings": [finding("NETWORK_ISOLATION")]}}},
            "finding_reviews": [
                {"mode": "static", **finding("NETWORK_ISOLATION"), "verdict": "false positive"}
            ],
        },
    ]
    summary = reporter().summarize_evaluation({}, [], live_records=records, policy=policy_fixture())
    live = summary["live"]
    assert live["attempted_files"] == 3
    assert live["http_validated_files"] == 2
    assert live["raw_finding_count"] == 5
    assert live["modes"]["static"]["raw_code_counts"] == {"NETWORK_ISOLATION": 2, "UNKNOWN": 1}
    assert live["modes"]["static"]["false_positives_per_file"] == {
        "numerator": 1,
        "denominator": 2,
        "value": 0.5,
    }
    assert live["modes"]["probe"]["false_positives_per_file"] == {
        "numerator": 0,
        "denominator": 2,
        "value": 0.0,
    }
    assert live["modes"]["probe"]["working_problem_verdicts"] == {
        "true issue": 0,
        "false positive": 0,
        "unsure": 1,
    }
    assert live["modes"]["probe"]["zero_problem_expectation_violations"] == 1
    assert live["modes"]["probe"]["report_coverage"] == {
        "numerator": 1,
        "denominator": 2,
        "value": 0.5,
    }
    assert live["abstention_count"] == 1
    unknown = next(row for row in live["raw_findings"] if row["code"] == "UNKNOWN")
    assert unknown["finding_verdict"] == "ABSTENTION"
    probe = next(
        row for row in live["runs"] if row["case_id"] == "live-a" and row["mode"] == "probe"
    )
    assert probe["wall_ms"] == 54
    assert probe["command"] == ["python", "-m", "dockroute", "doctor", "--probe"]


def test_working_http_does_not_create_false_positive_verdict_without_review_or_policy():
    records = [
        {
            "id": "a",
            "http": {"ready": True},
            "automatic": {"static": {"report": {"findings": [finding("NETWORK_ISOLATION")]}}},
        }
    ]
    summary = reporter().summarize_evaluation({}, [], live_records=records, policy=policy_fixture())
    assert summary["live"]["false_positives_per_file"] == {
        "numerator": 0,
        "denominator": 1,
        "value": 0.0,
    }
    assert summary["live"]["zero_problem_expectation_violations"] == 1
    assert summary["live"]["unreviewed_problem_count"] == 1
    assert summary["live"]["raw_findings"][0]["finding_verdict"] == "unsure"
    no_policy = reporter().summarize_evaluation({}, [], live_records=records)
    assert no_policy["live"]["false_positives_per_file"]["value"] is None
    assert no_policy["live"]["http_validated_files"] == 1


def test_fault_recall_keeps_missed_auto_discovery_and_invalid_attempts_separate():
    faults = {
        "cases": [
            {
                "id": "hit",
                "expected_code": "DNS_FAILURE",
                "baseline_validated": True,
                "mutation_validated": True,
                "auto_detected": True,
                "manual_detected": True,
                "status": "complete",
            },
            {
                "id": "miss",
                "expected_code": "DNS_FAILURE",
                "baseline_validated": True,
                "mutation_validated": True,
                "auto_detected": False,
                "manual_detected": True,
                "status": "complete",
            },
            {
                "id": "failed",
                "expected_code": "DNS_FAILURE",
                "baseline_validated": True,
                "mutation_validated": True,
                "auto_detected": False,
                "manual_detected": False,
                "status": "execution_failed",
            },
            {
                "id": "invalid",
                "expected_code": "DNS_FAILURE",
                "baseline_validated": False,
                "mutation_validated": True,
                "auto_detected": True,
                "manual_detected": True,
                "status": "invalid",
            },
        ]
    }
    summary = reporter().summarize_evaluation({}, [], fault_records=faults)
    assert summary["faults"]["attempts"] == 4
    assert summary["faults"]["known_validated_faults"] == 3
    assert summary["faults"]["automatic_recall"] == {
        "numerator": 1,
        "denominator": 3,
        "value": pytest.approx(1 / 3),
    }
    assert summary["faults"]["manual_recall"] == {
        "numerator": 2,
        "denominator": 3,
        "value": pytest.approx(2 / 3),
    }
    assert summary["faults"]["invalid_attempts"] == 1
    assert summary["faults"]["execution_failed_attempts"] == 1


def test_empty_metrics_are_null_and_invalid_finding_reviews_are_rejected():
    summary = reporter().summarize_evaluation({}, [])
    assert summary["discovery"]["precision"]["value"] is None
    assert summary["discovery"]["recall"]["value"] is None
    assert summary["pipeline"]["failure_rate"]["value"] is None
    assert summary["live"]["false_positives_per_file"]["value"] is None
    assert summary["faults"]["automatic_recall"]["value"] is None
    record = {
        "id": "a",
        "finding_reviews": [
            {"mode": "static", **finding("DNS_FAILURE"), "verdict": "false positive"}
        ],
        "automatic": {},
    }
    with pytest.raises(ValueError, match="does not match"):
        reporter().summarize_evaluation({}, [], live_records=[record], policy=policy_fixture())


def test_portless_intention_is_never_confirmed_even_when_legacy_flag_is_missing():
    report = {
        "results": [
            {"case_id": "a", "intentions": [{"source": "app", "host": "cache", "port": None}]}
        ]
    }
    reviews = [{"case_id": "a", "source": "app", "host": "cache", "port": None, "label": "correct"}]
    summary = reporter().summarize_evaluation(report, reviews)
    assert summary["discovery"]["counts"]["correct"] == 0
    assert summary["discovery"]["dependency_only_excluded"] == 1
    assert summary["discovery"]["precision"]["value"] is None
    assert report["results"][0]["intentions"][0] == {"source": "app", "host": "cache", "port": None}


def test_live_audit_records_explicit_compose_metadata_and_does_not_merge_manual_findings():
    record = {
        "id": "live-a",
        "case_id": "a",
        "http": {"ready": True},
        "compose_files": ["prepared/compose.yaml"],
        "provenance": {"upstream": "https://github.com/example/live", "revision": "c" * 40},
        "automatic": {"static": {"report": {"findings": [finding("UNKNOWN")]}}},
        "manual_checks": [
            {"source": "app", "target": "db:5432", "report": {"findings": [finding("DNS_FAILURE")]}}
        ],
    }
    summary = reporter().summarize_evaluation(
        {}, [], live_records=[record], policy=policy_fixture()
    )
    assert summary["live"]["raw_finding_count"] == 1
    assert summary["live"]["manual_checks"][0]["raw_code_counts"] == {"DNS_FAILURE": 1}
    assert summary["audit_rows"][0]["compose_files"] == ["prepared/compose.yaml"]
    assert summary["audit_rows"][0]["repo"] == "https://github.com/example/live"
    assert summary["live"]["runs"][0]["case_id"] == "a"


def test_duplicate_injected_faults_cannot_inflate_recall_denominator():
    fault = {
        "id": "same",
        "baseline_validated": True,
        "mutation_validated": True,
        "auto_detected": True,
    }
    with pytest.raises(ValueError, match="unique"):
        reporter().summarize_evaluation({}, [], fault_records=[fault, fault])


def test_notes_strip_userinfo_and_query_credentials_from_non_http_urls():
    reviews = reviews_fixture()
    reviews["labels"][0]["notes"] = (
        "Source uses postgres://demo:private-password@db:5432/demo?token=private"
    )
    summary = reporter().summarize_evaluation(files_fixture(), reviews)
    assert summary["audit_rows"][0]["notes"] == "Source uses postgres://db:5432/demo"
    assert "private-password" not in json.dumps(summary)


def test_cli_missing_live_directory_is_a_failure_instead_of_zero_live_cases(tmp_path):
    for name, value in {
        "evaluation": {},
        "reviews": [],
        "manifest": {"cases": []},
        "policy": {},
    }.items():
        (tmp_path / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "report_corpus.py"),
            "--evaluation",
            str(tmp_path / "evaluation.json"),
            "--reviews",
            str(tmp_path / "reviews.json"),
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--policy",
            str(tmp_path / "policy.json"),
            "--output",
            str(tmp_path / "summary.json"),
            "--csv",
            str(tmp_path / "audit.csv"),
            "--live-dir",
            str(tmp_path / "missing-live-evidence"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "summary.json").exists()


def test_changed_product_source_retains_raw_findings_but_cannot_earn_grading_credit():
    record = {
        "id": "changed",
        "http": {"ready": True},
        "automatic": {
            "static": {
                "valid_for_grading": False,
                "source": {"stable": False},
                "error": "source_changed_during_diagnostic",
                "report": {"findings": [finding("NETWORK_ISOLATION")]},
            }
        },
        "finding_reviews": [
            {"mode": "static", **finding("NETWORK_ISOLATION"), "verdict": "false positive"}
        ],
    }
    live = reporter().summarize_evaluation({}, [], live_records=[record], policy=policy_fixture())[
        "live"
    ]
    assert live["http_validated_files"] == 1
    assert live["raw_finding_count"] == 1
    assert live["raw_findings"][0]["finding_verdict"] == "false positive"
    assert live["raw_findings"][0]["valid_for_grading"] is False
    assert live["false_positives_per_file"] == {"numerator": 0, "denominator": 1, "value": 0.0}
    assert live["zero_problem_expectation_violations"] == 1
    assert live["ungraded_problem_count"] == 1
    assert live["modes"]["static"]["grading_coverage"] == {
        "numerator": 0,
        "denominator": 1,
        "value": 0.0,
    }


def test_manifest_partition_and_repository_catalog_preserve_canonical_audit_metadata():
    report = files_fixture()
    report["manifest"]["partition"] = "development"
    report["manifest"]["cases"][0].pop("split")
    report["manifest"]["cases"][0]["repo"] = "upstream"
    report["manifest"]["repositories"] = [
        {"id": "upstream", "canonical_url": "https://github.com/example/upstream"}
    ]
    summary = reporter().summarize_evaluation(report, reviews_fixture())
    assert summary["audit_rows"][0]["repo"] == "https://github.com/example/upstream"
    assert summary["audit_rows"][0]["compose_files"] == ["compose.yaml", "override.yaml"]


def test_duplicate_manifest_case_ids_cannot_hide_selected_files():
    report = files_fixture()
    report["manifest"]["cases"].append(report["manifest"]["cases"][0])
    with pytest.raises(ValueError, match="unique"):
        reporter().summarize_evaluation(report, reviews_fixture())


def test_native_timings_engine_and_source_fingerprints_survive_live_aggregation():
    timings = {
        "total_ms": 12.5,
        "stages": [{"role": "source", "stage": "dns", "count": 1, "total_ms": 1.25}],
        "requests": [{"operation": "inspect_container", "elapsed_ms": 2.5}],
    }
    record = {
        "id": "a",
        "http": {"ready": True},
        "automatic": {"static": {"report": {"findings": [], "timings": timings}, "wall_ms": 34}},
        "runtime": {
            "engine": {"Version": "29.8.1", "ApiVersion": "1.54", "Os": "linux"},
            "case_start_source_sha256": {"src/dockroute/discovery.py": "a" * 64},
        },
    }
    live = reporter().summarize_evaluation({}, [], live_records=[record])["live"]
    assert live["runs"][0]["timing"] == {
        "total_ms": 12.5,
        "stages": [{"role": "source", "stage": "dns", "count": 1, "total_ms": 1.25}],
        "requests": [{"operation": "inspect_container", "elapsed_ms": 2.5}],
    }
    assert live["runs"][0]["wall_ms"] == 34
    assert live["runtime_provenance"][0]["versions"]["engine"] == {
        "Version": "29.8.1",
        "ApiVersion": "1.54",
        "Os": "linux",
    }
    assert live["runtime_provenance"][0]["versions"]["case_start_source_sha256"] == {
        "src/dockroute/discovery.py": "a" * 64
    }


def test_legacy_singular_timing_reports_remain_readable():
    record = {
        "id": "a",
        "automatic": {"static": {"report": {"findings": [], "timing": {"total_ms": 7}}}},
    }
    live = reporter().summarize_evaluation({}, [], live_records=[record])["live"]
    assert live["runs"][0]["timing"] == {"total_ms": 7}


@pytest.mark.parametrize(
    ("identity", "findings", "expected"),
    [
        ({"source_service": "web", "source": {"stable": True}}, [{"source": "web"}], "web"),
        ({"source": {"stable": True}}, [{"source": "backend"}], "backend"),
        ({"source": "legacy"}, [], "legacy"),
        ({"source": {"stable": True}}, [{"source": "one"}, {"source": "two"}], ""),
    ],
)
def test_manual_source_names_do_not_serialize_fingerprint_metadata(identity, findings, expected):
    record = {
        "id": "a",
        "manual_checks": [{**identity, "target": "db:5432", "report": {"findings": findings}}],
    }
    manual = reporter().summarize_evaluation({}, [], live_records=[record])["live"]["manual_checks"]
    assert manual[0]["source"] == expected


def test_cli_generates_json_csv_and_input_provenance_without_opening_case_roots(tmp_path):
    report = files_fixture()
    manifest = report.pop("manifest")
    manifest["cases"][0]["root"] = str(tmp_path / "must-not-open")
    files = {
        "evaluation": report,
        "reviews": reviews_fixture(),
        "manifest": manifest,
        "policy": policy_fixture(),
    }
    for name, value in files.items():
        (tmp_path / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
    output = tmp_path / "summary.json"
    audit = tmp_path / "audit.csv"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "report_corpus.py"),
            "--evaluation",
            str(tmp_path / "evaluation.json"),
            "--reviews",
            str(tmp_path / "reviews.json"),
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--policy",
            str(tmp_path / "policy.json"),
            "--output",
            str(output),
            "--csv",
            str(audit),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    summary = json.loads(output.read_text(encoding="utf-8"))
    assert summary["pipeline"]["selected_files"] == 1
    assert len(summary["provenance"]["inputs"]) == 4
    assert all(len(item["sha256"]) == 64 for item in summary["provenance"]["inputs"])
    assert len(list(csv.DictReader(audit.open(encoding="utf-8", newline="")))) == 6
