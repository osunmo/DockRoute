"""Saved fault evidence must not borrow manual or unvalidated diagnostic credit."""

import importlib
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def adapter():
    assert importlib.util.find_spec("scripts.report_corpus_faults") is not None, (
        "Fault adapter is missing"
    )
    return importlib.import_module("scripts.report_corpus_faults")


def diagnostic(code="NETWORK_ISOLATION", *, stable=True, host="backend", pin="a"):
    return {
        "valid_for_grading": stable,
        "source": {
            "stable": stable,
            "before": {"product_source_sha256": {"discovery.py": pin * 64}},
            "after": {"product_source_sha256": {"discovery.py": pin * 64}},
        },
        "report": {
            "project": "dockroute-corpus-" + "1" * 32,
            "findings": [{"source": "web", "destination": host, "port": 9091, "code": code}],
        },
    }


def fault(
    case_id="a",
    *,
    observed=True,
    static="correct_root_cause",
    probe="missed_discovery",
    manual="correct_root_cause",
):
    return {
        "mutation": {
            "id": case_id,
            "kind": "separate_network",
            "expected": {
                "source": "web",
                "host": "backend",
                "port": 9091,
                "diagnostic_code": "NETWORK_ISOLATION",
                "http": 502,
            },
        },
        "raw": {
            "project": "dockroute-corpus-" + "1" * 32,
            "status": "complete",
            "cleanup": {"cleanup": "complete"},
            "http": {"ready": True, "http_status": 502},
            "automatic": {"static": diagnostic(), "probe": diagnostic("UNKNOWN")},
            "manual_checks": [{"source_service": "web", "target": "backend:9091", **diagnostic()}],
        },
        "assessment": {
            "application_fault_observed": observed,
            "execution_class": "fault_http_failure",
            "automatic": {"static": {"classification": static}, "probe": {"classification": probe}},
            "manual": [{"classification": manual}],
        },
    }


def report(cases):
    return {
        "schema_version": "corpus-faults-results-1",
        "status": "complete",
        "baseline": {
            "validated_http": {"ready": True, "http_status": 200, "body_pattern_matched": True}
        },
        "product_source_sha256": {"discovery.py": "a" * 64},
        "cases": cases,
        "unsupported": [{"id": "published_host_port", "executed": False}],
        "not_run": [{"id": "remaining", "reason": "prior_cleanup_uncertain"}],
    }


def test_validated_fault_denominators_and_manual_credit_remain_separate():
    data = report(
        [
            fault("hit"),
            fault("miss", static="abstained", manual="abstained"),
            fault("invalid", observed=False),
        ]
    )
    data["cases"][1]["raw"]["automatic"]["static"] = diagnostic("UNKNOWN")
    data["cases"][1]["raw"]["manual_checks"][0] = {
        "source_service": "web",
        "target": "backend:9091",
        **diagnostic("UNKNOWN"),
    }
    result = adapter().summarize_faults(data)
    assert result["supported_planned"] == 4
    assert result["attempted"] == 3
    assert result["known_validated_faults"] == 2
    assert result["invalid_attempts"] == 1
    assert result["unsupported_count"] == 1 and result["not_run_count"] == 1
    assert result["phases"]["static"]["recall"] == {"numerator": 1, "denominator": 2, "value": 0.5}
    assert result["phases"]["probe"]["recall"] == {"numerator": 0, "denominator": 2, "value": 0.0}
    assert result["phases"]["manual"]["recall"] == {"numerator": 1, "denominator": 2, "value": 0.5}


@pytest.mark.parametrize(
    "damage", ["source_changed", "source_mismatch", "wrong_endpoint", "wrong_project", "wrong_code"]
)
def test_claimed_root_cause_needs_actual_valid_pinned_matching_diagnosis(damage):
    data = report([fault()])
    run = data["cases"][0]["raw"]["automatic"]["static"]
    if damage == "source_changed":
        run["source"]["stable"] = False
    elif damage == "source_mismatch":
        run["source"]["after"]["product_source_sha256"] = {"discovery.py": "b" * 64}
    elif damage == "wrong_endpoint":
        run["report"]["findings"][0]["destination"] = "other"
    elif damage == "wrong_project":
        run["report"]["project"] = "unrelated-project"
    else:
        run["report"]["findings"][0]["code"] = "UNKNOWN"
    result = adapter().summarize_faults(data)
    assert result["phases"]["static"]["recall"]["numerator"] == 0
    assert result["phases"]["static"]["recall"]["denominator"] == 1


def test_missing_baseline_proof_or_missing_attempts_return_null_recall():
    data = report([fault()])
    data["baseline"]["validated_http"]["body_pattern_matched"] = False
    result = adapter().summarize_faults(data)
    assert result["known_validated_faults"] == 0
    assert result["phases"]["manual"]["recall"]["value"] is None
    assert adapter().summarize_faults(report([]))["phases"]["static"]["recall"]["value"] is None


def test_duplicate_supported_or_unrun_ids_are_rejected():
    data = report([fault("remaining")])
    with pytest.raises(ValueError, match="unique"):
        adapter().summarize_faults(data)


@pytest.mark.parametrize("verified,credit", [(True, 1), (False, 0)])
def test_loopback_credit_requires_owned_listener_trace_proof(verified, credit):
    data = report([fault()])
    expected = data["cases"][0]["mutation"]["expected"]
    expected.update(diagnostic_code="LOOPBACK_ONLY_LISTENER", destination_service="backend")
    run = data["cases"][0]["raw"]["automatic"]["static"]
    row = run["report"]["findings"][0]
    row.update(
        code="LOOPBACK_ONLY_LISTENER",
        destination_service="backend",
        source_container="a" * 64,
    )
    run["report"]["services"] = [
        {
            "service": "web",
            "state": "running",
            "container_id": "a" * 64,
            "container_name": "web-container",
        },
        {
            "service": "backend",
            "state": "running",
            "container_id": "b" * 64,
            "container_name": "backend-container",
        },
    ]
    trace = []
    for role, identifier in (("source", "a" * 64), ("destination", "b" * 64)):
        trace.extend(
            [
                {
                    "role": role,
                    "stage": stage,
                    "state": "TCP_REFUSED"
                    if role == "source" and stage == "result_parsing"
                    else "SUCCESS",
                }
                for stage in ("namespace", "result_parsing")
            ]
        )
        trace.append(
            {
                "role": role,
                "stage": "create",
                "state": "SUCCESS",
                "helper_configuration": {
                    "network_mode": "container:" + identifier,
                    "execution_id": "c" * 32,
                },
            }
        )
    row["probe"] = {
        "state": "TCP_REFUSED",
        "listener_state": "SUCCESS",
        "listener_verified": verified,
        "listener_addresses": ["127.0.0.1"],
        "execution_id": "c" * 32,
        "dns": "ok",
        "tcp": "refused",
        "trace": trace,
    }
    result = adapter().summarize_faults(data)
    assert result["phases"]["static"]["recall"]["numerator"] == credit


def test_claimed_observation_without_raw_behavior_proof_cannot_enter_denominator():
    data = report([fault()])
    data["cases"][0]["raw"]["http"] = {"ready": True, "http_status": 200}
    result = adapter().summarize_faults(data)
    assert result["known_validated_faults"] == 0
    assert result["invalid_attempts"] == 1
    assert result["phases"]["static"]["recall"]["value"] is None


def test_missing_expected_fields_and_missing_finding_fields_cannot_match_none():
    data = report([fault()])
    data["cases"][0]["mutation"]["expected"] = {}
    data["cases"][0]["raw"]["automatic"]["static"]["report"]["findings"] = [{}]
    result = adapter().summarize_faults(data)
    assert result["phases"]["static"]["recall"]["numerator"] == 0
    assert result["known_validated_faults"] == 0


def test_manual_verdict_cannot_borrow_valid_evidence_from_another_check():
    data = report([fault()])
    checks = data["cases"][0]["raw"]["manual_checks"]
    checks.append({"source_service": "web", "target": "backend:9091", **diagnostic(stable=False)})
    data["cases"][0]["assessment"]["manual"] = [
        {"classification": "abstained"},
        {"classification": "correct_root_cause"},
    ]
    result = adapter().summarize_faults(data)
    assert result["phases"]["manual"]["recall"]["numerator"] == 0


def test_successful_expected_http_status_is_not_an_observed_injected_failure():
    data = report([fault()])
    data["cases"][0]["mutation"]["expected"]["http"] = 200
    data["cases"][0]["raw"]["http"]["http_status"] = 200
    result = adapter().summarize_faults(data)
    assert result["known_validated_faults"] == 0
    assert result["phases"]["static"]["recall"]["value"] is None
