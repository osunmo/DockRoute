"""Score saved nested real-project fault records without running any diagnostic.

The driver records mutations, unmodified raw reports, and independent behavioral
assessments. This adapter requires observed faults and actual matching diagnostic
evidence before granting credit, and separates automatic static/probe phases from
explicit manual checks. Unsupported and not-run attempts remain visible.
"""

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.report_corpus import _manual_source, _mapping, _ratio, _safe  # noqa: E402
from scripts.run_corpus_faults import _listener_proof, assess_fault  # noqa: E402


def _expected_valid(expected: dict[str, Any]) -> bool:
    return bool(
        all(
            isinstance(expected.get(key), str) and expected[key].strip()
            for key in ("source", "host", "diagnostic_code")
        )
        and expected["diagnostic_code"] not in {"UNKNOWN", "HEALTHY", "TCP_REACHABLE"}
        and isinstance(expected.get("port"), int)
        and not isinstance(expected["port"], bool)
        and 1 <= expected["port"] <= 65535
        and (
            expected.get("http") == "unavailable"
            or isinstance(expected.get("http"), int)
            and not isinstance(expected["http"], bool)
            and 400 <= expected["http"] <= 599
        )
    )


def _valid(
    run: dict[str, Any], expected: dict[str, Any], pin: dict[str, str], project: str
) -> bool:
    source = _mapping(run.get("source"))
    report = _mapping(run.get("report"))
    return bool(
        _expected_valid(expected)
        and pin
        and project
        and run.get("valid_for_grading") is True
        and source.get("stable") is True
        and not run.get("error")
        and not report.get("error")
        and report.get("project") == project
        and _mapping(source.get("before")).get("product_source_sha256") == pin
        and _mapping(source.get("after")).get("product_source_sha256") == pin
        and any(
            row.get("source") == expected.get("source")
            and row.get("destination") == expected.get("host")
            and row.get("port") == expected.get("port")
            and row.get("code") == expected.get("diagnostic_code")
            and (
                expected.get("diagnostic_code") != "LOOPBACK_ONLY_LISTENER"
                or _listener_proof(row, report, {**expected, "project": project})
            )
            for row in report.get("findings", [])
        )
    )


def summarize_faults(report: dict[str, Any]) -> dict[str, Any]:
    """Keep all saved attempts; score only validated faults and verified results."""
    cases = report.get("cases", [])
    not_run, unsupported = report.get("not_run", []), report.get("unsupported", [])
    ids = (
        [case.get("mutation", {}).get("id") for case in cases]
        + [row.get("id") for row in not_run]
        + [row.get("id") for row in unsupported]
    )
    if any(not isinstance(case_id, str) or not case_id for case_id in ids) or len(set(ids)) != len(
        ids
    ):
        raise ValueError("fault attempts require unique IDs")
    http = _mapping(_mapping(report.get("baseline")).get("validated_http"))
    baseline_valid = bool(
        http.get("ready") is True
        and http.get("body_pattern_matched") is True
        and isinstance(http.get("http_status"), int)
        and 200 <= http["http_status"] < 300
    )
    pin = report.get("product_source_sha256", {})
    rows = []
    for case in cases:
        mutation, raw, assessment = (
            case["mutation"],
            case.get("raw", {}),
            case.get("assessment", {}),
        )
        expected, project = mutation.get("expected", {}), raw.get("project", "")
        recomputed = assess_fault(mutation, raw, pin) if _expected_valid(expected) else {}
        observed = (
            assessment.get("application_fault_observed") is True
            and recomputed.get("application_fault_observed") is True
        )
        known = baseline_valid and observed
        phases = {}
        for phase in ("static", "probe"):
            run = _mapping(raw.get("automatic")).get(phase, {})
            verdict = _mapping(assessment.get("automatic")).get(phase, {})
            classification = verdict.get("classification", "not_run")
            actual = _valid(run, expected, pin, project)
            phases[phase] = {
                "classification": classification,
                "actual_expected_code_verified": actual,
                "credited": known and classification == "correct_root_cause" and actual,
            }
        manual_verdicts = assessment.get("manual", [])
        checks = [
            run
            for run in raw.get("manual_checks", [])
            if _manual_source(run) == expected.get("source")
            and run.get("target") == f"{expected.get('host')}:{expected.get('port')}"
        ]
        actual_manual = any(_valid(run, expected, pin, project) for run in checks)
        manual_aligned = len(checks) == len(manual_verdicts)
        manual_credited = manual_aligned and any(
            verdict.get("classification") == "correct_root_cause"
            and _valid(run, expected, pin, project)
            for run, verdict in zip(checks, manual_verdicts)
        )
        phases["manual"] = {
            "classifications": [row.get("classification") for row in manual_verdicts],
            "actual_expected_code_verified": actual_manual,
            "assessment_alignment_valid": manual_aligned,
            "credited": known and manual_credited,
        }
        rows.append(
            {
                "id": mutation["id"],
                "kind": mutation.get("kind"),
                "expected": _safe(expected),
                "baseline_validated": baseline_valid,
                "mutation_behavior_validated": observed,
                "known_validated_fault": known,
                "original_status": raw.get("status", "unknown"),
                "execution_class": assessment.get("execution_class"),
                "cleanup": _mapping(raw.get("cleanup")).get("cleanup"),
                "phases": phases,
            }
        )
    known_count = sum(row["known_validated_fault"] for row in rows)
    phases_summary = {}
    for phase in ("static", "probe", "manual"):
        phases_summary[phase] = {
            "recall": _ratio(sum(row["phases"][phase]["credited"] for row in rows), known_count),
            "verified_expected_code_cases": sum(
                row["phases"][phase]["actual_expected_code_verified"]
                and row["known_validated_fault"]
                for row in rows
            ),
        }
    return {
        "schema_version": "dockroute.corpus-fault-report/1.0",
        "scope": "Saved validated injected faults; manual checks separate from automatic discovery",
        "original_status": report.get("status", "unknown"),
        "error": _safe(report.get("error")),
        "baseline_validated": baseline_valid,
        "supported_planned": len(cases) + len(not_run),
        "attempted": len(cases),
        "known_validated_faults": known_count,
        "invalid_attempts": len(cases) - known_count,
        "failed_or_refused_attempts": sum(
            row["original_status"] in {"failed", "refused", "cancelled"} for row in rows
        ),
        "original_status_counts": dict(Counter(row["original_status"] for row in rows)),
        "execution_class_counts": dict(Counter(row["execution_class"] for row in rows)),
        "cleanup_counts": dict(Counter(row["cleanup"] for row in rows)),
        "not_run_count": len(not_run),
        "not_run": _safe(not_run),
        "unsupported_count": len(unsupported),
        "unsupported": _safe(unsupported),
        "phases": phases_summary,
        "cases": rows,
        "product_source_sha256": _safe(pin),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--faults", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = summarize_faults(json.loads(args.faults.read_text(encoding="utf-8-sig")))
        result["provenance"] = {
            "input_file": args.faults.name,
            "input_sha256": hashlib.sha256(args.faults.read_bytes()).hexdigest(),
            "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(2, "fault reporting failed: unreadable or inconsistent saved evidence\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
