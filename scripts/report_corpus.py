"""Aggregate saved corpus evidence without normalizing Compose or running diagnosis.

The API accepts the evaluator's JSON and independent prediction reviews. Add
``report["manifest"]`` to supply repository/Compose metadata and retain selected
cases that never reached the evaluator. The CLI does this from ``--manifest``.
``live_records`` are saved run_corpus_live records with optional independent
``finding_reviews`` (mode/source/destination/port/code/verdict/notes). No finding
becomes a false positive merely because the application's HTTP check worked.
``fault_records`` contain cases with baseline_validated, mutation_validated,
auto_detected and manual_detected booleans; their conclusions are not fabricated
into raw diagnosis findings. All ratios retain numerator and denominator.
"""

import argparse
import csv
import hashlib
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evaluate_corpus import score_predictions  # noqa: E402

SCHEMA_VERSION = "dockroute.corpus-report/1.0"
AUDIT_COLUMNS = (
    "repo",
    "commit",
    "compose_files",
    "service",
    "discovered_endpoint",
    "discovery_label",
    "diagnosis_code",
    "finding_verdict",
    "notes",
)
VERDICTS = ("true issue", "false positive", "unsure")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"']+")
_METADATA = (
    "dockroute_version",
    "baseline_revision",
    "checkout_revision",
    "evaluator_sha256",
    "evaluated_source_sha256",
    "compose_version",
    "python_version",
    "timing_scopes",
    "manifest_sha256",
    "review_labels_sha256",
)


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _records(value):
    if value is None:
        return []
    if isinstance(value, dict):
        value = value.get("cases", value.get("records", []))
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError("records must be a list of objects")
    return value


def _repo(value):
    if not isinstance(value, str):
        return ""
    try:
        parsed = urlsplit(value)
        if parsed.scheme and parsed.netloc:
            host = parsed.hostname or ""
            if ":" in host:
                host = f"[{host}]"
            if parsed.port:
                host += f":{parsed.port}"
            return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except ValueError:
        return "[invalid URL]"
    return value


def _text(value):
    if value is None:
        return ""
    value = str(value)
    return _URL.sub(lambda match: _repo(match.group()), value).replace("\x00", "")


def _safe(value):
    if isinstance(value, str):
        return _text(value)
    if isinstance(value, list):
        return [_safe(item) for item in value]
    if isinstance(value, dict):
        return {_text(key): _safe(item) for key, item in value.items()}
    return value


def _ratio(numerator, denominator):
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator if denominator else None,
    }


def _duration(value):
    return (
        value
        if isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
        else None
    )


def _edge_key(case_id, edge):
    return (
        case_id,
        edge.get("source"),
        str(edge.get("host", "")).lower().rstrip("."),
        edge.get("port"),
    )


def _endpoint(host, port):
    host = _text(host)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}" if port is not None else host


def _case_metadata(case_id, cases, attempts):
    case, attempt = cases.get(case_id, {}), attempts.get(case_id, {})
    files = case.get("compose_files", attempt.get("compose_files", []))
    if not files:
        files = [
            name
            for name in _mapping(attempt.get("input_hashes"))
            if name.lower().endswith((".yaml", ".yml"))
        ]
    return {
        "repo": _repo(case.get("repo", case.get("repo_url", attempt.get("repo", "")))),
        "commit": _text(case.get("revision", case.get("commit", attempt.get("revision", "")))),
        "compose_files": [_text(item) for item in files] if isinstance(files, list) else [],
    }


def _failure_category(attempt):
    if attempt.get("status") == "not_attempted":
        return "not_attempted"
    code, exit_code = str(attempt.get("error_class", "")), attempt.get("process_returncode")
    if isinstance(exit_code, int) and exit_code < 0 or "crash" in code:
        return "crash"
    if "unsupported" in code:
        return "unsupported"
    if attempt.get("status") == "partial" or any(
        part in code for part in ("interpolation", "unresolved", "missing_env")
    ):
        return "unresolved"
    if (
        code
        in {
            "invalid_compose",
            "invalid_config_or_manifest",
            "config_output_limit",
            "parse_failure",
            "invalid_json",
        }
        or "parse" in code
    ):
        return "parse_failure"
    if "timeout" in code:
        return "timeout"
    if code in {"missing_input", "compose_or_input_unavailable", "input_hash_failed"}:
        return "input_unavailable"
    return "other"


def _pipeline(report):
    manifest = _mapping(report.get("manifest"))
    split = _mapping(report.get("selection")).get("split")
    excluded = {
        case.get("id") for case in _mapping(report.get("selection")).get("excluded_cases", [])
    }
    manifest_cases = _records(manifest)
    ids = [case.get("id") for case in manifest_cases]
    if any(not isinstance(case_id, str) or not case_id for case_id in ids) or len(set(ids)) != len(
        ids
    ):
        raise ValueError("manifest cases require unique case IDs")
    repositories = {
        repository.get("id"): repository.get("canonical_url", repository.get("repo", ""))
        for repository in manifest.get("repositories", [])
    }
    cases = {
        case["id"]: {**case, "repo": repositories.get(case.get("repo"), case.get("repo", ""))}
        for case in manifest_cases
        if case.get("id") not in excluded
        and (split is None or case.get("split", manifest.get("partition")) == split)
    }
    attempts = {}
    for attempt in report.get("attempts", []):
        case_id = attempt.get("case_id")
        if not case_id or case_id in attempts:
            raise ValueError("attempts require unique case IDs")
        attempts[case_id] = attempt
    selected = list(
        dict.fromkeys(
            [*cases, *attempts, *(row.get("case_id") for row in report.get("results", []))]
        )
    )
    results = {row.get("case_id"): row for row in report.get("results", [])}
    per_file = []
    categories: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    for case_id in selected:
        attempt = attempts.get(case_id, {"case_id": case_id, "status": "not_attempted"})
        status = attempt.get("status", "unknown")
        # A result without an attempt remains an execution-accounting gap.
        failed = status != "normalized" or bool(attempt.get("error_class"))
        category = _failure_category(attempt) if failed else None
        statuses[status] += 1
        if category:
            categories[category] += 1
        if attempt.get("error_class"):
            errors[_text(attempt["error_class"])] += 1
        result = results.get(case_id, {})
        per_file.append(
            {
                "case_id": _text(case_id),
                **_case_metadata(case_id, cases, attempts),
                "status": _text(status),
                "error_class": _text(attempt.get("error_class")) or None,
                "failure_category": category,
                "normalization_duration_ms": _duration(
                    attempt.get(
                        "normalization_duration_ms",
                        attempt.get("duration_ms", result.get("normalization_duration_ms")),
                    )
                ),
                "discovery_duration_ms": _duration(
                    attempt.get("discovery_duration_ms", result.get("discovery_duration_ms"))
                ),
                "total_duration_ms": _duration(
                    attempt.get("total_duration_ms", result.get("total_duration_ms"))
                ),
                "process_duration_ms": _duration(attempt.get("process_duration_ms")),
                "command_argv": _safe(attempt.get("command_argv", [])),
                "process_returncode": attempt.get("process_returncode"),
            }
        )
    prep = manifest.get("preparation_failures", report.get("preparation_failures", []))
    prep = [
        {
            key: _safe(item[key])
            for key in ("case_id", "id", "error_class", "status", "repo", "revision")
            if key in item
        }
        for item in _records(prep)
    ]
    summary = {
        "selected_files": len(selected),
        "attempted_files": len(attempts),
        "status_counts": dict(statuses),
        "failure_categories": dict(categories),
        "error_class_counts": dict(errors),
        "failure_rate": _ratio(sum(categories.values()), len(selected)),
        "nonzero_compose_exits": sum(
            isinstance(a.get("process_returncode"), int) and a["process_returncode"] > 0
            for a in attempts.values()
        ),
        "unresolved_fields": sum(len(row.get("unresolved", [])) for row in results.values()),
        "preparation_failures": prep,
        "preparation_failure_count": len(prep),
    }
    return summary, per_file, cases, attempts


def _discovery_audit(report, reviews, cases, attempts):
    labels = reviews.get("labels", []) if isinstance(reviews, dict) else reviews
    labels_by_key = {_edge_key(item.get("case_id"), item): item for item in labels}
    rows = []
    for result in report.get("results", []):
        case_id = result.get("case_id")
        for edge in result.get("intentions", []):
            review = labels_by_key.get(_edge_key(case_id, edge), {})
            dependency = edge.get("dependency_only") or edge.get("port") is None
            rows.append(
                {
                    **_case_metadata(case_id, cases, attempts),
                    "service": _text(edge.get("source")),
                    "discovered_endpoint": _endpoint(edge.get("host"), edge.get("port")),
                    "discovery_label": "dependency-only-unconfirmed"
                    if dependency
                    else review.get("label", "unreviewed"),
                    "diagnosis_code": None,
                    "finding_verdict": "NOT_RUN_FILES_ONLY",
                    "notes": _text(review.get("notes", review.get("note", ""))),
                }
            )
    for review in labels:
        if review.get("label") == "missed":
            rows.append(
                {
                    **_case_metadata(review.get("case_id"), cases, attempts),
                    "service": _text(review.get("source")),
                    "discovered_endpoint": _endpoint(review.get("host"), review.get("port")),
                    "discovery_label": "missed",
                    "diagnosis_code": None,
                    "finding_verdict": "NOT_RUN_FILES_ONLY",
                    "notes": _text(review.get("notes", review.get("note", ""))),
                }
            )
    for case_id, attempt in attempts.items():
        if not any(row.get("case_id") == case_id for row in report.get("results", [])):
            rows.append(
                {
                    **_case_metadata(case_id, cases, attempts),
                    "service": "",
                    "discovered_endpoint": "",
                    "discovery_label": "NOT_EVALUATED",
                    "diagnosis_code": None,
                    "finding_verdict": "NOT_RUN_FILES_ONLY",
                    "notes": _text(attempt.get("error_class", attempt.get("status"))),
                }
            )
    for case_id in cases.keys() - attempts.keys():
        if not any(row.get("case_id") == case_id for row in report.get("results", [])):
            rows.append(
                {
                    **_case_metadata(case_id, cases, attempts),
                    "service": "",
                    "discovered_endpoint": "",
                    "discovery_label": "NOT_EVALUATED",
                    "diagnosis_code": None,
                    "finding_verdict": "NOT_RUN_FILES_ONLY",
                    "notes": "not_attempted",
                }
            )
    return rows


def _finding_key(mode, finding):
    return (
        mode,
        finding.get("source"),
        str(finding.get("destination", "")).lower().rstrip("."),
        finding.get("port"),
        finding.get("code"),
    )


def _manual_source(run):
    """Keep service identity separate from per-invocation source fingerprints."""
    for key in ("source_service", "source"):
        value = run.get(key)
        if isinstance(value, str):
            return _text(value)
    sources = {
        row["source"]
        for row in _mapping(run.get("report")).get("findings", [])
        if isinstance(row.get("source"), str) and row["source"]
    }
    return _text(next(iter(sources))) if len(sources) == 1 else ""


def _live(records, policy, cases, attempts):
    expectations = _mapping(_mapping(policy).get("expectations"))
    problem_codes = set(
        expectations.get("zero_problem_codes", expectations.get("problem_codes", []))
    )
    zero_registered = bool(problem_codes) and bool(
        expectations.get("zero_problem_codes") or expectations.get("working_live_projects")
    )
    abstentions = set(expectations.get("abstention_codes", ["UNKNOWN"]))
    informational = set(expectations.get("informational_codes", ["HEALTHY", "TCP_REACHABLE"]))
    validated = sum(record.get("http", {}).get("ready") is True for record in records)
    denominator = validated if zero_registered else 0
    modes = sorted({mode for record in records for mode in _mapping(record.get("automatic"))})
    raw, runs, audit, manual = [], [], [], []
    mode_summaries = {}
    seen_ids = set()
    for record in records:
        case_id = record.get("case_id", record.get("id"))
        if not case_id or case_id in seen_ids:
            raise ValueError("live records require unique case IDs")
        seen_ids.add(case_id)
        working = record.get("http", {}).get("ready") is True
        reviews = {}
        for review in record.get("finding_reviews", []):
            key = _finding_key(review.get("mode"), review)
            if review.get("verdict") not in VERDICTS:
                raise ValueError("unknown finding verdict")
            if key in reviews:
                raise ValueError("duplicate finding review")
            reviews[key] = review
        matched = set()
        meta = _case_metadata(case_id, cases, attempts)
        provenance = _mapping(record.get("provenance"))
        if not meta["repo"]:
            meta["repo"] = _repo(provenance.get("upstream", ""))
        if not meta["commit"]:
            meta["commit"] = _text(provenance.get("revision"))
        if not meta["compose_files"]:
            files = record.get("compose_files", provenance.get("compose_files", []))
            meta["compose_files"] = (
                [_text(item) for item in files] if isinstance(files, list) else []
            )
        for mode, run in _mapping(record.get("automatic")).items():
            report = _mapping(run.get("report"))
            source = _mapping(run.get("source"))
            grading_valid = bool(
                isinstance(run.get("report"), dict)
                and not run.get("error")
                and not report.get("error")
                and run.get("valid_for_grading", True) is True
                and source.get("valid_for_grading", True) is True
                and source.get("stable", True) is True
                and run.get("process_tree_exited", True) is True
                and run.get("cleanup", "not_needed") in {"complete", "not_needed"}
            )
            runs.append(
                {
                    "case_id": _text(case_id),
                    "mode": _text(mode),
                    "http_validated": working,
                    "report_available": isinstance(run.get("report"), dict),
                    "valid_for_grading": grading_valid,
                    "source": {
                        key: _safe(source[key])
                        for key in (
                            "stable",
                            "before",
                            "after",
                            "dockroute_version",
                            "valid_for_grading",
                        )
                        if key in source
                    },
                    "error": _text(run.get("error")) or None,
                    "exit_code": run.get("exit_code"),
                    "wall_ms": _duration(run.get("wall_ms")),
                    "command": _safe(run.get("command", [])),
                    "cleanup": _text(run.get("cleanup")) or None,
                    "timing": _safe(_mapping(report.get("timings", report.get("timing")))),
                }
            )
            for item in report.get("findings", []):
                key = _finding_key(mode, item)
                review = reviews.get(key, {})
                if review:
                    matched.add(key)
                code = item.get("code", "MISSING_CODE")
                kind = (
                    "problem"
                    if code in problem_codes
                    else "abstention"
                    if code in abstentions
                    else "informational"
                    if code in informational
                    else "unclassified"
                )
                verdict = (
                    review.get("verdict", "unsure")
                    if kind == "problem"
                    else "ABSTENTION"
                    if kind == "abstention"
                    else "INFORMATIONAL"
                    if kind == "informational"
                    else "UNREVIEWED_CODE"
                )
                raw.append(
                    {
                        "case_id": _text(case_id),
                        "mode": _text(mode),
                        "source": _text(item.get("source")),
                        "destination": _text(item.get("destination")),
                        "port": item.get("port"),
                        "code": _text(code),
                        "kind": kind,
                        "finding_verdict": verdict,
                        "explicitly_reviewed": bool(review),
                        "http_validated": working,
                        "graded_zero_problem_baseline": working and zero_registered,
                        "valid_for_grading": grading_valid,
                        "notes": _text(review.get("notes", review.get("note", ""))),
                    }
                )
                audit.append(
                    {
                        **meta,
                        "service": _text(item.get("source")),
                        "discovered_endpoint": _endpoint(item.get("destination"), item.get("port")),
                        "discovery_label": "LIVE_AUTOMATIC_UNREVIEWED",
                        "diagnosis_code": _text(code),
                        "finding_verdict": verdict,
                        "notes": f"mode={_text(mode)}; "
                        + _text(review.get("notes", review.get("note", ""))),
                    }
                )
        if reviews.keys() - matched:
            raise ValueError("finding review does not match a raw automatic finding")
        for index, run in enumerate(record.get("manual_checks", [])):
            manual.append(
                {
                    "case_id": _text(case_id),
                    "check_index": index,
                    "source": _manual_source(run),
                    "target": _text(run.get("target")),
                    "wall_ms": _duration(run.get("wall_ms")),
                    "command": _safe(run.get("command", [])),
                    "error": _text(run.get("error")) or None,
                    "raw_code_counts": dict(
                        Counter(
                            _text(item.get("code", "MISSING_CODE"))
                            for item in _mapping(run.get("report")).get("findings", [])
                        )
                    ),
                }
            )
    for mode in modes:
        findings = [item for item in raw if item["mode"] == mode]
        problems = [
            item
            for item in findings
            if item["kind"] == "problem" and item["graded_zero_problem_baseline"]
        ]
        verdicts = {
            verdict: sum(
                item["finding_verdict"] == verdict and item["valid_for_grading"]
                for item in problems
            )
            for verdict in VERDICTS
        }
        mode_summaries[mode] = {
            "raw_finding_count": len(findings),
            "raw_code_counts": dict(Counter(item["code"] for item in findings)),
            "working_problem_verdicts": verdicts,
            "zero_problem_expectation_violations": len(problems),
            "false_positives_per_file": _ratio(verdicts["false positive"], denominator),
            "report_coverage": _ratio(
                sum(
                    run["mode"] == mode and run["http_validated"] and run["report_available"]
                    for run in runs
                ),
                validated,
            ),
            "grading_coverage": _ratio(
                sum(
                    run["mode"] == mode and run["http_validated"] and run["valid_for_grading"]
                    for run in runs
                ),
                validated,
            ),
            "ungraded_problem_count": sum(not item["valid_for_grading"] for item in problems),
            "unreviewed_problem_count": sum(not item["explicitly_reviewed"] for item in problems),
        }
    problems = [
        item for item in raw if item["kind"] == "problem" and item["graded_zero_problem_baseline"]
    ]
    return {
        "attempted_files": len(records),
        "http_validated_files": validated,
        "graded_working_files": denominator,
        "zero_problem_expectation_registered": zero_registered,
        "raw_finding_count": len(raw),
        "raw_code_counts": dict(Counter(item["code"] for item in raw)),
        "abstention_count": sum(item["kind"] == "abstention" for item in raw),
        "informational_count": sum(item["kind"] == "informational" for item in raw),
        "unclassified_code_count": sum(item["kind"] == "unclassified" for item in raw),
        "zero_problem_expectation_violations": len(problems),
        "unreviewed_problem_count": sum(not item["explicitly_reviewed"] for item in problems),
        "ungraded_problem_count": sum(not item["valid_for_grading"] for item in problems),
        "false_positives_per_file": _ratio(
            sum(
                item["finding_verdict"] == "false positive" and item["valid_for_grading"]
                for item in problems
            ),
            denominator,
        ),
        "false_positive_scope": "all automatic modes combined; mode-specific rates also provided",
        "status_counts": dict(
            Counter(_text(record.get("status", "unknown")) for record in records)
        ),
        "cleanup_counts": dict(
            Counter(
                _text(_mapping(record.get("cleanup")).get("cleanup", "unknown"))
                for record in records
            )
        ),
        "modes": mode_summaries,
        "raw_findings": raw,
        "runs": runs,
        "manual_checks": manual,
        "runtime_provenance": [
            {
                "case_id": _text(record.get("case_id", record.get("id"))),
                "versions": {
                    key: _safe(_mapping(record.get("runtime"))[key])
                    for key in (
                        "python",
                        "docker_sdk",
                        "dockroute",
                        "runner_sha256",
                        "product_source_sha256",
                        "engine",
                        "case_start_source_sha256",
                        "case_start_source_scope",
                        "compose",
                        "repository_revision",
                    )
                    if key in _mapping(record.get("runtime"))
                },
            }
            for record in records
        ],
    }, audit


def _faults(records):
    ids = [record.get("id", record.get("case_id")) for record in records]
    if any(not isinstance(case_id, str) or not case_id for case_id in ids) or len(set(ids)) != len(
        ids
    ):
        raise ValueError("fault records require unique case IDs")
    valid = [
        record
        for record in records
        if record.get("baseline_validated") is True and record.get("mutation_validated") is True
    ]
    return {
        "attempts": len(records),
        "known_validated_faults": len(valid),
        "invalid_attempts": len(records) - len(valid),
        "execution_failed_attempts": sum(
            record.get("status") in {"failed", "execution_failed", "cancelled", "refused"}
            for record in records
        ),
        "automatic_recall": _ratio(
            sum(record.get("auto_detected") is True for record in valid), len(valid)
        ),
        "manual_recall": _ratio(
            sum(record.get("manual_detected") is True for record in valid), len(valid)
        ),
        "records": [
            {
                key: _safe(record[key])
                for key in (
                    "id",
                    "case_id",
                    "expected_code",
                    "baseline_validated",
                    "mutation_validated",
                    "auto_detected",
                    "manual_detected",
                    "status",
                    "notes",
                    "error",
                )
                if key in record
            }
            for record in records
        ],
        "scope": "validated injected faults; manual checks remain separate from automatic discovery",
    }


def summarize_evaluation(report, reviews, *, live_records=None, fault_records=None, policy=None):
    """Return auditable metrics from saved evidence; never inspect case root paths."""
    if not isinstance(report, dict):
        raise ValueError("evaluation must be an object")
    # Older stored reports may omit dependency_only. A portless edge cannot be
    # confirmed as an endpoint merely because a reviewer supplied a label.
    scoring_report = {
        **report,
        "results": [
            {
                **row,
                "intentions": [
                    {
                        **edge,
                        "dependency_only": bool(edge.get("dependency_only"))
                        or edge.get("port") is None,
                    }
                    for edge in row.get("intentions", [])
                ],
            }
            for row in report.get("results", [])
        ],
    }
    score = score_predictions(scoring_report, reviews)
    pipeline, per_file, cases, attempts = _pipeline(report)
    # The scorer uses attempts for case coverage; retain unattempted selected cases too.
    score["evaluated_case_coverage"]["selected"] = pipeline["selected_files"]
    score["evaluated_case_coverage"]["skipped_or_partial"] = pipeline["failure_rate"]["numerator"]
    if pipeline["failure_rate"]["numerator"]:
        score["corpus_recall_complete"] = False
    live, live_audit = _live(_records(live_records), policy, cases, attempts)
    review_metadata = _mapping(reviews)
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "saved-corpus-evidence",
        "discovery": score,
        "pipeline": pipeline,
        "runtime": {
            "scope": "single measured pass per file; unavailable durations remain null",
            "per_file": per_file,
        },
        "live": live,
        "faults": _faults(_records(fault_records)),
        "review_provenance": {
            key: _safe(review_metadata[key])
            for key in (
                "reviewer",
                "scope",
                "frozen_oracle_sha256",
                "frozen_manifest_sha256",
                "created_utc",
                "limitations",
            )
            if key in review_metadata
        },
        "provenance": {
            "evaluation_metadata": {
                key: _safe(_mapping(report.get("metadata"))[key])
                for key in _METADATA
                if key in _mapping(report.get("metadata"))
            }
        },
        "audit_rows": _discovery_audit(report, reviews, cases, attempts) + live_audit,
    }


def export_audit_csv(summary, destination):
    """Write the public audit allowlist to a path or an already-open text stream."""
    stream = destination if hasattr(destination, "write") else None
    if stream is None:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        stream = path.open("w", encoding="utf-8", newline="")
    try:
        writer = csv.DictWriter(stream, fieldnames=AUDIT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in summary.get("audit_rows", []):
            output = {key: row.get(key) for key in AUDIT_COLUMNS}
            output["compose_files"] = ";".join(row.get("compose_files", []))
            writer.writerow(output)
    finally:
        if stream is not destination:
            stream.close()


def _load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("evaluation", "reviews", "manifest", "policy", "output", "csv"):
        parser.add_argument(f"--{flag}", required=True, type=Path)
    parser.add_argument(
        "--live-dir", type=Path, help="Directory of saved top-level live result JSON files"
    )
    parser.add_argument("--faults", type=Path, help="Saved validated fault attempts JSON")
    args = parser.parse_args(argv)
    try:
        report = _load(args.evaluation)
        report["manifest"] = _load(args.manifest)
        if args.live_dir and not args.live_dir.is_dir():
            raise ValueError("live evidence directory is missing")
        live_paths = sorted(args.live_dir.glob("*.json")) if args.live_dir else []
        summary = summarize_evaluation(
            report,
            _load(args.reviews),
            live_records=[_load(path) for path in live_paths],
            fault_records=_load(args.faults) if args.faults else None,
            policy=_load(args.policy),
        )
        inputs = [args.evaluation, args.reviews, args.manifest, args.policy, *live_paths]
        if args.faults:
            inputs.append(args.faults)
        summary["provenance"]["inputs"] = [
            {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in inputs
        ]
        summary["provenance"]["reporter_sha256"] = hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(summary, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8"
        )
        export_audit_csv(summary, args.csv)
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(2, "reporting failed: unreadable or inconsistent saved evidence\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
