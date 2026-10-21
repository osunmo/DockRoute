"""Freeze a random review sample and estimate finite-corpus endpoint precision.

This tool reads saved evaluator JSON only. It never runs Docker or creates labels.
Select once with a preregistered seed BEFORE reading the selected predictions.
Review every sampled endpoint, including difficult cases, then use ``score``.
Unknown labels stay unknown; they are never dropped from the sampling denominator.
The interval is conditional on the labels being correct, not reviewer accuracy.
"""

import argparse
import hashlib
import json
import math
import random
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "dockroute.prediction-sampling/1.0"
INCORRECT = {"wrong-target", "not-a-connection"}
LABELS = {"correct", *INCORRECT, "unsure", "unreviewed", "missed"}


def _digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode()
    ).hexdigest()


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _key(case, row):
    if not isinstance(row, dict):
        raise ValueError("prediction or review must be an object")
    values = [case, row.get("source"), row.get("host")]
    if any(not isinstance(v, str) or not v or len(v) > 255 for v in values):
        raise ValueError("prediction identifiers must be nonempty strings")
    if any(not re.fullmatch(r"[a-zA-Z0-9_.:\-]+", v) for v in values):
        raise ValueError("unsafe prediction identifier")
    port = row.get("port")
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("invalid prediction port")
    return case, row["source"], row["host"].lower().rstrip("."), port


def _row(key):
    return dict(zip(("case_id", "source", "host", "port"), key))


def _reviews(value):
    rows = value.get("labels", []) if isinstance(value, dict) else value
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("reviews must contain a labels list")
    return rows


def select_sample(reports, reviews, *, size=60, seed, inputs=None, command=None):
    """One simple random sample from all previously unreviewed endpoints.

    Reviewed endpoints form a census stratum. All other endpoint predictions
    form one simple-random-sample stratum, not one convenient sample per repo.
    """
    if type(size) is not int or size < 1 or not isinstance(seed, str) or not seed:
        raise ValueError("positive sample size and nonempty preregistered seed required")
    if not reports or len(reports) != len(reviews):
        raise ValueError("one review input per evaluator report is required")
    population, excluded, known, metadata, attempts = {}, set(), {}, [], []
    for report, review_document in zip(reports, reviews):
        local, local_excluded = set(), set()
        if not isinstance(report, dict) or not isinstance(report.get("results"), list):
            raise ValueError("evaluator report must contain results")
        metadata.append(report.get("metadata", {}))
        attempts.extend(report.get("attempts", []))
        for result in report["results"]:
            if not isinstance(result, dict) or not isinstance(result.get("intentions", []), list):
                raise ValueError("prediction result must contain an intentions list")
            for edge in result.get("intentions", []):
                key = _key(result.get("case_id"), edge)
                if key in population or key in excluded:
                    raise ValueError("duplicate prediction across input population")
                if edge.get("dependency_only") or key[3] is None:
                    excluded.add(key)
                    local_excluded.add(key)
                else:
                    population[key] = _row(key)
                    local.add(key)
        seen = set()
        for review in _reviews(review_document):
            label = review.get("label")
            if label not in LABELS:
                raise ValueError("unknown existing review label")
            key = _key(review.get("case_id"), review)
            if key in seen:
                raise ValueError("duplicate existing review")
            seen.add(key)
            if label == "missed":
                if key in local:
                    raise ValueError("missed label matches a prediction")
                continue
            if key in local_excluded:
                continue
            if key not in local:
                raise ValueError("existing review does not match its report")
            if label == "correct" or label in INCORRECT:
                known[key] = label
    ordered = sorted(population)
    unknown = [key for key in ordered if key not in known]
    chosen = sorted(random.Random(seed).sample(unknown, min(size, len(unknown))))
    result = {
        "schema_version": SCHEMA,
        "kind": "selection",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "method": "simple-random-without-replacement; Python random.Random(str_seed).sample",
        "python_version": sys.version.split()[0],
        "seed": seed,
        "requested_size": size,
        "counts": {
            "eligible": len(population),
            "known_correct": sum(v == "correct" for v in known.values()),
            "known_incorrect": sum(v in INCORRECT for v in known.values()),
            "unreviewed": len(unknown),
            "sampled": len(chosen),
            "dependency_only_excluded": len(excluded),
        },
        "population_sha256": _digest([_row(key) for key in ordered]),
        "unreviewed_population_sha256": _digest([_row(key) for key in unknown]),
        "population": [
            {**_row(key), "existing_label": known.get(key, "unreviewed")} for key in ordered
        ],
        "sample": [_row(key) for key in chosen],
        "inputs": inputs or [],
        "evaluated_metadata": metadata,
        "case_accounting": [
            {"case_id": a.get("case_id"), "status": a.get("status")} for a in attempts
        ],
        "command": command or [],
        "scope": "All port-bearing predictions in these saved reports; not unseen repositories.",
    }
    result["selection_sha256"] = _digest(result)
    return result


def exact_interval(population, sample_size, observed):
    """95% equal-tailed hypergeometric confidence set for total successes K.

    Invert the two exact one-sided tests at alpha/2=.025. Keep K when both
    P_K(X >= observed) and P_K(X <= observed) are at least .025. Integer
    comparisons avoid roundoff at the tail threshold. This accounts for sampling
    without replacement and becomes exact when the entire population is reviewed.
    """
    if any(type(v) is not int for v in (population, sample_size, observed)) or not (
        0 <= observed <= sample_size <= population
    ):
        raise ValueError("invalid finite-population counts")
    denominator = math.comb(population, sample_size)
    accepted = []
    for total in range(observed, population - sample_size + observed + 1):
        lower, upper = 0, 0
        for value in range(max(0, sample_size - population + total), min(total, sample_size) + 1):
            weight = math.comb(total, value) * math.comb(population - total, sample_size - value)
            if value <= observed:
                lower += weight
            if value >= observed:
                upper += weight
        if lower * 40 >= denominator and upper * 40 >= denominator:
            accepted.append(total)
    return min(accepted), max(accepted)


def score_sample(selection, review_document):
    if not isinstance(selection, dict) or not isinstance(review_document, dict):
        raise ValueError("selection and review document must be objects")
    expected = selection.get("selection_sha256")
    if expected != _digest(
        {key: value for key, value in selection.items() if key != "selection_sha256"}
    ):
        raise ValueError("selection hash mismatch")
    if review_document.get("selection_sha256") != expected:
        raise ValueError("reviews reference a different selection")
    reviewer = review_document.get("reviewer_kind")
    if reviewer not in {"agent-source", "human", "mixed"}:
        raise ValueError("reviewer_kind must identify agent-source, human or mixed review")
    selected = {_key(r["case_id"], r) for r in selection["sample"]}
    labels = {}
    review_rows = review_document.get("reviews", [])
    if not isinstance(review_rows, list) or any(not isinstance(row, dict) for row in review_rows):
        raise ValueError("sample reviews must be a list of objects")
    for row in review_rows:
        key = _key(row.get("case_id"), row)
        label = row.get("label")
        if key not in selected or key in labels or label not in LABELS - {"missed"}:
            raise ValueError("duplicate, invalid or unselected sample review")
        if label in {"correct", *INCORRECT} and not row.get("evidence"):
            raise ValueError("decided sample reviews require source evidence")
        labels[key] = label
    counts = {
        "selected": len(selected),
        "correct": sum(label == "correct" for label in labels.values()),
        "incorrect": sum(label in INCORRECT for label in labels.values()),
        "unsure": sum(label == "unsure" for label in labels.values()),
        "unreviewed": len(selected) - len(labels) + sum(v == "unreviewed" for v in labels.values()),
    }
    known = selection["counts"]["known_correct"]
    total = selection["counts"]["eligible"]
    population = selection["counts"]["unreviewed"]
    sample = len(selected)
    good, unresolved = counts["correct"], counts["unsure"] + counts["unreviewed"]
    lo_k = exact_interval(population, sample, good)[0]
    hi_k = exact_interval(population, sample, good + unresolved)[1]
    estimate = (
        (known + population * good / sample) / total
        if total and sample and not unresolved
        else None
    )
    if total and not population:
        estimate = known / total
    bounds = (
        [
            (known + population * good / sample) / total,
            (known + population * (good + unresolved) / sample) / total,
        ]
        if total and sample
        else ([known / total, (known + population) / total] if total else [None, None])
    )
    return {
        "schema_version": SCHEMA,
        "kind": "precision-estimate",
        "selection_sha256": expected,
        "review_sha256": _digest(review_document),
        "reviewer_kind": reviewer,
        "independent_human_review": False,
        "sample_counts": counts,
        "population_counts": selection["counts"],
        "overall_precision": {
            "denominator": total,
            "estimate": estimate,
            "estimate_bounds": bounds,
            "confidence_interval_95": (
                [(known + lo_k) / total, (known + hi_k) / total] if total else [None, None]
            ),
            "confidence_method": "Exact equal-tailed hypergeometric inversion, known-label census stratum plus one random unreviewed stratum; union over unresolved sample labels.",
            "logical_bounds": (
                [(known + good) / total, (known + population - counts["incorrect"]) / total]
                if total
                else [None, None]
            ),
        },
        "case_accounting": selection["case_accounting"],
        "limitations": [
            "Conditional on existing and new labels being correct; sampling does not quantify reviewer error.",
            "Not a recall estimate and not accuracy on unseen repositories.",
            "Normalization failures remain in case accounting; files with no predictions do not contribute to endpoint precision.",
            "No complete-case estimate is reported when sampled reviews are missing or unsure.",
            "Reviewer identity alone does not establish independence; independent human review is not asserted.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command_name", required=True)
    choose = sub.add_parser("select", help="Freeze sample before reviewing predictions")
    choose.add_argument("--input", type=Path, action="append", required=True)
    choose.add_argument(
        "--labels", type=Path, action="append", help="One labels JSON per input, in input order"
    )
    choose.add_argument("--seed", required=True)
    choose.add_argument("--size", type=int, default=60)
    choose.add_argument("--output", type=Path, required=True)
    score = sub.add_parser("score", help="Estimate precision from frozen selection and reviews")
    score.add_argument("--selection", type=Path, required=True)
    score.add_argument("--reviews", type=Path, required=True)
    score.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise ValueError("output exists; preserve previous selection/results")
        if args.command_name == "select":
            paths = args.labels or []
            if paths and len(paths) != len(args.input):
                raise ValueError("provide one --labels per --input, or none")
            reports = [json.loads(p.read_text(encoding="utf-8-sig")) for p in args.input]
            reviews = [json.loads(p.read_text(encoding="utf-8-sig")) for p in paths] or [
                [] for _ in reports
            ]
            pins = [
                {
                    "path": str(p),
                    "sha256": file_sha256(p),
                    "labels_path": str(paths[i]) if paths else None,
                    "labels_sha256": file_sha256(paths[i]) if paths else None,
                }
                for i, p in enumerate(args.input)
            ]
            result = select_sample(
                reports,
                reviews,
                size=args.size,
                seed=args.seed,
                inputs=pins,
                command=list(argv if argv is not None else sys.argv),
            )
        else:
            result = score_sample(
                json.loads(args.selection.read_text(encoding="utf-8-sig")),
                json.loads(args.reviews.read_text(encoding="utf-8-sig")),
            )
            result["command"] = list(argv if argv is not None else sys.argv)
            result["selection_file_sha256"] = file_sha256(args.selection)
            result["review_file_sha256"] = file_sha256(args.reviews)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, ensure_ascii=True, allow_nan=False)
            handle.write("\n")
        print(f"Saved {result['kind']} to {args.output}")
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print(
            "Sampling failed: invalid input, review, or existing output (values omitted).",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
