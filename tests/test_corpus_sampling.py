"""Random review selection must remain reproducible, unbiased and auditable."""

import importlib.util
import itertools
import json
import math
from pathlib import Path

import pytest


@pytest.fixture
def sampler():
    path = Path(__file__).resolve().parents[1] / "scripts" / "sample_corpus_predictions.py"
    assert path.is_file(), "the reproducible precision sampler is missing"
    spec = importlib.util.spec_from_file_location("corpus_sampling", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def corpus(count=10):
    return {
        "metadata": {"checkout_revision": "a" * 40, "evaluated_source_sha256": {"x": "b" * 64}},
        "results": [
            {
                "case_id": "sample",
                "intentions": [
                    {"source": "web", "host": f"db{i}", "port": 5432} for i in range(count)
                ]
                + [{"source": "web", "host": "dependency", "port": None}],
            }
        ],
        "attempts": [{"case_id": "sample", "status": "partial"}],
    }


def review(i, label="correct"):
    return {"case_id": "sample", "source": "web", "host": f"db{i}", "port": 5432, "label": label}


def select(sampler, count=10, size=4, reviews=None):
    return sampler.select_sample([corpus(count)], [reviews or []], size=size, seed="fixed-seed")


def scored_reviews(selection, labels):
    return {
        "selection_sha256": selection["selection_sha256"],
        "reviewer_kind": "agent-source",
        "reviews": [
            {**row, "label": label, "evidence": "pinned source location"}
            for row, label in zip(selection["sample"], labels)
        ],
    }


def test_selection_reproducible_order_independent_without_replacement(sampler):
    first = select(sampler, reviews=[review(0), review(1, "not-a-connection")])
    reordered = corpus()
    reordered["results"][0]["intentions"].reverse()
    second = sampler.select_sample(
        [reordered], [[review(1, "not-a-connection"), review(0)]], size=4, seed="fixed-seed"
    )
    assert first["sample"] == second["sample"]
    assert first["population_sha256"] == second["population_sha256"]
    assert len({row["host"] for row in first["sample"]}) == 4
    assert {row["host"] for row in first["sample"]}.isdisjoint({"db0", "db1", "dependency"})
    assert first["counts"] == {
        "eligible": 10,
        "known_correct": 1,
        "known_incorrect": 1,
        "unreviewed": 8,
        "sampled": 4,
        "dependency_only_excluded": 1,
    }
    assert first["case_accounting"][0]["status"] == "partial"


def test_source_input_and_selection_tampering_rejected(sampler):
    selection = select(sampler)
    reviews = scored_reviews(selection, ["correct"] * 4)
    selection["sample"][0]["port"] = 6379
    with pytest.raises(ValueError, match="selection"):
        sampler.score_sample(selection, reviews)


@pytest.mark.parametrize("mutation", ["duplicate", "foreign", "invalid_port", "label"])
def test_invalid_population_or_labels_refused(sampler, mutation):
    data = corpus()
    labels = []
    if mutation == "duplicate":
        data["results"][0]["intentions"].append(data["results"][0]["intentions"][0])
    elif mutation == "foreign":
        labels = [review(100)]
    elif mutation == "invalid_port":
        data["results"][0]["intentions"][0]["port"] = True
    else:
        labels = [review(0, "probably")]
    with pytest.raises(ValueError):
        sampler.select_sample([data], [labels], size=4, seed="seed")


def test_known_labels_and_random_sample_weight_population(sampler):
    selected = select(sampler, count=10, size=4, reviews=[review(0), review(1, "wrong-target")])
    report = sampler.score_sample(
        selected, scored_reviews(selected, ["correct"] * 3 + ["not-a-connection"])
    )
    assert report["overall_precision"]["estimate"] == pytest.approx((1 + 8 * 3 / 4) / 10)
    assert report["overall_precision"]["denominator"] == 10
    assert report["sample_counts"]["incorrect"] == 1
    assert report["reviewer_kind"] == "agent-source"
    assert report["independent_human_review"] is False


def test_unsure_and_missing_reviews_keep_bounds_no_complete_case_estimate(sampler):
    selected = select(sampler, count=10, size=4)
    reviews = scored_reviews(selected, ["correct", "wrong-target", "unsure"])
    report = sampler.score_sample(selected, reviews)
    assert report["overall_precision"]["estimate"] is None
    assert report["overall_precision"]["estimate_bounds"] == [0.25, 0.75]
    assert report["sample_counts"] == {
        "selected": 4,
        "correct": 1,
        "incorrect": 1,
        "unsure": 1,
        "unreviewed": 1,
    }
    assert report["overall_precision"]["confidence_interval_95"][0] <= 0.25
    assert report["overall_precision"]["confidence_interval_95"][1] >= 0.75


def test_census_has_exact_interval(sampler):
    selected = select(sampler, count=3, size=60)
    report = sampler.score_sample(
        selected, scored_reviews(selected, ["correct", "correct", "wrong-target"])
    )
    assert report["overall_precision"]["confidence_interval_95"] == [2 / 3, 2 / 3]


def test_hypergeometric_exact_interval_has_at_least_nominal_coverage(sampler):
    # Exhaust all possible samples, including all-correct/all-wrong endpoints.
    for population in range(1, 14):
        for sample_size in range(1, population + 1):
            for successes in range(population + 1):
                coverage = 0.0
                for observed in range(sample_size + 1):
                    if observed > successes or sample_size - observed > population - successes:
                        continue
                    low, high = sampler.exact_interval(population, sample_size, observed)
                    probability = (
                        math.comb(successes, observed)
                        * math.comb(population - successes, sample_size - observed)
                        / math.comb(population, sample_size)
                    )
                    if low <= successes <= high:
                        coverage += probability
                assert coverage >= 0.95 - 1e-12


def test_census_and_zero_sample_boundaries(sampler):
    assert sampler.exact_interval(10, 0, 0) == (0, 10)
    assert sampler.exact_interval(10, 10, 7) == (7, 7)
    with pytest.raises(ValueError):
        sampler.exact_interval(3, 4, 2)


def test_wrong_selection_duplicate_or_unselected_reviews_refused(sampler):
    selected = select(sampler)
    for mutation in ("wrong_hash", "duplicate", "foreign", "missed"):
        reviews = scored_reviews(selected, ["correct"] * 4)
        if mutation == "wrong_hash":
            reviews["selection_sha256"] = "0" * 64
        elif mutation == "duplicate":
            reviews["reviews"].append(reviews["reviews"][0])
        elif mutation == "foreign":
            reviews["reviews"][0]["host"] = "unselected"
        else:
            reviews["reviews"][0]["label"] = "missed"
        with pytest.raises(ValueError):
            sampler.score_sample(selected, reviews)


def test_cli_pins_raw_input_bytes_and_refuses_overwrite(sampler, tmp_path):
    data = tmp_path / "corpus.json"
    data.write_text(json.dumps(corpus()), encoding="utf-8")
    output = tmp_path / "selection.json"
    args = [
        "select",
        "--input",
        str(data),
        "--seed",
        "preregistered",
        "--size",
        "4",
        "--output",
        str(output),
    ]
    assert sampler.main(args) == 0
    saved = json.loads(output.read_text())
    assert saved["inputs"][0]["sha256"] == sampler.file_sha256(data)
    assert saved["command"][-1] == str(output)
    assert sampler.main(args) == 2


def test_sampling_not_limited_to_front_of_sorted_population(sampler):
    chosen = set()
    for seed in itertools.islice(map(str, range(100)), 40):
        result = sampler.select_sample([corpus(10)], [[]], size=2, seed=seed)
        chosen.update(row["host"] for row in result["sample"])
    assert len(chosen) == 10


@pytest.mark.parametrize("bad", [None, [], {"reviews": [None]}])
def test_malformed_sample_reviews_have_a_clear_error(sampler, bad):
    with pytest.raises(ValueError):
        sampler.score_sample(select(sampler), bad)


def test_malformed_prediction_or_review_rows_have_a_clear_error(sampler):
    for report, labels in [({"results": [None]}, []), (corpus(), [None])]:
        with pytest.raises(ValueError):
            sampler.select_sample([report], [labels], size=3, seed="fixed")
