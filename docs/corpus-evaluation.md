# Real-repository evaluation

The historical blind evaluation measured **42/47 reviewed precision (89.4%)**
and **42/61 partial-oracle recall (68.9%)** across five pinned repositories.
Development recall was **88/148 (59.5%)** across 25 Compose configurations.
Automatic root-cause recall on four validated faults injected into real projects
was **1/4 static and 2/4 active**.

These measurements used DockRoute 0.3.0. They must not be relabeled as 0.4
or 0.4.1 results. Version 0.4.1 includes preflight reachability probing,
Windows named pipe support, parser improvements, and evidence-source changes,
but no new blind accuracy result. [baseline.json](../benchmarks/baseline.json) retains
the small, versioned baseline and hashes of its original summary records.

Third-party replay: not yet done.

## Known limitations and interpretation

Reviews were performed by source-reviewing agents, with no independent human
validation. Oracles cover a partial outgoing-connection subset. Twelve blind
predictions and 160 development predictions were unreviewed. Reviewed precision
does not establish precision for those predictions; recall is conditional on the
authored subset, not the complete graph.

The 19 known blind misses included eight driver-qualified database URIs, seven
mounted Envoy endpoints, three image/application defaults and one mounted
Prometheus endpoint. The current implementation addresses supported driver
qualifiers and bounded Nginx/Prometheus/Envoy formats; this has not established a
new recall figure. Unknown formats, dynamic templating, remote configs, image
defaults and arbitrary command languages can still hide connections.

No HTTP readiness, protocol/authentication or TLS test is performed. A successful
TCP connection can coexist with HTTP 500/503. Discovery is an inferred intention,
not observed application traffic. Later changes informed by the original holdout
are tuned regressions, not another blind evaluation.

## Method

Repositories and Compose inputs are pinned by commit and file hash. Compose
normalization handles interpolation, anchors, env files and includes; unresolved
fields, parse failures, missing files and crashes remain recorded. Files-only
evaluation starts no application containers and makes no connectivity diagnosis.

Precision is correct / (correct + wrong target + not a connection), restricted to
reviewed endpoint predictions. Recall is correct / (correct + wrong target +
missed) within the frozen oracle. Portless dependencies and unreviewed predictions
are counted separately. A manual check never earns automatic-discovery credit.

The five original live attempts produced two validated working applications,
two startup/readiness failures and one refused build. Working-project
false-positive rates therefore had a denominator of two. Four real-project
injected faults had independently validated failing behavior; the retained
root-cause recall is 1/4 static and 2/4 active.

## Reproduce and contribute evidence

Use the pinned repository lock, oracle, reviews and evaluator commands in the
release evidence asset. Detailed records are distributed as CI artifacts or
release assets, rather than committed into this repository. Until a historical
asset is published and linked from a release, its detailed evidence is not
publicly reproducible; this is a release gate, not a passing result.

Both Bash and PowerShell accept these single-line commands:

```sh
python scripts/prepare_corpus.py --help
python scripts/evaluate_corpus.py --help
python scripts/report_corpus.py --help
python scripts/run_corpus_faults.py --help
```

Follow [the second-round protocol](corpus-round2.md) to freeze new repositories
before implementation, retain all failures, sample unreviewed predictions, and
keep blind and tuned results distinct. See [release gates](releasing.md) for
artifact privacy and source/version requirements.
