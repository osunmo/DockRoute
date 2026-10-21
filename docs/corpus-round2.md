# Second corpus evaluation protocol

This round extends the first pinned evaluation after URI parsing, bounded log
evidence, and mounted-configuration extractors are implemented. Those changes are
developed against synthetic fixtures and the original 16 repositories. New source
content remains hidden from the implementation agents until the product and the
files-only evaluator are frozen. The second round uses 12 new repositories;
repository selection is deliberate, not a random sample of all Compose users.

## Registration and separation

1. A custodian records the 12 canonical repository URLs, exact commit IDs and one
   Compose configuration per repository using only repository and filename
   metadata. The immutable selection includes failures; a difficult repository is
   never silently replaced. No file blobs are read before the implementation
   freeze. Metadata request attempts and their hashes remain recorded.
2. Freeze every production module and evaluator file by SHA-256, Git revision,
   tool version, exact evaluation command and UTC timestamp. Changes after the
   freeze invalidate blind status for a rerun; retain the first run unchanged.
3. After release, the custodian inspects pinned configuration and source consumers
   and freezes a source-derived endpoint oracle before viewing predictions. Record
   each label's file, line, hash and reasoning. Label coverage is explicitly
   partial whenever application defaults, mounted files or other consumers have
   not been completely inspected. Agent/source review is not independent human
   validation.
4. Normalize using Docker Compose with explicit inert sample environment inputs,
   not the operator's ambient secrets. Record the exact command, version, elapsed
   time, exit status and hashes of private raw stdout/stderr. Never publish raw
   normalized configuration or raw secret-bearing logs.
5. Evaluate and retain every selected case. Count parse failures, crashes, missing
   files, unavailable tooling, unsupported syntax and unresolved interpolation.
   A later successful retry does not erase its predecessor. Report endpoint
   precision and source-oracle recall with their numerators and denominators;
   failed files remain in file-level failure rates.

The preregistered expectation for a **working live** configuration is zero problem
findings. `UNKNOWN` is an abstention, and dependency-only intentions do not count as
discovered network endpoints. Files-only discovery produces no runtime diagnosis;
it cannot establish the false-positive finding rate of a working application.

## Random review of existing unreviewed predictions

The primary population is every unique port-bearing endpoint in the final frozen
rerun of the original development and first held-out repositories. This is a
post-tuning finite population. Existing correct/incorrect reviews form one fully
reviewed stratum. All remaining endpoint predictions form a single sampling
stratum, including external or ambiguous predictions. Dependency-only records are
excluded and counted. The selected sample is **60**, or the entire remaining
population if smaller, without replacement using this preregistered seed:

```text
dockroute-2026-10-14-round2-v1
```

Do not choose the sample until the product is frozen and those prediction reports
exist. Run the selector once and preserve its raw input hashes, canonical
population hash, selected endpoints, seed, Python version and exact command
before reviewing any selected row. Existing reviews may be transferred to a
rerun only where the endpoint and source evidence remain applicable; retained,
removed and newly discovered endpoints must be accounted for.

```sh
python scripts/sample_corpus_predictions.py select   --input outputs/round2/development.json --labels outputs/round2/development-reviews.json   --input outputs/round2/previous-holdout.json --labels outputs/round2/previous-holdout-reviews.json   --size 60 --seed dockroute-2026-10-14-round2-v1   --output outputs/round2/random-selection.json

python scripts/sample_corpus_predictions.py score   --selection outputs/round2/random-selection.json   --reviews outputs/round2/random-reviews.json   --output outputs/round2/random-precision.json
```

The review document contains `selection_sha256`, `reviewer_kind` (`agent-source`,
`human` or `mixed`) and `reviews`. Each review has `case_id`, `source`, `host`,
`port`, `label` and `evidence`. Labels are `correct`, `wrong-target`,
`not-a-connection`, `unsure` or `unreviewed`. Evidence should reference pinned
source locations and explain actual endpoint consumption. Never substitute an
easier row for an unsure row. The score does not assert independent human review
merely because a review document says `human`.

If C known reviewed endpoints are correct, U endpoints were previously unreviewed,
N is the entire endpoint population, and x of n randomly sampled endpoints are
correct, estimated precision is `(C + U*x/n) / N`. The script inverts the exact
hypergeometric tails for the unknown total correct count K in the U stratum:
retain K where both `P_K(X <= x)` and `P_K(X >= x)` are at least 0.025. It transforms
the retained K range to `(C+K)/N`. This finite-population interval accounts for
sampling without replacement and collapses to the observed fraction on a census.
It is conservative because K and X are integers.

If any sampled rows remain unsure or unreviewed, publish estimate bounds and the
union of confidence intervals over all possible labels for those rows; do not
compute a biased complete-case point estimate. Publish deterministic logical
bounds as well. The 95% interval measures sampling uncertainty conditional on the
labels being correct. It does not measure reviewer mistakes or performance on
unseen repositories, and it is not a recall estimate.

## Linux live execution

Use a dedicated Linux CI job with immutable prebuilt image digests. Build/pull
images in a separate preparation phase, record its failures separately, and
exclude it from the diagnostic runtime measurement. Preserve each service's
original application/configuration; do not repair upstream projects silently to
make the benchmark pass. Run only the allowlisted small-stack recipes with fresh
project names, isolated networks and volumes, dynamic loopback ports, bounded
readiness/probe deadlines, and the existing ownership-checked cleanup.

Collect per-file and per-command wall time, success/failure, raw redacted reports,
Docker/Compose/DockRoute versions, image IDs/digests and source hashes. Report
startup/build failure and diagnostic failure separately. A CI workflow that has
not actually run is execution support, not evidence of Linux results. Do not
reinterpret all earlier Windows failures as environmental without their recorded
failure evidence.
