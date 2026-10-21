# Contributing

Fixtures with clear expected evidence are a useful first contribution. Prefer a
small reproduction from a real failure and cite its source/license. Do not
include production credentials, private names, real logs or sensitive mounts.

## Set up and test

Bash:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev,binary]"
python -m pytest -q
```

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,binary]"
python -m pytest -q
```

Both shells:

```sh
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy --explicit-package-bases --platform linux src/dockroute scripts/benchmark_accuracy.py --check-untyped-defs --ignore-missing-imports
```

The helper runs in Linux containers, so type checks target Linux worker APIs.
Host tests run on Windows, Linux and macOS. Local TCP tests require loopback
access. Tests must never depend on another user's Compose project.

## Submit a fixture

The original `scenarios/` already cover localhost misuse, separate networks,
host-port confusion, loopback-only listeners, a missing hostname and a reachable
control. Extend those with realistic variants rather than treating them as
unimplemented cases. Good first fixture ideas include:

- A real framework's localhost database default, paired with an intentional
  localhost listener control.
- A service binding only to 127.0.0.1, paired with a reachable bind-address fix.
- Two services on different networks with a network-scoped alias.
- `depends_on` without a healthcheck: the dependency is created before it is
  ready, so topology alone should remain `UNKNOWN`.
- Unsupported mounted-config syntax where abstention is the honest expected
  answer.

For the expanded runner, add a unique folder under `scenarios-accuracy/` with
`compose.yaml` and `expected.yaml`. Use the suite's pinned Python image and
minimal services. No bind mounts, volumes, external networks, privileged devices,
sensitive data or production destinations are permitted. Fixed localhost ports
need explicit runner opt-in and must fail visibly on collision.

### Expanded expected.yaml contract

```yaml
scenario: 10-refused-port-variant
ground_truth_fault: a configured port refuses while the actual server port accepts TCP
runtime_kind: wrong_port  # choose an existing observer or add a tested one
source_service: app
destination_service: api
target_host: api
target_port: 8001
root_cause_code: null
expected_behavior: api accepts port 8000 while 8001 explicitly refuses
static_codes: [UNKNOWN]
active_codes: [CONNECTION_REFUSED]
manual_codes: [CONNECTION_REFUSED]
accepted_uncertainty: [UNKNOWN]
required_evidence: [probe]
expected_exit: {static: 2, active: 1, manual: 1}
cleanup: all owned containers, networks, and helpers removed
```

The names and fault description must match the actual fixture. The example
contract describes a refusal control; a delayed-readiness contribution needs an
observer that actually establishes the delay rather than merely renaming this
example. Supported `runtime_kind` values currently are `missing_hostname`,
`wrong_port`, `host_port_confusion`, `http_error`, `source_restart`,
`destination_restart`, `disappearing_source` and `recovery`. HTTP controls add
`http_status`. New behavior kinds require a bounded independent observer and
unit tests in the evaluator; an expected label alone is not ground truth.

- `root_cause_code`: a supported root cause, or null for transport/application
  controls where no specific root cause should be claimed.
- `static_codes`, `active_codes`, `manual_codes`: allowed public diagnosis codes
  for each separate track. Omit manual codes if no manual check is meaningful.
- `accepted_uncertainty`: allowed abstentions, still scored as abstentions.
  `UNKNOWN` must not hide an execution failure or replace a required successful
  HTTP-control TCP check.
- `required_evidence`: evidence/observation kinds needed for a non-UNKNOWN
  finding. Track-specific `static_required_evidence`,
  `active_required_evidence` and `manual_required_evidence` override it.
- `expected_exit`: an integer or list per track. Use the documented CLI exits;
  helper failure state belongs in the probe evidence, not a new diagnosis code.
- `cleanup`: document exactly which owned resources must be gone.

The six original fixtures use a legacy `expected_diagnosis` contract; do not mix
that format with expanded fixtures. Both runners independently validate real
behavior before grading. Supply the command, pinned image, observed behavior,
report and cleanup evidence with a contribution.

```sh
python scripts/benchmark_accuracy.py --scenario YOUR_FOLDER --runs 10 --output outputs/my-fixture.json
```

## Evidence and public compatibility

Diagnostics must separate intention, observation, explanation, confidence and
remediation. Prefer UNKNOWN to an unsupported cause. TCP refusal does not prove
a bind-address issue; TCP success does not prove application readiness.
Destination-side evidence is required for loopback-only listeners.

Every code has [its own reference entry](docs/diagnostics.md). Schema 3.0 is the
current public contract; historical schemas 2.1, 2.0 and 1.0 remain available.
Incompatible code/field/meaning changes require a new schema major version,
migration notes and contract tests. Worker protocol versions are separate.

Keep only the small `benchmarks/baseline.json` report in Git. Retain large reports,
raw fixture output, failed attempts and private originals in CI/release artifacts
or local ignored storage. Never upload raw real-world normalization, environment
files, application logs or access credentials. Follow [release gates](docs/releasing.md).

Static mode stays read-only. Active changes must retain bounded cancellation,
destination scope, helper ownership and cleanup on success/failure/cancellation.
Never use daemon-wide prune or `docker compose down -v`. Do not weaken resource
limits or change scheduling based on a non-interleaved timing comparison.
