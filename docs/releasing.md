# Release gates

A release may be published only when all gates below apply to the exact tagged
commit. Preparing workflow files or running tests on a different revision does
not satisfy them.

1. Package metadata and `dockroute --version` agree. Report schema and diagnostic
   codes have documented compatibility decisions and migration instructions.
2. Unit tests, Ruff, formatting, mypy and package builds pass on supported hosts.
3. Hosted Linux Docker CI runs the original six and expanded synthetic fixtures
   against the exact candidate source; actual behavior, diagnoses and owned
   cleanup are verified. Preserve failures and reruns separately.
4. Reports record exact tool/Engine/Compose versions, source revision/hashes,
   pinned inputs/images, command lines and observed results. A release is not
   evidence for an older dirty working directory.
5. Scan the publication checkout, source distribution, binary archives and
   evidence artifacts for secrets and personal/local paths. Do not upload
   `.env`, raw real-project Compose normalization, logs, private keys, access
   tokens, Docker credentials, local user paths or build caches.
6. Keep only `benchmarks/baseline.json` as the compact in-tree evidence report.
   Upload detailed sanitized historical evidence and fresh regression output as
   CI artifacts/release assets. Retain original private evidence locally; record
   both original and sanitized hashes when redaction changes bytes.
7. A `vX.Y.Z` tag must match the package version and target the verified commit.
   Release publication stays blocked until the hosted Linux job is green.
   A draft release is used for final artifact review.

## Maintainer commands

Bash:

```bash
git push origin HEAD
gh workflow run diagnostic-accuracy.yml --ref YOUR_CANDIDATE_BRANCH -f runs=10
gh run list --workflow diagnostic-accuracy.yml
# Inspect the successful exact-commit run and download its artifacts first.
git tag -a v0.4.0 -m "DockRoute 0.4.0"
git push origin v0.4.0
```

PowerShell:

```powershell
git push origin HEAD
gh workflow run diagnostic-accuracy.yml --ref YOUR_CANDIDATE_BRANCH -f runs=10
gh run list --workflow diagnostic-accuracy.yml
# Inspect the successful exact-commit run and download its artifacts first.
git tag -a v0.4.0 -m 'DockRoute 0.4.0'
git push origin v0.4.0
```

The release workflow builds native binaries and creates a draft GitHub release.
Attach the Linux regression evidence bundle to that draft; review it before
publishing. Real-repository baseline evidence remains labeled with the version
actually measured. No new blind accuracy claim follows from a synthetic pass.
