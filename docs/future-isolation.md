# Deferred fix-and-verify extension

The initial release provides remediation prose only. It does not generate or apply patches and does not verify user projects in scratch environments.

A future extension may produce a patch for human review and then verify it only after demonstrating isolation. Compose must be fully resolved, all resources enumerated, and each shared resource rejected or explicitly replaced with a fresh test-owned resource. External networks, named volumes, sensitive bind mounts, secrets/config files, fixed host ports, fixed names, devices, privileged/shared namespaces, production endpoints, build hooks and lifecycle hooks must fail closed. Network egress to production must be blocked at the test environment boundary; rewriting a URL is not proof of isolation. Read-only mounts can still disclose secrets and are not sufficient safeguards.

The verifier must use unique project/resource identities, record ownership before creation, support cancellation, compare baseline and patched outcomes with independent observations, and clean only its own resources. It must refuse verification when isolation cannot be demonstrated. The synthetic benchmark runner's resource checks are specific to its supplied fixtures and are not a general production-cloning verifier.
