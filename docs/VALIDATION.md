# Initial validation — October 12, 2026

Validated locally with Go 1.27.2 in Docker. Tests used generated fake credentials and no production secret store.

- Race tests and `go vet`: passed for the management server and shared Knox client.
- Real Knox integration: passed against pinned Pinterest Knox commit `61dd58235016fe07c1a63aa8afda1be3e00fbea9`. The harness used Knox's actual router, encrypted in-memory database, ACL enforcement, and version transitions with an isolated test authentication provider and verified TLS.
- Lifecycle tests: key creation, metadata redaction, separate ACL retrieval, read-only write denial, Active-to-Primary rotation, ACL revocation, and live StepDownproxy credential refresh passed.
- Docker demo smoke: create/list/inspect, lossless 64-bit IDs, version promotion, access-rule updates, and console/backend credential separation passed.
- Packaged CLI smoke: stdin provisioning, create/list/inspect, version promotion, and ACL updates passed against the real Knox demo.
- Browser checks: login, create, inspect, add version, promote, update ACL, and responsive layouts passed. Existing secret values were excluded from displayed metadata.
- `govulncheck`: no vulnerabilities found in the checked integration dependency graph.
- Publication checks: local environment files, credentials, certificates, binaries, and screenshots excluded; Git history scanned with Gitleaks before push.

The production platform and demo backend have separate Docker images. The demo backend uses fake authentication and volatile storage and is only for generated test data. These tests do not validate a production identity provider, external GitHub tokens, or the host's deployment controls. This initial release has not had an independent security audit.
