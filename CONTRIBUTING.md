# Contributing

Run `gofmt`, race tests, `go vet`, the real Knox integration suite, and the Docker demo smoke test. Add meaningful tests for version transitions, backend failures, authentication, and redaction when changing those boundaries. Keep existing secret values out of browser and CLI output.

Use decimal strings for 64-bit version IDs in JSON crossing the browser boundary. Match Knox's actual form-encoded v0 protocol and ACL-merge semantics. Never retry mutations automatically. Keep the companion usable without a running StepDownproxy instance.

Do not commit `.env`, `.secrets`, `.local`, private keys, real tokens, or host configuration. Runtime test credentials should be generated. Sensitive reports belong in the private reporting flow described in SECURITY.md.
