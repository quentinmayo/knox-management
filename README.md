# Knox management

**Keys under control.**

An optional, standalone management console and CLI for [Pinterest Knox](https://github.com/pinterest/knox). Browse key IDs, inspect metadata and ACLs, create keys, add versions, promote or deactivate versions, and apply access rules. Existing secret values are never returned to the browser or CLI.

This is the companion to [StepDownproxy](https://github.com/quentinmayo/StepDownproxy). The proxy can use Knox without installing this platform. This platform can manage Knox without running the proxy. Both are MIT-licensed and self-hosted.

## Try a local demo

Requires Docker Compose and Python 3.

```sh
git clone https://github.com/quentinmayo/knox-management.git
cd knox-management
python3 scripts/init-demo.py
docker compose -f compose.demo.yaml up --build -d
python3 scripts/smoke.py
```

Open `http://127.0.0.1:19100` and sign in using `KNOX_MANAGEMENT_TOKEN` from the generated, ignored `.env` file. The demo wraps the real Pinterest Knox router and encrypted in-memory database with a fake local authentication provider. It uses generated demonstration credentials, has no real GitHub account connection, and loses its keys when the Knox container stops. Use it only for fake secrets.

```sh
docker compose -f compose.demo.yaml down
```

## Connect your Knox deployment

Start from [examples/config.json](examples/config.json). Configure the Knox origin, authorization reference, custom CA, and client certificate if your Knox provider requires one. The console credential and Knox backend credential must be different.

```json
{
  "listen": "127.0.0.1:19100",
  "admin_token_env": "KNOX_MANAGEMENT_TOKEN",
  "knox": {
    "url": "https://knox.internal.example",
    "auth_file": "/run/secrets/knox-auth",
    "ca_file": "/run/certs/knox-ca.pem",
    "cert_file": "/run/certs/client.pem",
    "key_file": "/run/certs/client.key"
  }
}
```

Use exactly one `admin_token_env`/`admin_token_file` and one Knox `auth_env`/`auth_file`. Console tokens need at least 32 random bytes. Knox authorization references contain the complete Knox authorization string: the provider prefix is preserved, including `0u`, `0m`, or `0t` where appropriate. Knox mTLS also requires the certificate and key. TLS server verification is always enabled; `allow_http: true` is an explicit local-development opt-in.

The console is a **single-operator tool**. Anyone holding its admin token can perform operations available to its configured Knox backend principal. It does not give each browser user a separate Knox identity. Knox enforces its own Read/Write/Admin ACLs on every request. Use a dedicated backend principal with only the privileges required.

Run from source with Go 1.27+:

```sh
go build -o bin/knox-management ./cmd/knox-management
bin/knox-management -config /path/to/config.json serve
```

Use `-tls-cert` and `-tls-key` for console HTTPS, or place it behind a private TLS reverse proxy. Keep cleartext listeners on loopback or an isolated trusted network.

For Docker with an existing Knox server, create `.local/config.json` from the example, set its listen address to `:19100`, and mount secret files under `.secrets` and certificates under `.local/certs`. Files must be readable by UID/GID 65532 in the non-root container. Keep private-key permissions restrictive. Then run `docker compose up --build -d` with `KNOX_MANAGEMENT_TOKEN` set. Both local directories and `.env` are ignored by Git and excluded from the build context.

## CLI

Global flags precede the command. Values for create/add-version come from stdin; ACLs come from JSON on stdin. No command displays existing secret data.

```sh
bin/knox-management -config config.json list
bin/knox-management -config config.json inspect stepdown:github:token
bin/knox-management -config config.json create stepdown:github:token < /secure/new-token
bin/knox-management -config config.json add-version stepdown:github:token < /secure/next-token
bin/knox-management -config config.json set-status stepdown:github:token VERSION_ID Primary
bin/knox-management -config config.json set-acl stepdown:github:token < access.json
```

An access file is an array of entries:

```json
[{"type":"Machine","id":"proxy.internal.example","access":"Read"}]
```

Knox merges matching ACL entries. Set `access` to `None` to revoke a grant. Removing an entry from a submitted array does not revoke an existing grant. Retain an Admin grant when editing access. Key deletion is deliberately absent from this initial tool.

## Rotation

1. Add a new version; Knox creates it as Active.
2. Verify that the upstream API accepts the new credential.
3. Promote that version to Primary. Knox makes the previous Primary Active.
4. StepDownproxy fetches the current Primary after each approved request, so subsequent calls use the new value without restarting the proxy.
5. Revoke the old credential at its provider and deactivate its Knox version when appropriate.

Knox state changes do not revoke credentials at GitHub or other providers. Mutations are not automatically retried; inspect state after a network failure with an unknown outcome.

Knox version IDs are 64-bit values. The console/API serializes version IDs as decimal strings to preserve them across JavaScript. Never convert them to floating-point numbers.

## Management API

All API calls require `Authorization: Bearer <management-token>`. The console uses explicit authorization headers, no cookies or browser credential persistence, same-origin checks, a restrictive CSP, and local static assets.

`POST /api/command` accepts one of:

| Operation | Fields |
| --- | --- |
| `list` | None |
| `inspect` | `key_id` |
| `create` | `key_id`, write-only `value`, optional `acl` |
| `add-version` | `key_id`, write-only `value` |
| `set-status` | `key_id`, decimal-string `version_id`, `status`: Primary/Active/Inactive |
| `set-acl` | `key_id`, `acl` entries to merge |

`GET /api/activity` returns the last 100 operation names, timestamps, and success flags. No key values, submitted bodies, credentials, or raw backend errors are logged. History is in memory; use Knox's own audit facilities for backend records. Knox's list endpoint exposes global key IDs; inspect still requires Read access. Metadata inspection retrieves a key from Knox on the server and strips version data before responding.

## Validation and development

```sh
go test -race -cover ./...
go vet ./...
```

The nested `integration` module pins the real Knox source. Clone StepDownproxy beside this repository, then:

```sh
cd ../StepDownproxy
go build -o /tmp/stepdownproxy ./cmd/stepdownproxy
cd ../knox-management/integration
STEPDOWN_PROXY_BINARY=/tmp/stepdownproxy GOWORK=off go test -race -v ./...
```

The suite checks key creation, metadata redaction, read-only ACLs, Active-to-Primary promotion, revocation, verified TLS, and live proxy credential rotation. The test authenticator is fake; Knox's routing, storage encryption, ACLs, and version behavior are real. It does not validate your production identity provider. CI also performs secret and dependency vulnerability scans. See [validation](docs/VALIDATION.md).

This initial release has no SSO, per-user administrative RBAC, approvals, durable platform audit sink, key deletion, or automated backend login/lease renewal. It is not independently audited. Report sensitive issues using [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Independent of Pinterest; not an official Pinterest Knox interface. The pinned Knox code used by the demo/integration harness retains its own Apache-2.0 license. The production platform uses the small standard-library Knox client from StepDownproxy.
