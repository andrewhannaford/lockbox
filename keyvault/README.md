# KeyVault

A minimal self-hosted secret store for backing up your own keys (e.g. Lockbox key
files, API tokens, recovery codes). Secrets are encrypted at rest with AES-256-GCM
using a `MASTER_KEY` you set, and every request requires a Bearer token.

This is for **your own keys** — there is no key exfiltration, no telemetry, no
logging of secrets, and it does not reach out to any machine.

## Run

```bash
# generate two secrets
openssl rand -hex 32   # MASTER_KEY (encryption-at-rest key)
openssl rand -hex 32   # API_KEY     (shared with the Lockbox .exe)

# put them in docker-compose.yml, then:
docker compose up -d --build
```

The service listens on `127.0.0.1:8080`. Keep it bound to localhost (or put it
behind your Traefik with auth) so it's not directly exposed.

## Endpoints

`POST /keys` requires this header (enforced by the service); `GET`/`DELETE` are
protected by the reverse proxy (Pocket ID / OIDC):

```
Authorization: Bearer <API_KEY>
```

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/health` | — | health check |
| POST | `/keys` | `{"name":"...","value":"...","host":"..."}` | store a secret (needs Bearer `API_KEY`) |
| GET | `/keys` | — | list stored names and hosts |
| GET | `/keys/<name>` | — | retrieve a secret and its host |
| DELETE | `/keys/<name>` | — | delete a secret |

Lockbox sends its hostname as `host`, so the Keys page labels which machine each
key belongs to. The same `API_KEY` is baked into the executable at build time via
`build_exe.py`.

Names must match `[A-Za-z0-9._-]{1,128}`.

## Example

```bash
# store a Lockbox key file's contents
curl -X POST http://localhost:8080/keys \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"lockbox-master","value":"'"$(base64 -w0 mykey.bin)"'"}'

# list
curl http://localhost:8080/keys -H "Authorization: Bearer $API_KEY"

# retrieve
curl http://localhost:8080/keys/lockbox-master -H "Authorization: Bearer $API_KEY"
```

## Important

- **Two secrets to protect:** the `MASTER_KEY` (decrypts everything at rest) and
  the `API_KEY` (grants access). Back them up somewhere separate and trusted.
- Losing `MASTER_KEY` means the stored secrets are unrecoverable — by design.
- Data lives in the `keyvault-data` Docker volume. Back up that volume too.
