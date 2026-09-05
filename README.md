# sealbox-keeper

A small key service for [sealbox](https://github.com/Vebat/sealbox). It speaks the Vault transit protocol,
so sealbox points at it with `SEALBOX_KMS=transit` and never holds a master key again.

> **Status: pre-alpha, not audited.** This process becomes the root of trust for every object in sealbox.
> Do not run it anywhere you would not run a KMS.

## Why

With a local master key, whoever controls the sealbox process holds every key. keeper moves the master key
into a separate process on a separate host with a tiny API: wrap a key, unwrap a key, nothing else.
A compromised sealbox can then only unwrap keys while it is compromised, one call at a time, rate-limited,
each call written to a log that host cannot rewrite, and cut off by deleting one token.

That is what a KMS gives you. keeper is the smallest thing that gives it: one binary, no database, no
dependencies beyond `golang.org/x`. If you already run Vault, OpenBao or a cloud KMS, use that instead;
sealbox speaks to them the same way.

## Protocol

The transit subset sealbox uses, with the same request and response shapes:

```http
POST /v1/transit/encrypt/{key}   { "plaintext": base64, "context": base64 }
-> { "data": { "ciphertext": "keeper:<version>:<base64>", "key_id": "<version>" } }

POST /v1/transit/decrypt/{key}   { "ciphertext": "...", "context": base64 }
-> { "data": { "plaintext": base64 } }

POST /v1/transit/rewrap/{key}    { "ciphertext": "...", "context": base64 }
-> { "data": { "ciphertext": "...", "key_id": "<version>" } }
```

Authentication is the `X-Vault-Token` header. Errors are `{ "errors": ["..."] }`: 400 for a ciphertext that does
not open, 403 for a bad token or a key the client may not use, 429 for the rate limit.

Every key name is valid: keys are derived from the master key with HKDF, one per name, so `sealbox` and
`sealbox-staging` never share key material. The context is always bound, like a transit key created with
`derived=true`: a ciphertext made for one sealbox row does not open for another.

## Run it

```sh
printf 'KEEPER_MASTER_KEY=%s\nKEEPER_TOKEN=%s\n' "$(openssl rand -base64 32)" "$(openssl rand -base64 32)" > .env
docker compose up --build
```

Then point sealbox at it:

```sh
SEALBOX_KMS=transit
SEALBOX_TRANSIT_ADDR=http://localhost:8200
SEALBOX_TRANSIT_KEY=sealbox
SEALBOX_TRANSIT_TOKEN=<the KEEPER_TOKEN above>
```

An existing sealbox database moves over by rotation: keep `SEALBOX_MASTER_KEY` configured, add the four
variables above, restart, run `sealbox rotate`, then drop the master key. See the sealbox README.

## Configuration

| Variable | Meaning |
|---|---|
| `KEEPER_MASTER_KEY` or `KEEPER_MASTER_KEY_FILE` | master key versions, base64, current first, one per line or comma-separated; exactly one source |
| `KEEPER_CLIENTS_FILE` | named clients with tokens, allowed key names and rate limits, see [clients.example.json](clients.example.json) |
| `KEEPER_TOKEN` | one extra token allowed every key, for development only |
| `KEEPER_ADDR` | listen address, default `:8200` |
| `KEEPER_TLS_CERT`, `KEEPER_TLS_KEY` | PEM certificate and key; without them keeper listens on loopback only |
| `KEEPER_TLS_CLIENT_CA` | PEM CA bundle; when set, clients must present a certificate it signed |
| `KEEPER_INSECURE_HTTP` | `1` allows plaintext HTTP on a non-loopback address |

Per client, `decrypt_per_second` caps decrypt and rewrap, the calls that hand out key material. The default is
200 with a burst of 1000, enough for a sealbox batch reveal. Encrypt is never limited: it hands out nothing.

## Deploying it for real

keeper is only worth running if it lives in a different trust domain than sealbox. The minimum:

- Its own host or VM, its own network segment, its own administrators.
- TLS 1.3 with `KEEPER_TLS_CLIENT_CA`, so only sealbox's certificate is accepted at all.
- The master key from a file that only this process can read, ideally one sealed to the machine by a TPM or
  delivered by a secret store, never from the environment.
- stdout shipped off the host. Every call is one JSON line: client, operation, key name, status. Never material.
- On Linux keeper disables core dumps and marks itself non-dumpable at start. Run it as an unprivileged user
  on a read-only filesystem, and do not let anything else run on the box.

## Master key rotation

Put the new key first in `KEEPER_MASTER_KEY_FILE` and keep the old one after it, then restart. New
ciphertexts name the new version; old ones still open. Retiring the old version needs every ciphertext that
names it to be re-wrapped through `/v1/transit/rewrap`. sealbox does not call rewrap yet, so for now keep old
versions loaded, or rotate sealbox's own keys instead. Teaching `sealbox rotate` to rewrap through transit is
the next step on both sides.

## Threat model

Protects against: a compromised sealbox host walking away with the master key; bulk exfiltration faster than
the rate limit; a stolen token being used quietly, because every call is logged and the token is revocable.

Does not protect against: a compromised keeper host, which holds the master key in memory; a stolen token used
slowly and within the rate limit, until the log is read; loss of the master key, which loses everything wrapped
under it. Back the key up outside this host and test the restore.

## License

Apache-2.0. See [LICENSE](LICENSE).
