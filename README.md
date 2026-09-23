# libID-server-rs

The OAuth Bridge of a libID ceremony.

A platform ceremony runs in the browser: it opens the provider, consumes the
redirect against its own live state, exchanges the code where its ceremony
takes a token, notarizes what it needs, and builds the proof. This service
publishes the configuration an application starts from and serves the one
callback document the providers redirect back to. It performs no token
exchange and opens no notary connection. GitHub's exchange, which GitHub
answers only with the App's `client_secret`, runs in the browser too; the
bridge publishes that value as public application configuration.

It keeps no ceremony state, no session, no challenge and no result. A timeout,
a duplicate request, a restart or a lost response leave no record here, and
recovery is a fresh ceremony rather than a lookup. It holds no wallet, pays no
gas, keeps no database, and talks to no chain.

## How a claim works

1. The application reads `GET /api/v1/ceremony/config` from an admitted
   origin: the CCDP Distribution to load and, per enabled platform, the public
   client id, the ceremony versions and, for GitHub, the public
   `clientCredential`. It derives the redirect URI itself from the
   bridge origin it already knows: `{bridgeOrigin}/auth/callback`.
2. The browser derives its PKCE verifier, opens the provider's authorization
   page, and is redirected to `GET /auth/callback` on this bridge: one
   document, the same bytes for every request, written by the Distribution.
   The handler reads nothing from the request; the code in the query never
   reaches this process.
3. Everything after that runs in the browser on the Distribution's code: the
   token exchange, the notarized sessions, the proof. GitHub's token request
   carries the published credential as `client_secret` and is revealed whole.
   This service sees none of it and verifies nothing.

## Trust model

**The notary is the only trust root.** This service signs nothing and holds
no key and no secret: the single signature in a proof is the notary's.

GitHub's `client_secret` is published on purpose. GitHub requires it in every
token request, PKCE or not, so a browser client has to carry it; libID treats
it as public application configuration, and the GitHub ceremony's proof
statement covers the complete revealed token request, the credential
included. It identifies the App, not a user, and the ledger accepts nothing
the notary did not attest.

The configured origin and everything it serves are a code-supply-chain
boundary besides. A malicious server can replace the browser code it hands
out; origin checks and a closed input surface cannot constrain its owner.


## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness probe. Returns `OK`, whether or not a callback document is available. Not one of the contract's routes — see below. |
| `GET` | `/metrics` | What this deployment counts, in the Prometheus text exposition format. Not one of the contract's routes. |
| `GET`, `OPTIONS` | `/api/v1/ceremony/config` | The public ceremony configuration: `{ ccdpOrigin, platforms }`. Readable from an admitted origin, or by a same-origin `GET` without `Origin` on `Sec-Fetch-Site: same-origin`. `403` for any other origin, `400` for a query. `OPTIONS` answers the preflight a caller sending its own header needs, by the same admission rule: `GET`, the headers asked for, no credentials. |
| `GET` | `/auth/callback` | The registered OAuth callback document: the CCDP Distribution's artifact with this deployment's data inserted, identical for every request. |

`/health` is not one of the contract's two routes. The published image's
`HEALTHCHECK` targets it; it reads nothing from the request and answers two
bytes. The configuration route is the one that refuses a query; the callback
takes the provider's and ignores it.

Any other path, `POST /api/v1/ceremony/github-token` included, is answered
`404` with no CORS header.

### `GET /api/v1/ceremony/config`

```json
{
  "ccdpOrigin": "https://lib.id",
  "platforms": {
    "github": {
      "clientId": "Iv1.0123456789abcdef",
      "ceremonyVersions": [1],
      "clientCredential": "…"
    },
    "x": {
      "clientId": "…",
      "ceremonyVersions": [1]
    }
  }
}
```

`clientCredential` is present on exactly the entries whose ceremony
sends one: GitHub's. It is nonempty printable ASCII without whitespace,
checked at startup. The record carries no redirect URI, no allowlist, no
notary setting and no user token.

## The CCDP Distribution

The contract this server implements is `specs/oauth-bridge.md` in the libid
repository (pull request 13); the GitHub profile whose token request carries
the public credential is `specs/platform-ceremonies.md` (pull request 35).

This server is the **OAuth Bridge**, and only that. Everything the browser
executes — the Callback implementation, the prover, the circuits and
notarization client — is served by a separate static **CCDP Distribution** at
`CCDP_ORIGIN`, which may be cross-site and knows nothing about this bridge. The
bridge publishes configuration and serves one callback document. It serves no
CCDP resource and no proving asset.

### The callback document

The bridge does not write it. The Distribution builds one self-contained
artifact at `/ccdp/callback.html` carrying every supported Callback
implementation, with one non-executable slot for deployment data. The bridge
reads that artifact, substitutes **one unversioned list** —
`[allowedOrigins, ccdpOrigin]` — the effective admission set, which is
`ALLOWED_APP_ORIGINS` plus the resolved CCDP origin, and that origin —
in place of the marker, composes the response policy, and publishes the pair.
It does not parse the document: the marker occurs once or the artifact is
refused, and everything around it is served as it arrived. It parses no OAuth
`state`, selects no CCDP version, and holds no version list: a compatible
Callback change needs no bridge rebuild.

`allowedOrigins` is an array of strings, every member spelled as it was
written and an origin pattern among them where one is configured. It carries
`ccdpOrigin` itself, literally, whatever else the allowlist covers.

The policy's `script-src` carries **only the hashes the artifact was served
with**. The Distribution publishes the hashes of the code it ships; this bridge
checks that its `script-src` names hash sources and nothing else, then carries
them into the policy it writes. Those hashes are the only script sources the
served document has, so code they do not cover does not run whoever wrote it.
Substitution cannot invalidate one: the data is escaped to ASCII with no
character a parser reads as markup, and the marker occurs once.

The document never varies: no request field —
`Origin`, `Referer`, query, fragment — changes a byte of it or its policy. The
server never sees the provider's return: the handler reads nothing from the
request, and there is no request-logging middleware. **Any proxy in front of
this server must redact the callback path's query string from its access
logs** — that half of the contract is the operator's.

The artifact is **retrieved from the Distribution**: `{CCDP_ORIGIN}/ccdp/callback.html`,
first as soon as the process runs and then every five minutes, conditionally on
the `ETag` it came with. A retrieval that returns `304`, fails to reach the
Distribution, or returns something this bridge will not serve leaves the document
already being served as it is; only a valid replacement replaces it, and the
document and the policy naming its hashes are published as one value. Redirects
are refused, and the request carries no cookie, credential, query, or anything
derived from a callback request.

**The Distribution's availability is not this deployment's.** The process starts
without it, binds, and serves the configuration, the liveness probe and the
metrics. Until a retrieval produces a document the callback path answers `503`
with an inert page naming the last failure, and a failed retry backs off from
one second to five minutes, doubling. Once a document is published it keeps being
served through any later failure. A development stack serves its own
Distribution over HTTP on `localhost` or `127.0.0.1`, the one plaintext
exception the origin rules make.

## What this deployment counts

`GET /metrics` answers the Prometheus text exposition format. It is scraped
from the pod and is not part of the ceremony contract.

| Metric | What it says |
|---|---|
| `libid_bridge_artifact_retrievals_total{outcome}` | Retrievals, by `published`, `unchanged` or `failed` |
| `libid_bridge_artifact_retrieval_failures_total{kind}` | Failed retrievals, by which refusal |
| `libid_bridge_callback_requests_total{outcome}` | Callback requests, by `document` or `unavailable` |
| `libid_bridge_callback_document_available` | `1` while a document is available |
| `libid_bridge_callback_document_published_timestamp_seconds` | When the served document was published |

A deployment serving a document it can no longer replace shows a rising
`failed` count with `callback_document_available` still `1`, and its published
timestamp stops moving.

## What the operator has to supply

One thing this server does not do.

**Redact the callback query from proxy access logs.** The handler reads
nothing from the request, so the authorization code never reaches this
process — but a proxy that logs request lines by default writes it to disk
before this server sees the request at all.

## Configuration

The bridge reads a TOML configuration file named by `LIBID_CONFIG` or
`--config`. It is the deployment: nothing in it has a flag or a variable of
its own, because the enabled platforms can be written nowhere else and a
bridge with no platform could serve no ceremony. There is one place to look
and nothing to disagree with it. `bridge.toml.example` beside this README is a
complete starting point:

```toml
allowed_app_origins = ["https://app.example", "https://wallet.example"]
# A member may also be an origin pattern, where the Distribution's Callback
# understands one: allowed_app_origins = ["https://*.handles.link"]

[[platforms]]
id                        = "github"
client_id                 = "Iv1.0123456789abcdef"
versions                  = [1]
client_credential = "…"
```

An unknown key is refused at startup, `host` and `port` among them: where the
process listens is set with `HOST`/`PORT` or `--host`/`--port`. The platforms
are set only in the file,
one `[[platforms]]` table per enabled platform: its `id` (`github`, `google` or
`x`), its public `client_id`, the ceremony `versions` it advertises and, for
`github`, the App's client secret as `client_credential`, which the
bridge publishes. There is no notary setting and no environment variable for
the credential.

| Key | Environment | Default | Meaning |
|---|---|---|---|
| — | `HOST`, `--host` | `127.0.0.1` | Bind address (`0.0.0.0` in the container image). Not a file key: the image sets it in the environment, which beats a file. |
| — | `PORT`, `--port` | `8722` | Bind port. Not a file key, for the same reason. |
| `allowed_app_origins` | — | *(required)* | The application allowlist. A member is an exact origin — HTTPS, or HTTP on `localhost` or `127.0.0.1`, and already canonical, so a trailing slash, an uppercase host or a default port is refused with the canonical spelling named rather than folded — or an **origin pattern**, `https://*.<suffix>`, described below. A repeated spelling is refused; a pattern and an origin it covers are two members. The **effective** admission set is this list plus the resolved `CCDP_ORIGIN`, added exactly once and by its literal spelling. It is the one admission rule: the configuration route admits exactly one `Origin` that a member admits, and echoes that origin itself; the callback document is told the same set. A same-origin read carries no `Origin` and is admitted on `Sec-Fetch-Site: same-origin` alone. |
| `ccdp_origin` | — | `https://lib.id` | The CCDP Distribution this bridge selects: one origin serving `/ccdp/callback.html` and everything the browser runs after it, HTTPS, or HTTP on `localhost` or `127.0.0.1`. Published in the configuration and inserted into the callback document, and named as the one `frame-src` source of its policy, so a host a policy source expression cannot name, an IPv6 literal or an underscore among them, is refused. Omitting it selects the canonical libID Distribution. |
| `platforms` | — | *(required)* | The enabled platforms, as `[[platforms]]` tables: `id`, `client_id`, `versions`, and for `github` its `client_credential`. |
| — | `LIBID_CONFIG`, `--config` | *(none)* | Path to the configuration file. |

### Origin patterns

An allowlist member may be an **origin pattern**: `https://*.` and then the
host whose direct subdomains it admits, as in `https://*.handles.link`. It
admits one nonempty label under that host, and both ends are anchored.

The suffix is a host and nothing more: at least two labels, lowercase ASCII,
no port, no trailing dot, no empty label and no second `*`. A member carrying
a `*` that is not a well-formed pattern — `https://*handles.link`,
`https://*.handles.link:8443` — is refused at startup rather than read as an
exact origin: no browser stamps such an origin, so admitting the spelling
would keep the typo until a ceremony hung waiting for a peer to match it.

| Origin | `https://*.handles.link` |
|---|---|
| `https://improve-account-linking.handles.link` | admitted |
| `https://x_y.handles.link` | admitted |
| `https://xn--80ak6aa92e.handles.link` | admitted |
| `https://handles.link` | refused — the apex is not a subdomain |
| `https://a.b.handles.link` | refused — one label only |
| `http://x.handles.link` | refused — scheme |
| `https://x.handles.link:8443` | refused — port |
| `https://evilhandles.link` | refused — no label boundary |
| `https://handles.link.evil.test` | refused — anchored at the end |
| `https://.handles.link` | refused — empty label |
| `https://x.handles.link.` | refused — a trailing dot names another host |
| `https://X.handles.link` | refused — not canonical |

Nothing is normalised while matching. A browser stamps an origin lowercase and
in punycode, and a pattern whose suffix is in any other form is refused at
startup, so both sides are canonical already and the comparison is of bytes.

A pattern belongs in `allowed_app_origins` and nowhere else. `ccdp_origin` is
an exact origin, and the callback document's policy names that origin alone,
so no pattern reaches a `Content-Security-Policy`.

No public suffix list is consulted, and none is to be added. `https://*.co.uk`
satisfies the grammar: a pattern places the whole direct-subdomain namespace of
its suffix inside the trust boundary, and the operator writing one asserts
control of that namespace.

**A pattern needs a Callback that understands one.** A Callback that does not
still accepts a pattern member — a URL parser reads `*` as an ordinary host
byte, so the member passes its validation — and then matches it against no
peer. The ceremony does not fail; it never becomes ready. Configure a pattern
only where the CCDP Distribution this bridge serves carries a Callback that
understands patterns.

### Per platform

GitHub's entry carries the App's client secret as the public
`clientCredential`; the browser's token request sends it as
`client_secret`. X runs a public PKCE client, browser to notary, and Google's
identity evidence is a signed ID Token the browser reads out of the redirect
fragment: neither entry carries a credential, and nothing here takes part in
either ceremony beyond the configuration and the callback document.

## Running with Docker

```sh
docker run --rm -p 8722:8722 \
  -v ./bridge.toml:/etc/libid/bridge.toml:ro \
  -e LIBID_CONFIG=/etc/libid/bridge.toml \
  ghcr.io/libid-org/libid-server-rs:latest
```

Images are published on every GitHub release as
`ghcr.io/libid-org/libid-server-rs:<version>` and `:latest`. The image sets
`HOST=0.0.0.0` and `PORT=8722` and carries a `/health` healthcheck on that
port; `-e PORT=` moves both.

## Building from source

```sh
cargo build --release          # rustc >= 1.95 (see rust-version in Cargo.toml)
cargo test
```

## License

Dual-licensed under MIT and Apache-2.0 — see `LICENSE-MIT`,
`LICENSE-APACHE` and `NOTICE`.
