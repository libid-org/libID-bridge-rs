# libID-bridge-rs

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
   origin: the CCDP Distribution to load and, per enabled platform, the
   ceremony versions that Distribution bundles, each with its public client
   id and, for GitHub, the public `clientCredential`. It derives the redirect
   URI itself from the bridge origin it already knows:
   `{bridgeOrigin}/auth/callback`.
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
| `GET` | `/health` | Liveness probe. Returns `OK`, whether or not a callback document or a record is available. Not one of the contract's routes — see below. |
| `GET` | `/metrics` | What this deployment counts, in the Prometheus text exposition format. Not one of the contract's routes. |
| `GET`, `OPTIONS` | `/api/v1/ceremony/config` | The public ceremony configuration: `{ ccdpOrigin, platforms }`. Readable from an admitted origin, or by a same-origin `GET` without `Origin` on `Sec-Fetch-Site: same-origin`. `403` for any other origin, `400` for a query, `503` with `Retry-After: 5` until the Distribution's version list has been retrieved once. `OPTIONS` answers the preflight a caller sending its own header needs, by the same admission rule: `GET`, the headers asked for, no credentials. |
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
      "versions": [
        { "version": 1, "clientId": "Iv1.0123456789abcdef", "clientCredential": "…" }
      ]
    },
    "x": {
      "versions": [
        { "version": 1, "clientId": "…" }
      ]
    }
  }
}
```

A platform is present exactly when the configuration file enables it and the
Distribution lists at least one ceremony version for it. Its `versions` are
the versions the Distribution bundles, ascending and unique, each with the
OAuth client that version runs: the file's `version_override` for it where
there is one, the platform's defaults otherwise. `clientCredential` is
present on exactly the entries whose ceremony sends one: GitHub's. Every
client id and credential is nonempty printable ASCII without whitespace,
checked at startup. The record carries no redirect URI, no allowlist, no
notary setting and no user token.

The record depends on the Distribution, so it is not known at startup. Until
the version list has been retrieved once, an admitted caller is answered
`503` with `Retry-After: 5`, the CORS headers a `200` would carry, and a
`{"message": …}` body naming the Distribution URL waited on; an unadmitted
origin gets its `403` first, as always. Once a record has been composed it
keeps being served through any later failure, as the callback document does.

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
`state`, selects no CCDP version, and enumerates no ceremony version of its
own: a compatible Callback change needs no bridge rebuild.

`allowedOrigins` is an array of strings, every member spelled as it was
written, whichever kind it is. It carries `ccdpOrigin` itself, literally,
whatever else the allowlist covers.

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

### The version list

The Distribution publishes the platform ceremony versions it bundles at
`/ccdp/versions.json`, beside the artifact: one JSON object keyed by platform
id, each value a nonempty, duplicate-free, ascending array of unsigned 16-bit
integers, as in `{"github":[1],"google":[1],"x":[1]}`. The bridge advertises
exactly those versions. A key it does not know is ignored, whatever its
value: a Distribution may bundle a platform this bridge predates. Any other
violation — a top level that is not an object, a value that is not such an
array, an empty array, a duplicate, a version out of order — refuses the
whole list, and the list last accepted stays.

Each accepted list composes the record once: every configured platform the
list names, with the client each listed version runs. A configured platform
the list does not name is left out, and an override for a version the list
does not carry is ignored; each is logged when the record is composed, and
neither is an error, because the Distribution cannot be checked at startup.

### Retrieval

Both resources are **retrieved from the Distribution**,
`{CCDP_ORIGIN}/ccdp/callback.html` and `{CCDP_ORIGIN}/ccdp/versions.json`,
first as soon as the process runs and then every five minutes, each
conditionally on the `ETag` it came with. Each is published independently: a
retrieval that returns `304`, fails to reach the Distribution, or returns
something this bridge will not accept leaves what is already served as it is,
and only a valid replacement replaces it. The document and the policy naming
its hashes are published as one value, and so are the record and the list it
was composed from. Redirects are refused, each body is read up to a bound of
its own, and the request carries no cookie, credential, query, or anything
derived from a callback request.

**The Distribution's availability is not this deployment's.** The process starts
without it, binds, and serves the liveness probe and the metrics. Until a
retrieval produces a document the callback path answers `503` with an inert
page naming the last failure; until one produces a version list the
configuration route answers `503` naming the URL it waits on. A tick on
which either retrieval failed backs off from one second to five minutes,
doubling. Once a document or a record is published it keeps being served
through any later failure. A development stack serves its own Distribution
over HTTP on `localhost` or `127.0.0.1`, the one plaintext exception the
origin rules make.

## What this deployment counts

`GET /metrics` answers the Prometheus text exposition format. It is scraped
from the pod and is not part of the ceremony contract. `resource` is
`callback` for the artifact and `versions` for the version list.

| Metric | What it says |
|---|---|
| `libid_bridge_retrievals_total{resource,outcome}` | Retrievals, by resource and `published`, `unchanged` or `failed` |
| `libid_bridge_retrieval_failures_total{resource,kind}` | Failed retrievals, by resource and which refusal |
| `libid_bridge_callback_requests_total{outcome}` | Callback requests, by `document` or `unavailable` |
| `libid_bridge_available{resource}` | `1` while the callback document, or the record composed from the version list, is available |
| `libid_bridge_published_timestamp_seconds{resource}` | When the served document or record was published |

A deployment serving something it can no longer replace shows a rising
`failed` count for that resource with `available` still `1`, and its
published timestamp stops moving.

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

[[platforms]]
id                        = "github"
default_client_id         = "Iv1.0123456789abcdef"
default_client_credential = "…"

[platforms.version_override.2]
client_id         = "Iv1.fedcba9876543210"
client_credential = "…"
```

An unknown key is refused at startup, `host` and `port` among them: where the
process listens is set with `HOST`/`PORT` or `--host`/`--port`. The platforms
are set only in the file, one `[[platforms]]` table per enabled platform: its
`id` (`github`, `google` or `x`), the public `default_client_id` its ceremony
versions run and, for `github`, the App's client secret as
`default_client_credential`, which the bridge publishes. The versions
themselves are not written here; the Distribution lists the ones it bundles.
There is no notary setting and no environment variable for the credential.

A version may run a client of its own: `version_override` is a table keyed by
the version, the decimal spelling of an unsigned 16-bit integer, bare or
quoted, with no sign, leading zero or whitespace; any other key is refused at
startup, and TOML itself refuses a version written twice. An override is a
whole client — `client_id`, and `client_credential` exactly where the
platform's ceremony sends one — under the same byte rules as the defaults,
and the defaults stay required whatever is overridden. An override for a
version the Distribution does not list applies to nothing.

| Key | Environment | Default | Meaning |
|---|---|---|---|
| — | `HOST`, `--host` | `127.0.0.1` | Bind address (`0.0.0.0` in the container image). Not a file key: the image sets it in the environment, which beats a file. |
| — | `PORT`, `--port` | `8722` | Bind port. Not a file key, for the same reason. |
| `allowed_app_origins` | — | *(required)* | The application allowlist. A member is an exact origin, an origin pattern or `*`, as described below. A repeated spelling is refused; a pattern and an origin it covers are two members. The **effective** admission set is this list plus the resolved `CCDP_ORIGIN`, added exactly once and by its literal spelling. It is the one admission rule: the configuration route admits exactly one `Origin` that a member admits, and echoes that origin itself; the callback document is told the same set. A same-origin read carries no `Origin` and is admitted on `Sec-Fetch-Site: same-origin` alone. |
| `ccdp_origin` | — | `https://lib.id` | The CCDP Distribution this bridge selects: one origin serving `/ccdp/callback.html`, `/ccdp/versions.json` and everything the browser runs after the callback, HTTPS, or HTTP on `localhost` or `127.0.0.1`. Published in the configuration and inserted into the callback document, and named as the one `frame-src` source of its policy, so a host a policy source expression cannot name, an IPv6 literal or an underscore among them, is refused. Omitting it selects the canonical libID Distribution. |
| `platforms` | — | *(required)* | The enabled platforms, as `[[platforms]]` tables: `id`, `default_client_id`, for `github` its `default_client_credential`, and any `version_override` tables. |
| — | `LIBID_CONFIG`, `--config` | *(none)* | Path to the configuration file. |

### Allowlist members

A member of `allowed_app_origins` is one of three kinds.

An **exact origin** admits itself: HTTPS, or HTTP on `localhost` or
`127.0.0.1`, already canonical, so a trailing slash, an uppercase host or a
default port is refused with the canonical spelling named rather than folded.

An **origin pattern** is `*.` and then the host suffix whose subdomains it
admits, with no scheme prefix, as in `*.handles.link`. It admits every HTTPS
origin whose host ends in that suffix at a label boundary, at any depth, and
not the suffix itself. The suffix is DNS labels: lowercase alphanumeric, with
hyphens only inside a label, and the last label begins with a letter. So no
scheme, no port, no path, no uppercase, no underscore, no trailing dot, no
empty label and no second `*`. A member carrying a `*` that is not a
well-formed pattern — `*handles.link`, `https://*.handles.link`,
`*.handles.link:8443` — is refused at startup rather than read as an exact
origin.

**`*`** admits every origin.

A pattern places the whole subdomain namespace of its suffix, at every depth,
inside the trust boundary. No public suffix list is consulted, so `*.vercel.app`
and `*.co.uk` are suffixes like any other. What an allowlist admits is the
responsibility of whoever writes it.

A member and an origin carry one meaning wherever the allowlist is read, so
a member admits the same origins here and in the document this bridge serves.

A pattern and a `*` belong in `allowed_app_origins` and nowhere else.
`ccdp_origin` is an exact origin, it is the one origin the callback document's
policy names, and it alone is held to the alphabet a policy source expression
can carry: letters, digits, `-` and `.`.

**A member that is not an exact origin needs a Callback that understands one.**
A Callback published before origin-pattern support reads the list by the
exact-origin rule. It raises `invalidCallbackInputs` and renders its failure
text, before any connection exists, for every ceremony the deployment serves.
Publish the CCDP Distribution that carries pattern support first, then
configure the member.

### Per platform

GitHub's clients carry the App's client secret as the public
`clientCredential`; the browser's token request sends it as
`client_secret`. X runs a public PKCE client, browser to notary, and Google's
identity evidence is a signed ID Token the browser reads out of the redirect
fragment: neither carries a credential, and nothing here takes part in
either ceremony beyond the configuration and the callback document.

## Running with Docker

```sh
docker run --rm -p 8722:8722 \
  -v ./bridge.toml:/etc/libid/bridge.toml:ro \
  -e LIBID_CONFIG=/etc/libid/bridge.toml \
  ghcr.io/libid-org/libid-server-rs:0.4.0
```

Starting with the first release after the rename, images are published as
`ghcr.io/libid-org/libid-bridge-rs:<version>` and `:latest`. The same images
are also published under `ghcr.io/libid-org/libid-server-rs` for existing
deployments. Earlier releases remain at their original image paths; the
example above pins the existing 0.4.0 release until a renamed image is released.
The container also retains the old executable name as a compatibility symlink.

The image sets
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
