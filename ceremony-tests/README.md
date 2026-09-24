# ceremony-tests

The live ceremony suite: a Chrome that authorizes as a person at GitHub, X and
Google, a notary of its own built from `libid-tlsn`, the prover that runs the
notarized sessions, and what each platform's records must contain -- the rules
the Platform Verifier applies on chain. The library reaches nowhere into the
crate under test and declares every dependency, so it lifts out of this
repository as a unit.

It is a workspace of its own, with its own `Cargo.lock` and the `[patch]`
tables its `tlsn` and `mpz` revisions need: the server's builds resolve none
of the git dependencies the prover and the notary pull in.

The deployment under test reaches the GitHub rungs as one value,
`rungs::Published`: what the deployment publishes for a ceremony to start
from, and where the OAuth App redirects to. A host builds it -- this
repository's does in `tests/ceremony/host.rs`, from the bridge binary it
builds from the repository's manifest and starts -- and calls the rungs of
`ceremony_tests::rungs` from tests of its own, handing each the settings it
reads. The X and Google rungs take no deployment.

## Running

Every command runs from this directory, `ceremony-tests/`: it is where the
test target and its settings live, and relative paths in the settings -- the
profiles, cookie files, exports and traces -- resolve against it.

```sh
cargo test --test ceremony -- --test-threads=1
```

One rung at a time: X's authorization code lives thirty seconds, and rungs
run side by side contend for Chrome and the notary. The Google rung and the
Chrome checks are ignored in that run and selected by name, as below; the
library's own tests are `cargo test --lib`. The exports that renew the saved
sessions are tasks of the crate's `ceremony` command, below.

### Settings

The suite reads its settings from the environment, or from a gitignored
`.env.test` found from this directory upward (the repository root's serves),
where an exported variable wins; an empty value is an absent one.
`src/settings.rs` defines them, in `settings::VARIABLES`: each belongs to one
section, and a test loads the sections its rung reads and fails, naming every
required variable absent from them, before it starts. A missing setting never
skips a rung. `cargo run --bin ceremony -- settings` lists each variable as
set, missing or unset, never its value, and `cargo test --test ceremony
settings_sync` holds the table below, and the gate and job environments of
`ceremony.yml`, to that definition.

| Section | Read by | In CI |
|---|---|---|
| github-app | every GitHub rung but the bearer's: the host configures the bridge under test with it | `refusals` and `full`, gated by `go` |
| github-account | the GitHub authorization | `full`, gated by `account` |
| x-app, x-account, x-session | the X authorization | `x`, gated by `x` |
| google-app, google-account | the Google authorization and the Google export | `google` |
| google-session | the Google authorization | `google`, with no gate: it runs on a dispatch alone and fails on a missing setting |
| tooling | the browser and the exports; nothing in it is required | `x` sets `X_CHALLENGE_TRACE` |

| Variable | Section | Need | Meaning |
|---|---|---|---|
| `GH_OAUTH_CLIENT_ID` | github-app | required | The GitHub OAuth App's client id; the host configures the bridge under test with it. |
| `GH_OAUTH_CLIENT_SECRET` | github-app | required | The App's client secret, which the bridge publishes as `clientCredential` and the token session sends. |
| `LIBID_TEST_PUBLIC_ORIGIN` | github-app | required | The bridge origin the App's callback URL is registered under; the host derives `/auth/callback` from it. |
| `GH_TEST_ALICE_USERNAME` | github-account | required | The GitHub test account's login. |
| `GH_TEST_ALICE_PASSWORD` | github-account | required | Its password. |
| `GH_TEST_ALICE_TOTP_SECRET` | github-account | required | The base32 key of its authenticator app; without one GitHub verifies the device by mail, which a headless run cannot answer. |
| `X_OAUTH_CLIENT_ID` | x-app | required | The X app, a public PKCE client. |
| `LIBID_TEST_X_REDIRECT_URI` | x-app | required | The redirect URI registered on that app, byte for byte. |
| `X_TEST_ALICE_USERNAME` | x-account | required | The X test account's handle, which the identity session must return. |
| `X_TEST_ALICE_EMAIL` | x-account | optional | Its e-mail address, typed when X asks for it on a sign-in it examines. |
| `X_TEST_ALICE_PASSWORD` | x-account | optional | Its password, typed on a sign-in in a visible Chrome; a person types it where it is absent. |
| `X_TEST_ALICE_COOKIES` | x-session | required | The saved session the rung restores, as the base64 `ceremony export x` prints; a headless run has no other way in. |
| `X_TEST_ALICE_COOKIES_FILE` | x-session | instead of `X_TEST_ALICE_COOKIES` | The same session as the JSON file `ceremony export x --out` writes; keep it under a gitignored `.env*` name. |
| `GOOGLE_OAUTH_CLIENT_ID` | google-app | required | The Google OAuth client id; no client secret. |
| `LIBID_TEST_GOOGLE_REDIRECT_URI` | google-app | required | The registered redirect URI, without a query or fragment. |
| `GOOGLE_TEST_ALICE_EMAIL` | google-account | required | The Google test account's verified e-mail address, which the ID token must carry. |
| `GOOGLE_TEST_ALICE_PASSWORD` | google-account | optional | Its password, for one sign-in attempt when Google rejects the saved session; account verification stays interactive. |
| `GOOGLE_TEST_ALICE_COOKIES` | google-session | required | The saved session the rung restores, as the base64 `ceremony export google` prints. |
| `GOOGLE_TEST_ALICE_COOKIES_FILE` | google-session | instead of `GOOGLE_TEST_ALICE_COOKIES` | The same session as a JSON cookie export, a list or Playwright's storage state; keep it under a gitignored `.env*` name. |
| `CEREMONY_ENV_FILE` | tooling | optional | The settings file, when it is not the `.env.test` found from the working directory upward. |
| `CHROME` | tooling | optional | The Chrome binary, when it is not on the `PATH`. |
| `BROWSER_HEAD` | tooling | optional | Set for a visible Chrome, left on a page a person completes. |
| `BROWSER_TRACE` | tooling | optional | A directory; the driver writes a numbered screenshot and a dump of the page's controls and text into it at each step. |
| `X_CHALLENGE_TRACE` | tooling | optional | A directory for a screenshot taken only when X's security verification times out; CI keeps it for one day, and logs carry structural indicators, never page text or OAuth URLs. |
| `PROFILE_SIGN_IN` | tooling | optional | Set to make an export open the sign-in window even when the profile holds a session the platform honours. |
| `X_PROFILE` | tooling | optional | The Chrome profile `ceremony export x` reads, `.env.x-profile` by default. |
| `GOOGLE_PROFILE` | tooling | optional | The Chrome profile `ceremony export google` reads, `.env.google-profile` by default. |

Three GitHub rungs need no account: a refused code and a refused credential
each fail the token session with GitHub's own answer, past a real session to
`github.com`; a bearer GitHub did not issue fails the identity session. The
fourth signs in as the test account in Chrome, authorizes the App, and runs
the token session with the published credential and the identity session,
checking the bearer, both records and their signatures. A run that stops on a
page it does not handle prints that page's URL and text.

Two rungs run the X ceremony, in which the bridge takes no part. One needs
no account: an identity read with a bearer X did not issue fails with X's
own answer, past a real session to `api.x.com`. The other signs in as the X
test account in Chrome and authorizes the app, then runs the two sessions
the same way. The X export reads no X setting, only its profile.

The session comes from a dedicated Chrome profile, `X_PROFILE`. The first
export opens a visible Chrome on that profile with no automation attached, on
X's own sign-in page, and waits for the window to be closed; X examines a
sign-in it did not expect, and a browser with nothing attached is the one it
examines least. Every later export opens the profile headless, checks that X
still honours its session by opening the home timeline on it, and reads the
cookies with nobody present; a session X no longer honours, however fresh its
cookies look, brings the window back once, as does `PROFILE_SIGN_IN=1`:

```sh
cargo run --bin ceremony -- export x --out .env.x-cookies.json
```

With `--out` the JSON is written there whole or not at all, readable by its
owner alone, and nothing else is printed; without it the base64
`X_TEST_ALICE_COOKIES` value is printed instead.

A session from the browser a person already uses serves as well: export its
`x.com` cookies, as a list or as Playwright's `storageState`, to a file under
a gitignored `.env*` name -- it holds a working session -- and convert:

```sh
cargo run --bin ceremony -- convert x .env.x-export.json
```

In CI (`ceremony.yml`) pull requests run the crate's formatting, lints,
library tests and Chrome checks, and the rungs that need no account; the
nightly runs, and a dispatch with the `full` input set, add the GitHub
authorization, one rung at a time.
The X authorization runs weekly and on a dispatch with the `x` input set, and
only from the saved session: an unattended run never opens X's sign-in pages,
because X examines a fresh sign-in and has questions a test cannot answer. A
run whose saved session no longer authenticates says so and names the export
above. A pull-request or scheduled job whose settings are absent is skipped,
and the run carries a notice naming it; a dispatched job runs and fails on a
missing setting.

### Google identity authorization

The explicit Google rung restores a dedicated test account's saved session and
opens the Google v1 authorization URL directly: `response_type=id_token`,
`response_mode=fragment`, `scope=openid email`, and a fresh state and digest-bound
nonce. It handles the expected account chooser and English consent controls.
An optional password permits one sign-in attempt when the session is rejected;
account-verification prompts require interactive renewal. Google can refuse
automation even with a saved session.

It reads the google-app, google-account and google-session sections; the
saved session installs cookies for Google's hosts alone, and each sign-in step
is submitted at most once.

```sh
cargo test --locked --test ceremony \
  google::a_real_google_authorization_returns_a_verified_id_token -- --ignored --exact
```

The rung captures the fragment through Chrome's redirect event, closes the
browser, and validates RS256 against Google's HTTPS JWKS plus issuer, audience,
state, nonce, expiry, subject, and expected verified email. Its authorization
digest uses a fresh nonce and a fixed local-chain test operation. Tokens and
cookie values are not logged. This covers identity-evidence acquisition and
local verification, not the actual distributed callback implementation, proof
generation, trusted on-chain modulus membership, or claim submission.

Dispatch `ceremony.yml` with `google=true` to run this on a hosted runner. Set
client ID, email, and base64 cookies as repository secrets, and the redirect URI
as a repository variable with the names above. The job has no gate: a
missing setting fails it rather than skipping it. The Google rung is ignored in ordinary runs until explicitly selected.

The session the rung restores comes from a dedicated Chrome profile,
`GOOGLE_PROFILE` (`.env.google-profile`, gitignored), exactly as X's does,
the check being that the account page opens on the session and names the
test account; a Chrome with no automation attached is the only kind Google
lets a person sign in through:

```sh
cargo run --bin ceremony -- export google --out .env.google-cookies.json
```

It reads the google-app and google-account sections. With `--out` the JSON is
written there whole or not at all, readable by its owner alone, and nothing
else is printed; without it the base64 `GOOGLE_TEST_ALICE_COOKIES` value is
printed instead.

The browser's fragment handling, and the one client identity the disguised
Chrome presents in its headers and to a page's scripts, are checked without an
account against loopback fixtures:

```sh
cargo test --test ceremony -- --ignored --exact \
  browser::google::tests::chrome_preserves_the_redirect_fragment \
  browser::person::chrome_tells_one_story
```

## Lifting the crate out

Everything the library needs is declared in its own `Cargo.toml`, the
`[patch]` tables that pin the `tlsn` and `mpz` revisions `libid-tlsn` is
built against included. A repository taking this crate into a workspace of
its own moves those tables to that workspace's root manifest, which is the
only place Cargo reads them, keeping the revisions the pinned `libid-tlsn` tag
names. `tests/ceremony` is this repository's host and stays behind.

The two platforms that restore a saved session share its shape: a cookie list
as a browser exports it, parsed by `browser::cookies` for the hosts the
platform admits, carried as base64 in a `_COOKIES` setting or as JSON at a
`_COOKIES_FILE` path, and read back from a profile by `browser::profile`. A
platform adds the hosts it keeps and the cookie name that proves its sign-in.
