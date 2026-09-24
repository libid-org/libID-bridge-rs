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

The deployment under test is behind one interface, `Deployment`: where the
OAuth App redirects to, and what the deployment publishes for a ceremony to
start from. A host implements it -- this repository's does in
`tests/ceremony/host.rs`, over the bridge binary it builds from the
repository's manifest and starts -- and calls the rungs of
`ceremony_tests::rungs` from tests of its own. The X and Google rungs take no
deployment.

## Running

Every command runs from this directory, `ceremony-tests/`: it is where the
test target and its settings live, and relative paths in the settings -- the
profiles, cookie files, exports and traces -- resolve against it.

```sh
cargo test --test ceremony -- --test-threads=1
```

One rung at a time: X's authorization code lives thirty seconds, and rungs
run side by side contend for Chrome and the notary. The exports and the Chrome
checks are ignored in that run and selected by name, as below; the library's
own tests are `cargo test --lib`.

The suite reads its settings from the environment, or from a gitignored
`.env.test` found from this directory upward (the repository root's serves),
where an exported variable wins; a missing variable fails the run.

| Variable | Rungs | Meaning |
|---|---|---|
| `GH_OAUTH_CLIENT_ID`, `GH_OAUTH_CLIENT_SECRET` | GitHub | The OAuth App. The host configures the deployment under test with both, which publishes the secret as `clientCredential`; the suite reads them back through `Deployment::published` and sends them in the token request. |
| `LIBID_TEST_PUBLIC_ORIGIN` | GitHub | The bridge origin the App's callback URL is registered under; the host derives `/auth/callback` from it as the application would. |
| `CEREMONY_ENV_FILE` | all | The settings file, when it is not the `.env.test` found from the working directory upward. |
| `GH_TEST_ALICE_USERNAME`, `GH_TEST_ALICE_PASSWORD` | GitHub authorization | The test account. |
| `GH_TEST_ALICE_TOTP_SECRET` | GitHub authorization | The base32 key of the account's authenticator app; the browser answers the TOTP prompt with it. An account without one is asked to verify the device by mail, which a headless run cannot answer. |
| `BROWSER_HEAD=1` | authorization | A visible Chrome. |
| `CHROME` | authorization | The Chrome binary, when it is not on the `PATH`. |

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
the same way. It reads its own variables:

| Variable | Meaning |
|---|---|
| `X_OAUTH_CLIENT_ID` | The X app, a public PKCE client. |
| `LIBID_TEST_X_REDIRECT_URI` | The redirect URI registered on that app, byte for byte. |
| `X_TEST_ALICE_USERNAME`, `X_TEST_ALICE_PASSWORD` | The X test account. |
| `X_TEST_ALICE_EMAIL` | Its e-mail address, typed when X asks for it on a sign-in it examines. |
| `X_TEST_ALICE_COOKIES` | The saved session the rung restores, as the base64 the export prints. An unattended run has no other way in. |
| `X_TEST_ALICE_COOKIES_FILE` | The same session as the JSON file the export writes; `X_TEST_ALICE_COOKIES` wins where both are set. Keep it under a gitignored `.env*` name. |
| `X_PROFILE` | The Chrome profile the export reads, `.env.x-profile` by default; gitignored. |
| `PROFILE_SIGN_IN` | Set to make an export open the sign-in window even when the profile holds a session the platform honours. |
| `X_COOKIE_EXPORT_OUT` | Where the export writes its JSON; without it the base64 value is printed. |
| `X_COOKIE_EXPORT` | The cookies a browser exported, for the converter below. |
| `X_CHALLENGE_TRACE` | Optional directory for a screenshot only when X security verification times out. CI retains this diagnostic for one day; logs contain structural indicators, not page text or OAuth URLs. |
| `BROWSER_TRACE` | Optional: a directory; the driver writes a numbered screenshot and a dump of the page's controls and text into it at each step. |

The session comes from a dedicated Chrome profile, `X_PROFILE`. The first
export opens a visible Chrome on that profile with no automation attached, on
X's own sign-in page, and waits for the window to be closed; X examines a
sign-in it did not expect, and a browser with nothing attached is the one it
examines least. Every later export opens the profile headless, checks that X
still honours its session by opening the home timeline on it, and reads the
cookies with nobody present; a session X no longer honours, however fresh its
cookies look, brings the window back once, as does `PROFILE_SIGN_IN=1`:

```sh
X_COOKIE_EXPORT_OUT=.env.x-cookies.json \
  cargo test --test ceremony a_fresh_x_session -- --ignored --nocapture
```

With `X_COOKIE_EXPORT_OUT` the JSON is written there whole or not at all and
nothing else is printed; without it the base64 `X_TEST_ALICE_COOKIES` value is
printed instead.

A session from the browser a person already uses serves as well: export its
`x.com` cookies, as a list or as Playwright's `storageState`, to a file under
a gitignored `.env*` name -- it holds a working session -- and convert:

```sh
X_COOKIE_EXPORT=.env.x-export.json cargo test --test ceremony a_browser_export -- --ignored --nocapture
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

| Setting | Meaning |
|---|---|
| `GOOGLE_OAUTH_CLIENT_ID` | The real Google OAuth client ID; no client secret. |
| `LIBID_TEST_GOOGLE_REDIRECT_URI` | Exact registered redirect URI without a query or fragment. |
| `GOOGLE_TEST_ALICE_EMAIL` | The expected verified email. |
| `GOOGLE_TEST_ALICE_PASSWORD` | Optional local sign-in fallback. Each login step is submitted at most once; account verification remains interactive. |
| `GOOGLE_TEST_ALICE_COOKIES_FILE` | Local JSON cookie export (a list or Playwright storage state). Keep it under a gitignored `.env*` filename. Only Google domains are installed. |
| `GOOGLE_TEST_ALICE_COOKIES` | CI alternative: base64 of that JSON export. Takes precedence over the file. |

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
as a repository variable with the names above. Missing settings fail the live
job. The Google rung is ignored in ordinary runs until explicitly selected.

The session the rung restores comes from a dedicated Chrome profile,
`GOOGLE_PROFILE` (`.env.google-profile`, gitignored), exactly as X's does,
the check being that the account page opens on the session and names the
test account; a Chrome with no automation attached is the only kind Google
lets a person sign in through:

```sh
GOOGLE_COOKIE_EXPORT_OUT=.env.google-cookies.json \
  cargo test --test ceremony \
  browser::google::tests::a_fresh_google_session_is_exported_for_the_secret -- --ignored --exact --nocapture
```

With `GOOGLE_COOKIE_EXPORT_OUT` the JSON is written there whole or not at all
and nothing else is printed; without it the base64 `GOOGLE_TEST_ALICE_COOKIES`
value is printed instead.

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
