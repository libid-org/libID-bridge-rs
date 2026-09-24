//! The rungs: one ceremony step each, against the real platform, with the
//! deployment under test behind [`Deployment`] where a rung needs one.

use std::time::{
    Duration,
    Instant,
};

use base64::Engine;
use libid_ceremony::attestation::AttestedData;
use libid_tlsn::Direction;
use sha2::{
    Digest,
    Sha256,
};

use crate::{
    browser::{
        self,
        Grant,
    },
    env::{
        self,
        required,
    },
    github,
    notary::Notary,
    prover::{
        self,
        Failed,
        Notarized,
    },
    session::{
        self,
        Exchange,
        Identity,
    },
    x,
    Deployment,
};

/// A code GitHub refuses: twenty hex characters, the shape of a real one.
const SPENT_CODE: &str = "0123456789abcdef0123";

/// The longest bearer the client commits (REQ-PLAT-30).
const BEARER_CEILING: usize = 4096;

/// How long an X authorization code lives once issued (REQ-PLAT-33).
const X_CODE_LIFETIME: Duration = Duration::from_secs(30);

/// A bearer no platform issued.
const FOREIGN_BEARER: &str = "not-a-bearer";

/// The record the notary signed for `session`, the `what` session of a
/// ceremony, once it is checked to be this suite's notary's signature over
/// exactly the bytes the prover received.
async fn attested<K>(
    notary: &mut Notary,
    session: &Notarized<K>,
    what: &str,
) -> AttestedData {
    assert_eq!(
        prover::recovered(&session.wire),
        notary.pubkey(),
        "the {what} record was signed by this suite's notary"
    );
    let record = notary.record().await;
    assert_eq!(
        record.encode().expect("the record encodes"),
        session.wire.attested_data,
        "the struct the notary signed for the {what} session is the bytes the prover received"
    );
    record
}

/// The two commitments that hide the bearer, opened: the token record's
/// commitment over the bearer in the response, and the identity record's
/// one commitment in the request, each SHA-256 over the bearer and the
/// blinder the prover was handed for that range.
fn bearer_commitments_open(
    exchange: &Exchange,
    token_record: &AttestedData,
    identity: &Identity,
    identity_record: &AttestedData,
) {
    let bearer = exchange.session.kept.value.as_bytes();
    session::assert_opens(
        &token_record.received,
        &exchange.session.kept.range,
        bearer,
        &exchange.blinder,
    );
    let committed = &identity_record.sent.commitments[0];
    let range = committed.start as usize..committed.end as usize;
    let blinder = prover::blinder(&identity.session.openings, Direction::Sent, &range);
    session::assert_opens(&identity_record.sent, &range, bearer, &blinder);
}

/// An identity session `platform` refused: its own `4xx`, answered after the
/// MPC-TLS handshake with it completed.
fn refused_after_the_handshake(platform: &str, outcome: Result<Identity, Failed>) {
    let failed = outcome
        .err()
        .unwrap_or_else(|| panic!("{platform} refuses a bearer it did not issue"));
    let message = failed.to_string();
    assert!(message.contains("API returned 4"), "{message}");
    assert!(
        message.contains("TlsHandshakeComplete"),
        "the session reached {platform} before it failed: {message}"
    );
}

/// A `state` no earlier run sent: the process id and the clock, in hex.
fn fresh_state() -> String {
    format!(
        "{:x}{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock at or after the epoch")
            .as_nanos()
    )
}

/// A PKCE code verifier (RFC 7636, section 4.1): 32 random bytes as
/// unpadded url-safe base64, 43 characters.
fn fresh_verifier() -> String {
    let mut random = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
        .expect("OS randomness");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)
}

/// Unpadded url-safe base64 of SHA-256 over `input`: 43 characters.
fn s256(input: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(input))
}

/// The bearer a token session yielded: nonempty printable ASCII with no
/// carriage return or line feed, within the ceiling (REQ-PLAT-36).
fn assert_bearer(bearer: &str) {
    assert!(!bearer.is_empty());
    assert!(
        bearer.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
        "the bearer is printable ASCII"
    );
    assert!(bearer.len() <= BEARER_CEILING, "{} bytes", bearer.len());
    eprintln!("bearer: {} bytes", bearer.len());
}

/// A refused authorization code fails the token session with GitHub's own
/// answer, `bad_verification_code`, and the steps reached: a notary was
/// dialled, MPC-TLS completed against github.com and GitHub answered. The
/// client id and the credential are the ones the bridge published.
pub async fn a_refused_code_fails_the_token_session_with_githubs_answer(
    deployment: &impl Deployment,
) {
    let notary = Notary::attesting().await;
    let published = deployment.published().await;
    let failed = github::exchange(
        &notary,
        github::token_request(&github::TokenFields {
            client_id: &published.client_id,
            code: SPENT_CODE,
            redirect_uri: &deployment.redirect_uri(),
            code_verifier: &s256("placeholder"),
            client_secret: &published.credential,
        }),
    )
    .await
    .err()
    .expect("GitHub refuses a code it did not issue");
    let message = failed.to_string();
    assert!(message.contains("bad_verification_code"), "{message}");
    assert!(
        message.contains("TlsHandshakeComplete"),
        "the session reached GitHub before it failed: {message}"
    );
}

/// A credential GitHub refuses fails the token session with GitHub's own
/// answer, `incorrect_client_credentials`. The client id is the published
/// one: a placeholder id is answered `404` by GitHub, a different path.
pub async fn a_credential_github_refuses_fails_the_token_session(
    deployment: &impl Deployment,
) {
    let notary = Notary::attesting().await;
    let published = deployment.published().await;
    let failed = github::exchange(
        &notary,
        github::token_request(&github::TokenFields {
            client_id: &published.client_id,
            code: SPENT_CODE,
            redirect_uri: &deployment.redirect_uri(),
            code_verifier: &s256("placeholder"),
            client_secret: "not-this-deployments-credential",
        }),
    )
    .await
    .err()
    .expect("GitHub refuses a credential it did not issue");
    let message = failed.to_string();
    assert!(
        message.contains("incorrect_client_credentials"),
        "{message}"
    );
    assert!(
        message.contains("TlsHandshakeComplete"),
        "the session reached GitHub before it failed: {message}"
    );
}

/// A bearer GitHub did not issue fails the identity session with GitHub's
/// own answer (a `4xx`, `401 Unauthorized` today) and the steps reached. No
/// account is needed.
pub async fn a_bearer_github_refuses_fails_the_identity_session() {
    env::logging();
    let notary = Notary::attesting().await;
    refused_after_the_handshake(
        "GitHub",
        github::identity(&notary, FOREIGN_BEARER).await,
    );
}

/// The GitHub ceremony end to end: the bridge under test publishes the App's
/// client id and credential, Chrome signed in as the GitHub test account
/// authorizes the App, the suite's prover runs the token session with the
/// published credential as `client_secret` and the identity session through
/// the suite's notary, and both records are checked against the rules the
/// Platform Verifier applies. One authorization per run.
pub async fn a_real_github_authorization_yields_two_sessions_the_notary_attested(
    deployment: &impl Deployment,
) {
    let mut notary = Notary::attesting().await;
    let published = deployment.published().await;
    let account = browser::github::Account::from_env("GH_TEST_ALICE");
    let redirect_uri = deployment.redirect_uri();
    let state = fresh_state();
    let code_verifier = fresh_verifier();
    let code_challenge = s256(&code_verifier);

    let grant = Grant::obtained(&browser::github::Authorization {
        account: &account,
        client_id: &published.client_id,
        redirect_uri: &redirect_uri,
        state: &state,
        code_challenge: &code_challenge,
    })
    .await;
    let code = grant.code.clone();
    grant.closed().await;

    let fields = github::TokenFields {
        client_id: &published.client_id,
        code: &code,
        redirect_uri: &redirect_uri,
        code_verifier: &code_verifier,
        client_secret: &published.credential,
    };
    let exchange = github::exchange(&notary, github::token_request(&fields))
        .await
        .unwrap_or_else(|failed| panic!("the token session failed: {failed}"));
    eprintln!("token session: steps {:?}", exchange.session.steps);

    let bearer = &exchange.session.kept.value;
    assert_bearer(bearer);
    let token_record = attested(&mut notary, &exchange.session, "token").await;
    github::check_token(
        &token_record,
        exchange.session.sent_len,
        exchange.session.recv_len,
        &exchange.session.kept,
        &fields,
    );

    let identity = github::identity(&notary, bearer)
        .await
        .unwrap_or_else(|failed| panic!("the identity session failed: {failed}"));
    eprintln!("identity session: steps {:?}", identity.session.steps);
    let identity_record = attested(&mut notary, &identity.session, "identity").await;
    let (id, login) = github::check_identity(
        &identity_record,
        identity.session.sent_len,
        identity.session.recv_len,
        bearer,
        account.username(),
    );
    bearer_commitments_open(&exchange, &token_record, &identity, &identity_record);
    eprintln!("identity: an id of {} digits, login {login}", id.len());
}

/// A bearer X did not issue fails the identity session with X's own answer
/// (a `4xx`, `403 Forbidden` today) and the steps reached: a notary was
/// dialled, MPC-TLS completed against api.x.com and X answered. No account
/// is needed.
pub async fn a_bearer_x_refuses_fails_the_identity_session() {
    env::logging();
    let notary = Notary::attesting().await;
    refused_after_the_handshake("X", x::identity(&notary, FOREIGN_BEARER).await);
}

/// The X ceremony end to end, the bridge taking no part: Chrome signed in as
/// the X test account authorizes the app, the suite's prover runs the token
/// session and the identity session through the suite's notary, and both
/// records are checked against the rules the Platform Verifier applies. The
/// code lives thirty seconds, so everything that can be built before the
/// browser step is.
pub async fn a_real_x_authorization_yields_two_sessions_the_notary_attested() {
    env::logging();
    let mut notary = Notary::attesting().await;
    let account = browser::x::Account::from_env("X_TEST_ALICE");
    let client_id = required("X_OAUTH_CLIENT_ID");
    let redirect_uri = required("LIBID_TEST_X_REDIRECT_URI");
    let state = fresh_state();
    let code_verifier = fresh_verifier();
    let code_challenge = s256(&code_verifier);

    let grant = Grant::obtained(&browser::x::Authorization {
        account: &account,
        client_id: &client_id,
        redirect_uri: &redirect_uri,
        state: &state,
        code_challenge: &code_challenge,
        profile: None,
    })
    .await;
    let seen = Instant::now();

    let exchange = x::exchange(
        &notary,
        x::token_request(&client_id, &grant.code, &redirect_uri, &code_verifier),
    )
    .await
    .unwrap_or_else(|failed| {
        let late = if seen.elapsed() > X_CODE_LIFETIME {
            ", past the code's lifetime"
        } else {
            ""
        };
        panic!(
            "the token session failed {:?} after the code was seen{late}: {failed}",
            seen.elapsed()
        )
    });
    eprintln!(
        "token session: {:?} from the code to the record; steps {:?}",
        seen.elapsed(),
        exchange.session.steps
    );

    let bearer = &exchange.session.kept.value;
    assert_bearer(bearer);
    let token_record = attested(&mut notary, &exchange.session, "token").await;
    x::check_token(
        &token_record,
        exchange.session.sent_len,
        exchange.session.recv_len,
        &exchange.session.kept,
    );

    let identity = x::identity(&notary, bearer)
        .await
        .unwrap_or_else(|failed| panic!("the identity session failed: {failed}"));
    eprintln!("identity session: steps {:?}", identity.session.steps);
    let identity_record = attested(&mut notary, &identity.session, "identity").await;
    let (id, username) = x::check_identity(
        &identity_record,
        identity.session.sent_len,
        identity.session.recv_len,
        bearer,
        account.username(),
    );
    bearer_commitments_open(&exchange, &token_record, &identity, &identity_record);
    eprintln!(
        "identity: an id of {} digits, username {username}",
        id.len()
    );

    grant.closed().await;
}

/// Turn a cookie list exported from a browser into the
/// `X_TEST_ALICE_COOKIES` value, so the session a person signed in for is the
/// one the rung restores:
/// `X_COOKIE_EXPORT=.env.x-export.json cargo test --test ceremony --
/// --ignored --nocapture a_browser_export`, from `ceremony-tests/`.
pub async fn a_browser_export_becomes_the_x_secret() {
    let path = required("X_COOKIE_EXPORT");
    let export = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path} is a cookie export this test reads: {e}"));
    println!(
        "X_TEST_ALICE_COOKIES={}",
        browser::x::secret_from_export(&export)
    );
}

/// Export the session of `X_PROFILE` (`.env.x-profile`): a profile with no
/// sign-in opens a Chrome for a person to sign in once; after that the export
/// needs nobody. Written as JSON to `X_COOKIE_EXPORT_OUT` when that names a
/// path, or printed as the `X_TEST_ALICE_COOKIES` value otherwise. Run by
/// name, ignored otherwise: `cargo test --test ceremony -- --ignored
/// --nocapture a_fresh_x_session`, from `ceremony-tests/`.
pub async fn a_fresh_x_session_is_exported_for_the_secret() {
    let account = browser::x::Account::for_export("X_TEST_ALICE");
    let authorization = browser::x::Authorization {
        account: &account,
        client_id: &required("X_OAUTH_CLIENT_ID"),
        redirect_uri: &required("LIBID_TEST_X_REDIRECT_URI"),
        state: "export",
        code_challenge: "",
        profile: Some(browser::profile::named("X_PROFILE", ".env.x-profile")),
    };
    let cookies = authorization.fresh_cookies().await;
    browser::cookies::deliver(&cookies, "X_COOKIE_EXPORT_OUT", "X_TEST_ALICE_COOKIES");
}
