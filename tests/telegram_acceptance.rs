//! Acceptance and abuse cases for the two Telegram routes, written from the
//! Bridge's Telegram specification alone: the code swap at
//! `POST /api/v1/ceremony/telegram/token` and the key list at
//! `GET /api/v1/ceremony/telegram/jwks`.
//!
//! Every deployment here is written as a TOML file and read back the way the
//! binary reads one, so a setting the spec names and the file does not accept
//! fails at runtime with the parser's refusal rather than at compile time.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        Mutex,
    },
    time::Duration,
};

use axum::{
    body::Body,
    http::{
        header,
        HeaderMap,
        Method,
        Request,
        StatusCode,
        Uri,
    },
    Router,
};
use bytes::Bytes;
use http_body_util::BodyExt;
use libid_bridge_rs::{
    config,
    routes,
    Bridge,
};
use tower::ServiceExt;

use crate::common::{
    Distribution,
    FakeTelegram,
    ScratchFile,
    TokenReply,
    CLIENT_CREDENTIAL,
    CLIENT_ID,
    TELEGRAM_CLIENT_ID,
    TELEGRAM_REDIRECT_URI,
    TELEGRAM_SECRET,
};

const TOKEN_PATH: &str = "/api/v1/ceremony/telegram/token";
const JWKS_PATH: &str = "/api/v1/ceremony/telegram/jwks";
const APP: &str = "https://app.example";
const CODE: &str = "6b7f2c1d9e4a8035";
/// RFC 7636 appendix B's verifier: 43 unreserved characters.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// `base64("8123456789:SECRET-MARKER-7f3a")`, computed with coreutils
/// `base64`, not by the code under test.
const BASIC: &str = "Basic ODEyMzQ1Njc4OTpTRUNSRVQtTUFSS0VSLTdmM2E=";
/// `{"keys":[{"kty":"RSA","kid":"oidc-1"}]}` through `gzip -n -9`.
const GZIPPED_KEYS: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xab, 0x56, 0xca, 0x4e,
    0xad, 0x2c, 0x56, 0xb2, 0x8a, 0xae, 0x56, 0xca, 0x2e, 0xa9, 0x54, 0xb2, 0x52, 0x0a,
    0x0a, 0x76, 0x54, 0xd2, 0x51, 0xca, 0xce, 0x4c, 0x01, 0xb2, 0xf3, 0x33, 0x53, 0x92,
    0x75, 0x0d, 0x95, 0x6a, 0x63, 0x6b, 0x01, 0xf0, 0xab, 0x93, 0x07, 0x27, 0x00, 0x00,
    0x00,
];

// ─── deployments ─────────────────────────────────────────────────────────────

/// The `[telegram]` table a test writes.
struct Table<'a> {
    token_url: Option<&'a str>,
    jwks_url: Option<&'a str>,
}

impl<'a> Table<'a> {
    fn token(token_url: &'a str) -> Table<'a> {
        Table {
            token_url: Some(token_url),
            jwks_url: None,
        }
    }

    fn keys(jwks_url: &'a str) -> Table<'a> {
        Table {
            token_url: None,
            jwks_url: Some(jwks_url),
        }
    }
}

/// A deployment enabling GitHub and Telegram, written as a file and read the
/// way the binary reads one, with its secret in a file that lives as long as
/// the result. The table names no `redirect_uri`: the client sends it with
/// each swap. `jwks_url` is a spec setting the parser may not know yet; a
/// refusal of either is this function's error.
fn settings(table: &Table<'_>) -> Result<(config::Settings, ScratchFile), String> {
    settings_with_secret(table, &format!("{TELEGRAM_SECRET}\n"))
}

fn settings_with_secret(
    table: &Table<'_>,
    secret: &str,
) -> Result<(config::Settings, ScratchFile), String> {
    let secret = ScratchFile::holding(secret);
    let mut text = format!(
        "allowed_app_origins = [{APP:?}]\n\
         ccdp_origin = {:?}\n\
         [[platforms]]\nid = \"github\"\nclient_id = {CLIENT_ID:?}\n\
         client_credential = {CLIENT_CREDENTIAL:?}\n\
         [[platforms]]\nid = \"telegram\"\nclient_id = {TELEGRAM_CLIENT_ID:?}\n\
         [telegram]\nclient_secret_file = {:?}\n",
        Distribution::shared().origin(),
        secret.path().to_str().unwrap(),
    );
    if let Some(url) = table.token_url {
        text.push_str(&format!("token_url = {url:?}\n"));
    }
    if let Some(url) = table.jwks_url {
        text.push_str(&format!("jwks_url = {url:?}\n"));
    }
    let file = ScratchFile::holding(&text);
    let settings = config::Settings::read(file.path()).map_err(|e| e.to_string())?;
    Ok((settings, secret))
}

/// The router of a deployment started from `table`.
fn app(table: &Table<'_>) -> Router {
    let (settings, _secret) = settings(table).expect("the [telegram] table parses");
    let bridge = Bridge::start(&settings).expect("the deployment starts");
    routes::build_router(bridge.state)
}

/// The router of a deployment serving the key list from `jwks_url`.
fn keys_app(jwks_url: &str) -> Router {
    // Depends on the spec's `jwks_url` setting in the `[telegram]` table.
    let (settings, _secret) =
        settings(&Table::keys(jwks_url)).expect("jwks_url is a [telegram] setting");
    let bridge = Bridge::start(&settings).expect("the deployment starts");
    routes::build_router(bridge.state)
}

/// One response, read whole, after checking no part of it carries the secret.
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Answer {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("{e}: {:?}", String::from_utf8_lossy(&self.body)))
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }

    /// A `502` that names nothing of the upstream: a JSON object of exactly a
    /// string `message`.
    fn assert_bare_502(&self, upstream_marks: &[&str]) {
        assert_eq!(self.status, StatusCode::BAD_GATEWAY);
        let body = self.json();
        let object = body.as_object().expect("a JSON object");
        assert_eq!(object.keys().collect::<Vec<_>>(), ["message"], "{body}");
        assert!(object["message"].is_string(), "{body}");
        let text = String::from_utf8_lossy(&self.body);
        for mark in upstream_marks {
            assert!(!text.contains(mark), "{mark} leaked: {text}");
        }
    }
}

async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        !format!("{headers:?}").contains(TELEGRAM_SECRET),
        "the secret is in a response header"
    );
    assert!(
        !String::from_utf8_lossy(&body).contains(TELEGRAM_SECRET),
        "the secret is in a response body"
    );
    answer_parts(status, headers, body)
}

fn answer_parts(status: StatusCode, headers: HeaderMap, body: Bytes) -> Answer {
    Answer {
        status,
        headers,
        body,
    }
}

fn swap_body(code: &str, verifier: &str) -> String {
    swap_body_to(code, verifier, TELEGRAM_REDIRECT_URI)
}

fn swap_body_to(code: &str, verifier: &str, redirect_uri: &str) -> String {
    serde_json::json!({ "code": code, "codeVerifier": verifier, "redirectUri": redirect_uri })
        .to_string()
}

/// A swap request from `origin` carrying `body` as JSON.
fn swap(origin: Option<&str>, body: impl Into<Body>) -> Request<Body> {
    let mut request =
        Request::post(TOKEN_PATH).header("content-type", "application/json");
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    request.body(body.into()).unwrap()
}

fn get_keys(origin: Option<&str>) -> Request<Body> {
    let mut request = Request::get(JWKS_PATH);
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    request.body(Body::empty()).unwrap()
}

/// The form a swap posted, as `(key, value)` pairs in order.
fn form(body: &[u8]) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn assert_vary(answer: &Answer) {
    let vary = answer
        .header("vary")
        .expect("a Vary header")
        .to_ascii_lowercase();
    let tokens: BTreeSet<&str> = vary.split(',').map(str::trim).collect();
    assert!(tokens.contains("origin"), "{vary}");
    assert!(tokens.contains("sec-fetch-site"), "{vary}");
}

fn allow_set(answer: &Answer) -> BTreeSet<String> {
    answer
        .header("allow")
        .expect("an Allow header")
        .split(',')
        .map(|m| m.trim().to_owned())
        .collect()
}

/// A JSON document of exactly `len` bytes.
fn json_of_len(len: usize) -> String {
    let prefix = r#"{"keys":[],"p":""#;
    let pad = len - prefix.len() - 2;
    format!("{prefix}{}\"}}", "a".repeat(pad))
}

// ─── a fake key-list endpoint ────────────────────────────────────────────────

#[derive(Clone)]
enum KeysReply {
    Answer {
        status: StatusCode,
        media: &'static str,
        encoding: Option<&'static str>,
        body: Bytes,
    },
    /// A `302` to `/elsewhere` on the same fake, which serves a key list.
    Redirect,
}

impl KeysReply {
    fn ok(media: &'static str, body: impl Into<Bytes>) -> KeysReply {
        KeysReply::Answer {
            status: StatusCode::OK,
            media,
            encoding: None,
            body: body.into(),
        }
    }
}

#[derive(Clone)]
struct SeenFetch {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

type KeysState = (Arc<Mutex<Vec<SeenFetch>>>, Arc<Mutex<KeysReply>>);

/// Telegram's key list, on loopback and in plaintext, at `/jwks`.
struct FakeKeys {
    base: String,
    seen: Arc<Mutex<Vec<SeenFetch>>>,
    reply: Arc<Mutex<KeysReply>>,
}

impl FakeKeys {
    fn serving(reply: KeysReply) -> FakeKeys {
        let seen: Arc<Mutex<Vec<SeenFetch>>> = Arc::default();
        let reply = Arc::new(Mutex::new(reply));
        let router = Router::new()
            .route("/jwks", axum::routing::any(keys_answer))
            .route("/elsewhere", axum::routing::any(keys_elsewhere))
            .with_state((seen.clone(), reply.clone()));
        let (bound, address) = std::sync::mpsc::channel();
        common::runtime().spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let _ = bound.send(listener.local_addr().unwrap());
            let _ = axum::serve(listener, router).await;
        });
        let base = format!("http://{}", address.recv().unwrap());
        FakeKeys { base, seen, reply }
    }

    fn url(&self) -> String {
        format!("{}/jwks", self.base)
    }

    fn now_serves(&self, reply: KeysReply) {
        *self.reply.lock().unwrap() = reply;
    }

    fn requests(&self) -> Vec<SeenFetch> {
        self.seen.lock().unwrap().clone()
    }
}

async fn keys_answer(
    axum::extract::State((seen, reply)): axum::extract::State<KeysState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    seen.lock().unwrap().push(SeenFetch {
        method,
        uri,
        headers,
        body,
    });
    let reply = reply.lock().unwrap().clone();
    match reply {
        KeysReply::Answer {
            status,
            media,
            encoding,
            body,
        } => {
            let mut response = axum::response::Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, media);
            if let Some(encoding) = encoding {
                response = response.header(header::CONTENT_ENCODING, encoding);
            }
            response.body(Body::from(body)).unwrap()
        }
        KeysReply::Redirect => axum::response::Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/elsewhere")
            .body(Body::empty())
            .unwrap(),
    }
}

async fn keys_elsewhere(
    axum::extract::State((seen, _)): axum::extract::State<KeysState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    seen.lock().unwrap().push(SeenFetch {
        method,
        uri,
        headers,
        body,
    });
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"keys":[{"kid":"elsewhere"}]}"#))
        .unwrap()
}

// ─── settings ────────────────────────────────────────────────────────────────

/// `token_url` defaults to Telegram's endpoint.
#[test]
fn token_url_defaults_to_telegrams_endpoint() {
    let table = Table {
        token_url: None,
        jwks_url: None,
    };
    let (settings, _secret) = settings(&table).expect("the table parses");
    assert_eq!(
        settings.telegram.unwrap().token_url,
        "https://oauth.telegram.org/token"
    );
}

/// A table naming `jwks_url` parses, and one naming none starts a deployment
/// that serves the key route anyway (from the default).
#[test]
fn jwks_url_is_a_telegram_setting() {
    // Depends on the spec's `jwks_url` setting in the `[telegram]` table.
    let (settings, _secret) = settings(&Table::keys(
        "https://oauth.telegram.org/.well-known/jwks.json",
    ))
    .expect("jwks_url is a [telegram] setting");
    assert!(Bridge::start(&settings).is_ok());
}

/// The secret file's contents never appear in a startup refusal, in the
/// rendered settings or in the rendered deployment.
#[test]
fn the_secret_never_appears_in_debug_output_or_a_startup_refusal() {
    let (settings_ok, _secret) =
        settings(&Table::token("https://oauth.telegram.org/token")).unwrap();
    assert!(!format!("{settings_ok:?}").contains(TELEGRAM_SECRET));
    let deployment = libid_bridge_rs::deployment::Deployment::checked(&settings_ok)
        .expect("it checks");
    let rendered = format!("{:?}", deployment.telegram);
    assert!(rendered.contains(TELEGRAM_CLIENT_ID), "{rendered}");
    assert!(!rendered.contains(TELEGRAM_SECRET), "{rendered}");

    // A secret the startup refuses: the refusal names the file, not the value.
    for bad in [
        format!("{TELEGRAM_SECRET} trailing"),
        format!("{TELEGRAM_SECRET}\n\n"),
        format!("{TELEGRAM_SECRET}\u{0}"),
        format!("{TELEGRAM_SECRET}\u{e9}"),
    ] {
        let (settings, _secret) =
            settings_with_secret(&Table::token("https://oauth.telegram.org/token"), &bad)
                .unwrap();
        let refused = Bridge::start(&settings).err().expect("refused");
        assert!(!refused.to_string().contains(TELEGRAM_SECRET), "{refused}");
        assert!(!format!("{refused:?}").contains(TELEGRAM_SECRET));
    }
}

/// `/config` publishes Telegram's entry as exactly `{"clientId"}`.
#[tokio::test]
async fn config_publishes_telegram_as_its_client_id_only() {
    let app = app(&Table::token("https://oauth.telegram.org/token"));
    let answer = send(
        &app,
        Request::get("/api/v1/ceremony/config")
            .header("origin", APP)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        answer.json()["platforms"]["telegram"],
        serde_json::json!({ "clientId": TELEGRAM_CLIENT_ID })
    );
    let text = String::from_utf8_lossy(&answer.body);
    for absent in [TELEGRAM_REDIRECT_URI, "token_url", "jwks", "secret"] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }
}

// ─── route A: the code swap ──────────────────────────────────────────────────

/// The swap posts exactly the five form fields, `redirect_uri` the client's
/// `redirectUri` unchanged (delimiters percent-encoded), and authenticates
/// with HTTP Basic; the secret is not in the form.
#[tokio::test]
async fn the_swap_posts_the_exact_form_with_basic_authentication() {
    const REDIRECT: &str = "https://bridge.example/auth/callback?a=b&c=%41+d#f";
    let fake = FakeTelegram::serving(TokenReply::with(200, r#"{"id_token":"x"}"#));
    let app = app(&Table::token(fake.url()));
    let answer = send(
        &app,
        swap(Some(APP), swap_body_to(CODE, VERIFIER, REDIRECT)),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK);

    let seen = fake.requests();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, Method::POST);
    assert_eq!(
        request.headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .trim(),
        "application/x-www-form-urlencoded"
    );
    assert!(
        !String::from_utf8_lossy(&request.body).contains(TELEGRAM_SECRET),
        "the secret is in the form body"
    );
    let mut fields = form(&request.body);
    fields.sort();
    let mut expected = vec![
        ("client_id".to_owned(), TELEGRAM_CLIENT_ID.to_owned()),
        ("code".to_owned(), CODE.to_owned()),
        ("code_verifier".to_owned(), VERIFIER.to_owned()),
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("redirect_uri".to_owned(), REDIRECT.to_owned()),
    ];
    expected.sort();
    assert_eq!(fields, expected);
    assert_eq!(
        request
            .headers
            .get(header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap()),
        Some(BASIC)
    );
}

/// Telegram's status and body bytes reach the caller unchanged, as JSON,
/// under the CORS of `/config`.
#[tokio::test]
async fn the_swap_answers_telegrams_status_and_bytes_unchanged() {
    for (status, body) in [
        (
            200u16,
            "{\"id_token\" : \"e30.e30.sig\",\n  \"token_type\":\"Bearer\"}",
        ),
        (
            400,
            r#"{"error":"invalid_grant","error_description":"code é"}"#,
        ),
        (401, r#"{"error":"invalid_client"}"#),
    ] {
        let fake = FakeTelegram::serving(TokenReply::with(status, body));
        let app = app(&Table::token(fake.url()));
        let answer = send(&app, swap(Some(APP), swap_body(CODE, VERIFIER))).await;
        assert_eq!(answer.status.as_u16(), status);
        assert_eq!(&answer.body[..], body.as_bytes());
        assert!(answer
            .header("content-type")
            .unwrap()
            .starts_with("application/json"));
        assert_eq!(answer.header("access-control-allow-origin"), Some(APP));
        assert!(answer.header("access-control-allow-credentials").is_none());
        assert_vary(&answer);
    }
}

/// A foreign, opaque, near-miss or absent origin is refused before anything
/// is sent upstream, with no allow-origin header.
#[tokio::test]
async fn the_swap_refuses_a_foreign_origin_and_sends_nothing() {
    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = app(&Table::token(fake.url()));
    for origin in [
        Some("https://evil.example"),
        Some("null"),
        Some("https://APP.example"),
        Some("https://app.example/"),
        Some("http://app.example"),
        None,
    ] {
        let answer = send(&app, swap(origin, swap_body(CODE, VERIFIER))).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{origin:?}");
        assert!(answer.header("access-control-allow-origin").is_none());
        assert_vary(&answer);
    }
    assert!(fake.requests().is_empty(), "something was sent upstream");
}

/// The body is exactly `{"code","codeVerifier","redirectUri"}`: any other
/// field is refused and nothing is sent.
#[tokio::test]
async fn the_swap_refuses_any_other_field() {
    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = app(&Table::token(fake.url()));
    for extra in [
        ("redirect_uri", "https://evil.example/auth/callback"),
        ("client_id", "1"),
        ("clientSecret", "x"),
        ("grant_type", "refresh_token"),
    ] {
        let mut body = serde_json::json!({
            "code": CODE,
            "codeVerifier": VERIFIER,
            "redirectUri": TELEGRAM_REDIRECT_URI,
        });
        body[extra.0] = serde_json::Value::from(extra.1);
        let answer = send(&app, swap(Some(APP), body.to_string())).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{extra:?}");
        assert_eq!(answer.header("access-control-allow-origin"), Some(APP));
    }
    assert!(fake.requests().is_empty());
}

/// Malformed JSON, the wrong shape, and the wrong media type are refused and
/// nothing is sent.
#[tokio::test]
async fn the_swap_refuses_a_malformed_body_or_media_type() {
    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = app(&Table::token(fake.url()));
    for body in [
        "",
        "not json",
        "{",
        "[]",
        "null",
        r#"{"code":"abc"}"#,
        // No redirectUri.
        r#"{"code":"abc","codeVerifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}"#,
        r#"{"code":"abc","codeVerifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk","redirectUri":null}"#,
        r#"{"code":"abc","codeVerifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk","redirectUri":7}"#,
        r#"{"codeVerifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}"#,
        r#"{"code":1,"codeVerifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}"#,
        r#"{"code":"a","code":"b","codeVerifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}"#,
        r#"{"code":"abc","codeVerifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"} trailing"#,
    ] {
        let answer = send(&app, swap(Some(APP), body)).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body:?}");
    }

    for media in [
        None,
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
    ] {
        let mut request = Request::post(TOKEN_PATH).header("origin", APP);
        if let Some(media) = media {
            request = request.header("content-type", media);
        }
        let answer = send(
            &app,
            request.body(Body::from(swap_body(CODE, VERIFIER))).unwrap(),
        )
        .await;
        assert!(
            answer.status == StatusCode::BAD_REQUEST
                || answer.status == StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{media:?}: {}",
            answer.status
        );
    }
    assert!(fake.requests().is_empty());
}

/// An oversize body is refused before it is sent anywhere.
#[tokio::test]
async fn the_swap_refuses_an_oversize_body() {
    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = app(&Table::token(fake.url()));
    let body = swap_body(&"a".repeat(64 * 1024), VERIFIER);
    let answer = send(&app, swap(Some(APP), body)).await;
    assert!(
        answer.status == StatusCode::BAD_REQUEST
            || answer.status == StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        answer.status
    );
    assert!(fake.requests().is_empty());
}

/// A query string is refused after the origin is decided, and nothing is sent.
#[tokio::test]
async fn the_swap_refuses_a_query_but_reads_the_origin_first() {
    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = app(&Table::token(fake.url()));
    for (origin, status) in [
        (APP, StatusCode::BAD_REQUEST),
        ("https://evil.example", StatusCode::FORBIDDEN),
    ] {
        let request =
            Request::post(format!("{TOKEN_PATH}?redirect_uri=https://evil.example"))
                .header("origin", origin)
                .header("content-type", "application/json")
                .body(Body::from(swap_body(CODE, VERIFIER)))
                .unwrap();
        assert_eq!(send(&app, request).await.status, status, "{origin}");
    }
    assert!(fake.requests().is_empty());
}

/// The verifier is RFC 7636's: 43 to 128 of `ALPHA DIGIT - . _ ~`.
#[tokio::test]
async fn the_swap_holds_the_verifier_to_rfc_7636() {
    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = app(&Table::token(fake.url()));
    let refused = [
        "a".repeat(42),
        "a".repeat(129),
        String::new(),
        format!("{}+", "a".repeat(42)),
        format!("{}/", "a".repeat(42)),
        format!("{}=", "a".repeat(42)),
        format!("{} ", "a".repeat(42)),
        format!("{}&", "a".repeat(42)),
        format!("{}\u{e9}", "a".repeat(42)),
        format!("{}\u{0}", "a".repeat(42)),
    ];
    for verifier in &refused {
        let answer = send(&app, swap(Some(APP), swap_body(CODE, verifier))).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{verifier:?}");
    }
    assert!(fake.requests().is_empty(), "a refused verifier was sent");

    let admitted = [
        "a".repeat(43),
        "Z9".repeat(64),
        format!("{}-._~", "a".repeat(39)),
    ];
    for verifier in &admitted {
        let answer = send(&app, swap(Some(APP), swap_body(CODE, verifier))).await;
        assert_eq!(answer.status, StatusCode::OK, "{verifier:?}");
    }
    let sent: Vec<String> = fake
        .requests()
        .iter()
        .map(|r| {
            form(&r.body)
                .into_iter()
                .find(|(k, _)| k == "code_verifier")
                .unwrap()
                .1
        })
        .collect();
    assert_eq!(sent, admitted);
}

/// `redirectUri` is printable ASCII without spaces, at most 512 bytes; the
/// Bridge applies no scheme or path rule to it (Telegram does) and forwards
/// it as written.
#[tokio::test]
async fn the_swap_holds_the_redirect_uri_to_basic_hygiene_only() {
    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = app(&Table::token(fake.url()));
    let base = "https://bridge.example/auth/callback?p=";
    let refused = [
        format!("{base}{}", "a".repeat(513 - base.len())),
        format!("{base}a b"),
        format!("{base}a\tb"),
        format!("{base}a\nb"),
        format!("{base}a\u{0}b"),
        format!("{base}a\u{7f}b"),
        format!("{base}\u{e9}"),
    ];
    for redirect in &refused {
        let answer = send(
            &app,
            swap(Some(APP), swap_body_to(CODE, VERIFIER, redirect)),
        )
        .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{redirect:?}");
    }
    assert!(fake.requests().is_empty(), "a refused redirectUri was sent");

    let admitted = [
        format!("{base}{}", "a".repeat(512 - base.len())),
        "http://evil.example/not-a-callback".to_owned(),
        "x".to_owned(),
        "https://bridge.example/auth/callback?a=b&redirect_uri=https%3A%2F%2Fevil"
            .to_owned(),
    ];
    for redirect in &admitted {
        let answer = send(
            &app,
            swap(Some(APP), swap_body_to(CODE, VERIFIER, redirect)),
        )
        .await;
        assert_eq!(answer.status, StatusCode::OK, "{redirect:?}");
    }
    let sent: Vec<Vec<String>> = fake
        .requests()
        .iter()
        .map(|r| {
            form(&r.body)
                .into_iter()
                .filter(|(k, _)| k == "redirect_uri")
                .map(|(_, v)| v)
                .collect()
        })
        .collect();
    let expected: Vec<Vec<String>> = admitted.iter().map(|r| vec![r.clone()]).collect();
    assert_eq!(sent, expected);
}

/// A code carrying form delimiters cannot add or override a field: either it
/// is refused, or it reaches Telegram as one `code` value, byte for byte.
#[tokio::test]
async fn a_code_cannot_stretch_past_its_form_field() {
    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = app(&Table::token(fake.url()));
    let code = "abc&client_id=1&redirect_uri=https%3A%2F%2Fevil.example&code_verifier=x";
    let answer = send(&app, swap(Some(APP), swap_body(code, VERIFIER))).await;
    let seen = fake.requests();
    match answer.status {
        StatusCode::BAD_REQUEST => assert!(seen.is_empty()),
        StatusCode::OK => {
            let fields = form(&seen[0].body);
            for key in [
                "client_id",
                "code",
                "code_verifier",
                "redirect_uri",
                "grant_type",
            ] {
                assert_eq!(
                    fields.iter().filter(|(k, _)| k == key).count(),
                    1,
                    "{key}: {fields:?}"
                );
            }
            let get =
                |key: &str| fields.iter().find(|(k, _)| k == key).unwrap().1.clone();
            assert_eq!(get("code"), code);
            assert_eq!(get("redirect_uri"), TELEGRAM_REDIRECT_URI);
            assert_eq!(get("client_id"), TELEGRAM_CLIENT_ID);
            assert_eq!(get("code_verifier"), VERIFIER);
        }
        other => panic!("{other}"),
    }
}

/// A redirect from Telegram is not followed and is answered `502`.
#[tokio::test]
async fn the_swap_answers_502_for_a_redirect() {
    let fake = FakeTelegram::serving(TokenReply::with(302, r#"{"moved":true}"#));
    let app = app(&Table::token(fake.url()));
    let answer = send(&app, swap(Some(APP), swap_body(CODE, VERIFIER))).await;
    answer.assert_bare_502(&["elsewhere", "moved", "302"]);
    assert_eq!(answer.header("access-control-allow-origin"), Some(APP));
    assert_eq!(fake.requests().len(), 1);
}

/// A reply of 8 KiB passes; one byte more is a `502`.
#[tokio::test]
async fn the_swap_bounds_telegrams_reply_at_8_kib() {
    let at_limit = json_of_len(8 * 1024);
    let fake = FakeTelegram::serving(TokenReply::with(200, &at_limit));
    let app = app(&Table::token(fake.url()));
    let answer = send(&app, swap(Some(APP), swap_body(CODE, VERIFIER))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(&answer.body[..], at_limit.as_bytes());

    fake.now_serves(TokenReply::with(200, &json_of_len(8 * 1024 + 1)));
    let answer = send(&app, swap(Some(APP), swap_body(CODE, VERIFIER))).await;
    answer.assert_bare_502(&["aaaa"]);
}

/// A token endpoint nothing answers on is a `502` naming nothing of it.
#[tokio::test]
async fn the_swap_answers_502_when_telegram_is_unreachable() {
    let origin = common::unreachable_origin().await;
    let port = origin.rsplit(':').next().unwrap().to_owned();
    let app = app(&Table::token(&format!("{origin}/token")));
    let answer = send(&app, swap(Some(APP), swap_body(CODE, VERIFIER))).await;
    answer.assert_bare_502(&["127.0.0.1", &port, "refused", "/token"]);
    assert_eq!(answer.header("access-control-allow-origin"), Some(APP));
}

/// A token endpoint that never answers is a `502` within the swap's bound.
#[tokio::test]
async fn the_swap_answers_502_when_telegram_times_out() {
    let fake = FakeTelegram::serving(TokenReply::Silent);
    let (settings, _secret) = settings(&Table::token(fake.url())).unwrap();
    let bridge = Bridge::start_with(&settings, Duration::from_millis(300)).unwrap();
    let app = routes::build_router(bridge.state);
    let answer = tokio::time::timeout(
        Duration::from_secs(5),
        send(&app, swap(Some(APP), swap_body(CODE, VERIFIER))),
    )
    .await
    .expect("the swap is bounded");
    answer.assert_bare_502(&["127.0.0.1", "timed out", "elapsed"]);
}

/// The preflight of an admitted origin grants `POST` with `content-type` and
/// no credentials; a foreign origin's preflight is refused.
#[tokio::test]
async fn the_swap_answers_the_preflight_of_an_admitted_origin_only() {
    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = app(&Table::token(fake.url()));
    let preflight = |origin: &str| {
        Request::builder()
            .method("OPTIONS")
            .uri(TOKEN_PATH)
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .body(Body::empty())
            .unwrap()
    };
    let answer = send(&app, preflight(APP)).await;
    assert!(answer.status.is_success(), "{}", answer.status);
    assert_eq!(answer.header("access-control-allow-origin"), Some(APP));
    assert!(answer
        .header("access-control-allow-methods")
        .unwrap()
        .contains("POST"));
    assert!(answer
        .header("access-control-allow-headers")
        .unwrap()
        .to_ascii_lowercase()
        .contains("content-type"));
    assert!(answer.header("access-control-allow-credentials").is_none());

    for origin in ["https://evil.example", "null"] {
        let answer = send(&app, preflight(origin)).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{origin}");
        assert!(answer.header("access-control-allow-origin").is_none());
        assert!(answer.header("access-control-allow-methods").is_none());
    }
    assert!(fake.requests().is_empty());
}

/// Every other method is a `405` naming `POST` and `OPTIONS`.
#[tokio::test]
async fn the_swap_admits_only_post_and_its_preflight() {
    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = app(&Table::token(fake.url()));
    for method in ["GET", "HEAD", "PUT", "DELETE", "PATCH"] {
        let request = Request::builder()
            .method(method)
            .uri(TOKEN_PATH)
            .header("origin", APP)
            .body(Body::empty())
            .unwrap();
        let answer = send(&app, request).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(
            allow_set(&answer),
            BTreeSet::from(["POST".to_owned(), "OPTIONS".to_owned()]),
            "{method}"
        );
    }
    assert!(fake.requests().is_empty());
}

// ─── route B: the key list ───────────────────────────────────────────────────

/// The key list reaches the caller byte for byte under Telegram's own media
/// type, with the CORS of `/config`.
#[tokio::test]
async fn the_key_list_passes_through_unparsed() {
    // Not canonical JSON, and not even valid JSON: the route must not parse.
    let body: &[u8] = b"{ \"keys\" :[ {\"kid\":\"oidc-1\"} ] ,\n\"x\":1e400 }\xff";
    let fake =
        FakeKeys::serving(KeysReply::ok("application/jwk-set+json", body.to_vec()));
    let app = keys_app(&fake.url());
    let answer = send(&app, get_keys(Some(APP))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(&answer.body[..], body);
    assert_eq!(
        answer.header("content-type"),
        Some("application/jwk-set+json")
    );
    assert_eq!(answer.header("access-control-allow-origin"), Some(APP));
    assert!(answer.header("access-control-allow-credentials").is_none());
    assert_vary(&answer);
}

/// A gzip body with `Content-Encoding: gzip` reaches the caller unchanged,
/// still labelled gzip.
#[tokio::test]
async fn the_key_list_keeps_its_content_encoding() {
    let fake = FakeKeys::serving(KeysReply::Answer {
        status: StatusCode::OK,
        media: "application/json",
        encoding: Some("gzip"),
        body: Bytes::from_static(GZIPPED_KEYS),
    });
    let app = keys_app(&fake.url());
    let answer = send(&app, get_keys(Some(APP))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(&answer.body[..], GZIPPED_KEYS);
    assert_eq!(answer.header("content-encoding"), Some("gzip"));
    assert_eq!(answer.header("content-type"), Some("application/json"));
}

/// Two reads in a row cost one fetch, and answer the same bytes.
#[tokio::test]
async fn the_key_list_is_cached() {
    let fake = FakeKeys::serving(KeysReply::ok("application/json", r#"{"keys":[]}"#));
    let app = keys_app(&fake.url());
    let first = send(&app, get_keys(Some(APP))).await;
    fake.now_serves(KeysReply::ok("application/json", r#"{"keys":["changed"]}"#));
    let second = send(&app, get_keys(Some(APP))).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(first.body, second.body);
    assert_eq!(&second.body[..], br#"{"keys":[]}"#);
    assert_eq!(fake.requests().len(), 1, "one upstream fetch");
}

/// A failed fetch is not cached: the next read fetches again.
#[tokio::test]
async fn a_failed_key_fetch_is_not_cached() {
    let fake = FakeKeys::serving(KeysReply::Answer {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        media: "text/plain",
        encoding: None,
        body: Bytes::from_static(b"upstream says no"),
    });
    let app = keys_app(&fake.url());
    let first = send(&app, get_keys(Some(APP))).await;
    first.assert_bare_502(&["upstream says no", "500"]);
    fake.now_serves(KeysReply::ok("application/json", r#"{"keys":[]}"#));
    let second = send(&app, get_keys(Some(APP))).await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(fake.requests().len(), 2);
}

/// With nothing cached, an unreachable key list is a `502` naming nothing of
/// it.
#[tokio::test]
async fn the_key_list_answers_502_when_unreachable_and_uncached() {
    let origin = common::unreachable_origin().await;
    let port = origin.rsplit(':').next().unwrap().to_owned();
    let app = keys_app(&format!("{origin}/jwks"));
    let answer = send(&app, get_keys(Some(APP))).await;
    answer.assert_bare_502(&["127.0.0.1", &port, "refused"]);
    assert_eq!(answer.header("access-control-allow-origin"), Some(APP));
}

/// A key list of 64 KiB passes; one byte more is a `502`.
#[tokio::test]
async fn the_key_list_is_bounded_at_64_kib() {
    let at_limit = json_of_len(64 * 1024);
    let fake = FakeKeys::serving(KeysReply::ok("application/json", at_limit.clone()));
    let answer = send(&keys_app(&fake.url()), get_keys(Some(APP))).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.body.len(), 64 * 1024);

    let over = FakeKeys::serving(KeysReply::ok(
        "application/json",
        json_of_len(64 * 1024 + 1),
    ));
    let answer = send(&keys_app(&over.url()), get_keys(Some(APP))).await;
    answer.assert_bare_502(&["aaaa"]);
}

/// A redirect is not followed: `502`, and the target is never fetched.
#[tokio::test]
async fn the_key_list_does_not_follow_a_redirect() {
    let fake = FakeKeys::serving(KeysReply::Redirect);
    let app = keys_app(&fake.url());
    let answer = send(&app, get_keys(Some(APP))).await;
    answer.assert_bare_502(&["elsewhere"]);
    let paths: Vec<String> = fake
        .requests()
        .iter()
        .map(|r| r.uri.path().to_owned())
        .collect();
    assert_eq!(paths, ["/jwks"]);
}

/// The fetch carries no `Authorization` and nothing of the secret.
#[tokio::test]
async fn the_key_fetch_sends_no_credential() {
    let fake = FakeKeys::serving(KeysReply::ok("application/json", r#"{"keys":[]}"#));
    let app = keys_app(&fake.url());
    assert_eq!(send(&app, get_keys(Some(APP))).await.status, StatusCode::OK);
    let seen = fake.requests();
    assert_eq!(seen.len(), 1);
    let fetch = &seen[0];
    assert_eq!(fetch.method, Method::GET);
    assert!(fetch.headers.get(header::AUTHORIZATION).is_none());
    assert!(fetch.headers.get(header::COOKIE).is_none());
    assert!(fetch.body.is_empty());
    for part in [format!("{:?}", fetch.headers), fetch.uri.to_string()] {
        assert!(!part.contains(TELEGRAM_SECRET), "{part}");
        assert!(!part.contains(&BASIC[6..]), "{part}");
        assert!(!part.contains(TELEGRAM_CLIENT_ID), "{part}");
    }
}

/// A foreign origin is refused with no allow-origin header and no keys; a
/// same-origin read is admitted as `/config` admits one.
#[tokio::test]
async fn the_key_list_admits_as_config_does() {
    let fake = FakeKeys::serving(KeysReply::ok("application/json", r#"{"keys":["k"]}"#));
    let app = keys_app(&fake.url());
    for origin in [Some("https://evil.example"), Some("null"), None] {
        let answer = send(&app, get_keys(origin)).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{origin:?}");
        assert!(answer.header("access-control-allow-origin").is_none());
        assert!(!String::from_utf8_lossy(&answer.body).contains("\"k\""));
        assert_vary(&answer);
    }

    let same_origin = Request::get(JWKS_PATH)
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap();
    let answer = send(&app, same_origin).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert!(answer.header("access-control-allow-origin").is_none());
    assert_eq!(&answer.body[..], br#"{"keys":["k"]}"#);
}

/// A query string is refused after the origin is decided, and nothing is
/// fetched for it.
#[tokio::test]
async fn the_key_list_refuses_a_query_but_reads_the_origin_first() {
    let fake = FakeKeys::serving(KeysReply::ok("application/json", r#"{"keys":[]}"#));
    let app = keys_app(&fake.url());
    for (origin, status) in [
        (APP, StatusCode::BAD_REQUEST),
        ("https://evil.example", StatusCode::FORBIDDEN),
    ] {
        let request = Request::get(format!("{JWKS_PATH}?kid=oidc-1"))
            .header("origin", origin)
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&app, request).await.status, status, "{origin}");
    }
    assert!(fake.requests().is_empty());
}

/// The preflight of an admitted origin grants `GET`; a foreign one is refused.
#[tokio::test]
async fn the_key_list_answers_the_preflight_of_an_admitted_origin_only() {
    let fake = FakeKeys::serving(KeysReply::ok("application/json", r#"{"keys":[]}"#));
    let app = keys_app(&fake.url());
    let preflight = |origin: &str| {
        Request::builder()
            .method("OPTIONS")
            .uri(JWKS_PATH)
            .header("origin", origin)
            .header("access-control-request-method", "GET")
            .body(Body::empty())
            .unwrap()
    };
    let answer = send(&app, preflight(APP)).await;
    assert!(answer.status.is_success(), "{}", answer.status);
    assert_eq!(answer.header("access-control-allow-origin"), Some(APP));
    assert!(answer
        .header("access-control-allow-methods")
        .unwrap()
        .contains("GET"));
    assert!(answer.header("access-control-allow-credentials").is_none());

    let answer = send(&app, preflight("https://evil.example")).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert!(answer.header("access-control-allow-origin").is_none());
    assert!(fake.requests().is_empty());
}

/// Every method but `GET` and its preflight is a `405`.
#[tokio::test]
async fn the_key_list_admits_only_get_and_its_preflight() {
    let fake = FakeKeys::serving(KeysReply::ok("application/json", r#"{"keys":[]}"#));
    let app = keys_app(&fake.url());
    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        let request = Request::builder()
            .method(method)
            .uri(JWKS_PATH)
            .header("origin", APP)
            .body(Body::empty())
            .unwrap();
        let answer = send(&app, request).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        let allowed = allow_set(&answer);
        assert!(allowed.contains("GET"), "{method}: {allowed:?}");
        assert!(allowed.contains("OPTIONS"), "{method}: {allowed:?}");
        assert!(!allowed.contains(method), "{method}: {allowed:?}");
    }
    assert!(fake.requests().is_empty());
}

// ─── both routes ─────────────────────────────────────────────────────────────

/// Without Telegram, both paths answer as a path this bridge does not serve.
#[tokio::test]
async fn neither_route_exists_without_telegram() {
    let state = common::state(&[]).await;
    let app = routes::build_router(state);
    let unknown = send(
        &app,
        Request::get("/api/v1/ceremony/not-a-route")
            .header("origin", APP)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    for (method, path) in [
        ("POST", TOKEN_PATH),
        ("OPTIONS", TOKEN_PATH),
        ("GET", JWKS_PATH),
        ("OPTIONS", JWKS_PATH),
    ] {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("origin", APP);
        if method == "OPTIONS" {
            request = request.header("access-control-request-method", "POST");
        } else if method == "POST" {
            request = request.header("content-type", "application/json");
        }
        let body = if method == "POST" {
            Body::from(swap_body(CODE, VERIFIER))
        } else {
            Body::empty()
        };
        let answer = send(&app, request.body(body).unwrap()).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(answer.body, unknown.body, "{method} {path}");
        assert!(answer.header("access-control-allow-origin").is_none());
        assert!(answer.header("access-control-allow-methods").is_none());
    }
}
