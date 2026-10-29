//! Telegram's code swap over the axum router, against a fake token endpoint:
//! the form it sends, the answer it passes on, what it refuses, and that the
//! private secret leaves only in the `Authorization` header.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

use std::{
    sync::Arc,
    time::Duration,
};

use axum::{
    body::Body,
    http::{
        header,
        Request,
        StatusCode,
    },
    response::Response,
};
use common::{
    telegram_config,
    FakeTelegram,
    TokenReply,
    TELEGRAM_REDIRECT_URI,
    TELEGRAM_SECRET,
};
use http_body_util::BodyExt;
use libid_bridge_rs::{
    routes,
    state::AppState,
    Bridge,
};
use tower::ServiceExt;

const PATH: &str = "/api/v1/ceremony/telegram/token";
const APP_ORIGIN: &str = "https://app.example";
const CODE: &str = "6b7f2c1d9e4a8035";
const VERIFIER: &str = "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I";
const TOKENS: &str = r#"{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":"eyJ.eyJ.sig"}"#;

/// A deployment swapping at `fake`, each swap bounded by `timeout`.
fn state_with(fake: &FakeTelegram, timeout: Duration) -> Arc<AppState> {
    let (settings, _secret) = telegram_config(fake.url());
    Bridge::start_with(&settings, timeout)
        .expect("a deployment enabling telegram")
        .state
}

fn state(fake: &FakeTelegram) -> Arc<AppState> {
    state_with(fake, Duration::from_secs(10))
}

fn swap_body() -> String {
    body_of(CODE, VERIFIER, TELEGRAM_REDIRECT_URI)
}

fn body_of(code: &str, verifier: &str, redirect_uri: &str) -> String {
    serde_json::json!({ "code": code, "codeVerifier": verifier, "redirectUri": redirect_uri })
        .to_string()
}

fn post(
    origin: Option<&str>,
    uri: &str,
    media: &str,
    body: impl Into<Body>,
) -> Request<Body> {
    let mut request = Request::post(uri).header(header::CONTENT_TYPE, media);
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    request.body(body.into()).unwrap()
}

async fn send(state: Arc<AppState>, request: Request<Body>) -> Response {
    routes::build_router(state).oneshot(request).await.unwrap()
}

async fn bytes_of(response: Response) -> bytes::Bytes {
    response.into_body().collect().await.unwrap().to_bytes()
}

/// Every header value and the body of `response`, as one string to search.
async fn everything_in(response: Response) -> String {
    let mut text = format!("{:?}", response.headers());
    text.push_str(&String::from_utf8_lossy(&bytes_of(response).await));
    text
}

#[tokio::test]
async fn a_swap_sends_the_exact_form_and_passes_the_answer_through() {
    let fake = FakeTelegram::serving(TokenReply::with(200, TOKENS));
    let response = send(
        state(&fake),
        post(Some(APP_ORIGIN), PATH, "application/json", swap_body()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let h = response.headers().clone();
    assert_eq!(h["access-control-allow-origin"], APP_ORIGIN);
    assert!(h.get("access-control-allow-credentials").is_none());
    assert_eq!(h["content-type"], "application/json");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["vary"], "origin, sec-fetch-site");
    assert_eq!(&bytes_of(response).await[..], TOKENS.as_bytes());

    let seen = fake.requests();
    assert_eq!(seen.len(), 1);
    let swap = &seen[0];
    assert_eq!(swap.method, "POST");
    assert_eq!(
        swap.headers["content-type"],
        "application/x-www-form-urlencoded"
    );
    assert_eq!(swap.headers["accept"], "application/json");
    assert_eq!(
        std::str::from_utf8(&swap.body).unwrap(),
        "grant_type=authorization_code\
         &code=6b7f2c1d9e4a8035\
         &redirect_uri=https%3A%2F%2Fbridge.example%2Fauth%2Fcallback\
         &code_verifier=iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I\
         &client_id=8123456789"
    );
    // `base64("8123456789:SECRET-MARKER-7f3a")`, from coreutils.
    assert_eq!(
        swap.headers["authorization"],
        "Basic ODEyMzQ1Njc4OTpTRUNSRVQtTUFSS0VSLTdmM2E="
    );
}

#[tokio::test]
async fn a_refusal_from_telegram_is_passed_through_with_its_status() {
    let fake =
        FakeTelegram::serving(TokenReply::with(400, r#"{"error":"invalid_grant"}"#));
    let response = send(
        state(&fake),
        post(Some(APP_ORIGIN), PATH, "application/json", swap_body()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        APP_ORIGIN
    );
    assert_eq!(
        &bytes_of(response).await[..],
        br#"{"error":"invalid_grant"}"#
    );
}

/// A same-origin request carrying no `Origin` swaps, and gets no CORS header.
#[tokio::test]
async fn a_same_origin_swap_needs_no_cors_header() {
    let fake = FakeTelegram::serving(TokenReply::with(200, TOKENS));
    let mut request = post(None, PATH, "application/json", swap_body());
    request
        .headers_mut()
        .insert("sec-fetch-site", "same-origin".parse().unwrap());
    let response = send(state(&fake), request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
    assert_eq!(&bytes_of(response).await[..], TOKENS.as_bytes());
}

#[tokio::test]
async fn a_foreign_origin_is_refused_before_anything_is_sent() {
    let fake = FakeTelegram::serving(TokenReply::with(200, TOKENS));
    for origin in [Some("https://evil.example"), Some("null"), None] {
        let response = send(
            state(&fake),
            post(origin, PATH, "application/json", swap_body()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{origin:?}");
        assert!(response
            .headers()
            .get("access-control-allow-origin")
            .is_none());
    }
    assert!(fake.requests().is_empty());
}

#[tokio::test]
async fn a_preflight_grants_post_with_a_content_type_to_an_admitted_origin() {
    let fake = FakeTelegram::serving(TokenReply::with(200, TOKENS));
    let preflight = |origin: &str| {
        Request::builder()
            .method("OPTIONS")
            .uri(PATH)
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .body(Body::empty())
            .unwrap()
    };

    let response = send(state(&fake), preflight(APP_ORIGIN)).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let h = response.headers();
    assert_eq!(h["access-control-allow-origin"], APP_ORIGIN);
    assert_eq!(h["access-control-allow-methods"], "POST, OPTIONS");
    assert_eq!(h["access-control-allow-headers"], "content-type");
    assert!(h.get("access-control-allow-credentials").is_none());

    let response = send(state(&fake), preflight("https://evil.example")).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
}

#[tokio::test]
async fn another_method_is_refused_naming_the_ones_served() {
    let fake = FakeTelegram::serving(TokenReply::with(200, TOKENS));
    for method in ["GET", "HEAD", "PUT"] {
        let request = Request::builder()
            .method(method)
            .uri(PATH)
            .header("origin", APP_ORIGIN)
            .body(Body::empty())
            .unwrap();
        let response = send(state(&fake), request).await;
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method}"
        );
        assert_eq!(response.headers()["allow"], "POST, OPTIONS");
    }
}

#[tokio::test]
async fn a_malformed_request_is_refused_and_nothing_is_sent() {
    let fake = FakeTelegram::serving(TokenReply::with(200, TOKENS));
    let json = "application/json";
    let cases: Vec<(String, &str, String)> = vec![
        (format!("{PATH}?code={CODE}"), json, swap_body()),
        (PATH.into(), "text/plain", swap_body()),
        (PATH.into(), json, "{not json".into()),
        (PATH.into(), json, format!(r#"{{"code":"{CODE}"}}"#)),
        (
            PATH.into(),
            json,
            format!(r#"{{"code":"{CODE}","codeVerifier":"{VERIFIER}"}}"#),
        ),
        (
            PATH.into(),
            json,
            format!(
                r#"{{"code":"{CODE}","codeVerifier":"{VERIFIER}","redirectUri":"x","clientSecret":"s"}}"#
            ),
        ),
        (
            PATH.into(),
            json,
            body_of("", VERIFIER, TELEGRAM_REDIRECT_URI),
        ),
        (
            PATH.into(),
            json,
            body_of("a b", VERIFIER, TELEGRAM_REDIRECT_URI),
        ),
        (
            PATH.into(),
            json,
            body_of(&"c".repeat(513), VERIFIER, TELEGRAM_REDIRECT_URI),
        ),
        // Too short, too long, and outside the unreserved set.
        (
            PATH.into(),
            json,
            body_of(CODE, &"v".repeat(42), TELEGRAM_REDIRECT_URI),
        ),
        (
            PATH.into(),
            json,
            body_of(CODE, &"v".repeat(129), TELEGRAM_REDIRECT_URI),
        ),
        (
            PATH.into(),
            json,
            body_of(CODE, &format!("{}+", "v".repeat(42)), TELEGRAM_REDIRECT_URI),
        ),
        // An empty, spaced or oversized redirect URI.
        (PATH.into(), json, body_of(CODE, VERIFIER, "")),
        (
            PATH.into(),
            json,
            body_of(CODE, VERIFIER, "https://a.example/ b"),
        ),
        (PATH.into(), json, body_of(CODE, VERIFIER, &"r".repeat(513))),
        // A valid swap padded past the body cap.
        (
            PATH.into(),
            json,
            format!(
                r#"{{"code":"{CODE}","codeVerifier":"{VERIFIER}","redirectUri":"x"{}}}"#,
                " ".repeat(2048)
            ),
        ),
    ];
    for (uri, media, body) in cases {
        let response = send(
            state(&fake),
            post(Some(APP_ORIGIN), &uri, media, body.clone()),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{uri} {media} {body}"
        );
        // Refused for its request, not its origin: the browser can read why.
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            APP_ORIGIN
        );
        let refusal: serde_json::Value =
            serde_json::from_slice(&bytes_of(response).await).unwrap();
        assert!(refusal["message"].is_string(), "{refusal}");
    }
    assert!(fake.requests().is_empty());
}

#[tokio::test]
async fn an_endpoint_that_does_not_answer_is_a_bad_gateway() {
    let fake = FakeTelegram::serving(TokenReply::Silent);
    let response = send(
        state_with(&fake, Duration::from_millis(300)),
        post(Some(APP_ORIGIN), PATH, "application/json", swap_body()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let refusal: serde_json::Value =
        serde_json::from_slice(&bytes_of(response).await).unwrap();
    assert!(
        refusal["message"].as_str().unwrap().contains("in time"),
        "{refusal}"
    );
}

#[tokio::test]
async fn an_unreachable_endpoint_is_a_bad_gateway() {
    let url = format!("{}/token", common::unreachable_origin().await);
    let (settings, _secret) = telegram_config(&url);
    let state = Bridge::start(&settings).unwrap().state;
    let response = send(
        state,
        post(Some(APP_ORIGIN), PATH, "application/json", swap_body()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn an_oversized_answer_or_a_redirect_is_a_bad_gateway() {
    let fake = FakeTelegram::serving(TokenReply::with(200, &"x".repeat(8 * 1024 + 1)));
    let state = state(&fake);
    let response = send(
        state.clone(),
        post(Some(APP_ORIGIN), PATH, "application/json", swap_body()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        APP_ORIGIN
    );

    // Exactly at the bound is passed on.
    let at_bound = "x".repeat(8 * 1024);
    fake.now_serves(TokenReply::with(200, &at_bound));
    let response = send(
        state.clone(),
        post(Some(APP_ORIGIN), PATH, "application/json", swap_body()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(bytes_of(response).await.len(), at_bound.len());

    fake.now_serves(TokenReply::with(302, ""));
    let response = send(
        state,
        post(Some(APP_ORIGIN), PATH, "application/json", swap_body()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(response.headers().get("location").is_none());
    // Not followed: one request per swap.
    assert_eq!(fake.requests().len(), 3);
}

#[tokio::test]
async fn the_configuration_publishes_telegrams_client_id_and_no_credential() {
    let fake = FakeTelegram::serving(TokenReply::with(200, TOKENS));
    let request = Request::get("/api/v1/ceremony/config")
        .header("origin", APP_ORIGIN)
        .body(Body::empty())
        .unwrap();
    let response = send(state(&fake), request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let record: serde_json::Value =
        serde_json::from_slice(&bytes_of(response).await).unwrap();
    assert_eq!(
        record["platforms"]["telegram"],
        serde_json::json!({ "clientId": common::TELEGRAM_CLIENT_ID })
    );
}

/// The secret leaves only in the `Authorization` header: no answer of any route, and no debug
/// rendering of the settings or the checked client, carries it.
#[tokio::test]
async fn the_secret_appears_in_no_answer_and_no_debug_rendering() {
    let fake =
        FakeTelegram::serving(TokenReply::with(400, r#"{"error":"invalid_client"}"#));
    let (settings, _secret) = telegram_config(fake.url());
    assert!(!format!("{settings:?}").contains(TELEGRAM_SECRET));
    let deployment = libid_bridge_rs::deployment::Deployment::checked(&settings).unwrap();
    let client = deployment.telegram.expect("telegram is enabled");
    assert_eq!(client.client_secret.expose(), TELEGRAM_SECRET);
    let rendered = format!("{client:?}");
    assert!(!rendered.contains(TELEGRAM_SECRET), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");

    let state = state(&fake);
    let mut answers = Vec::new();
    for request in [
        post(Some(APP_ORIGIN), PATH, "application/json", swap_body()),
        post(Some(APP_ORIGIN), PATH, "application/json", "{}"),
        post(
            Some("https://evil.example"),
            PATH,
            "application/json",
            swap_body(),
        ),
        Request::get("/api/v1/ceremony/config")
            .header("origin", APP_ORIGIN)
            .body(Body::empty())
            .unwrap(),
    ] {
        answers.push(everything_in(send(state.clone(), request).await).await);
    }
    fake.now_serves(TokenReply::Silent);
    let slow = state_with(&fake, Duration::from_millis(200));
    answers.push(
        everything_in(
            send(
                slow,
                post(Some(APP_ORIGIN), PATH, "application/json", swap_body()),
            )
            .await,
        )
        .await,
    );
    for answer in answers {
        assert!(!answer.contains(TELEGRAM_SECRET), "{answer}");
    }
}

/// Without Telegram enabled the path is not served at all.
#[tokio::test]
async fn a_deployment_without_telegram_serves_no_swap() {
    let state = common::state(&[]).await;
    let response = send(
        state,
        post(Some(APP_ORIGIN), PATH, "application/json", swap_body()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
}
