//! No log line carries the Telegram client secret. Its own binary, so its
//! global subscriber sees every event the library emits.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

use std::sync::{
    Arc,
    Mutex,
};

use axum::{
    body::Body,
    http::{
        header,
        Request,
    },
    Router,
};
use common::{
    telegram_config,
    unreachable_origin,
    FakeTelegram,
    TokenReply,
    TELEGRAM_REDIRECT_URI,
    TELEGRAM_SECRET,
};
use libid_bridge_rs::{
    routes,
    Bridge,
};
use tower::ServiceExt;

const APP_ORIGIN: &str = "https://app.example";
const VERIFIER: &str = "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I";
/// `base64(client_id:client_secret)` for the test credentials.
const ENCODED_CREDENTIALS: &str = "ODEyMzQ1Njc4OTpTRUNSRVQtTUFSS0VSLTdmM2E=";

/// What the log lines are written to.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn router(token_url: &str, jwks_url: &str) -> Router {
    let (mut settings, secret) = telegram_config(token_url);
    settings.telegram.as_mut().unwrap().jwks_url = jwks_url.to_owned();
    let state = Bridge::start(&settings).unwrap().state;
    // The secret is read at startup; the file may go.
    drop(secret);
    routes::build_router(state)
}

fn swap(origin: &str) -> Request<Body> {
    let body = serde_json::json!({
        "code": "c", "codeVerifier": VERIFIER, "redirectUri": TELEGRAM_REDIRECT_URI,
    });
    Request::post(routes::TELEGRAM_TOKEN_PATH)
        .header(header::ORIGIN, origin)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn keys() -> Request<Body> {
    Request::get(routes::TELEGRAM_JWKS_PATH)
        .header(header::ORIGIN, APP_ORIGIN)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn the_secret_never_reaches_the_logs() {
    let captured = Capture::default();
    let sink = captured.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish(),
    )
    .unwrap();

    let fake = FakeTelegram::serving(TokenReply::with(200, "{}"));
    let app = router(fake.url(), fake.url());
    let big = format!(r#"{{"a":"{}"}}"#, "a".repeat(70 * 1024));
    for reply in [
        TokenReply::with(200, r#"{"id_token":"x"}"#),
        TokenReply::with(401, r#"{"error":"invalid_client"}"#),
        TokenReply::with(302, "{}"),
        TokenReply::with(200, &big),
    ] {
        fake.now_serves(reply);
        let _ = app.clone().oneshot(swap(APP_ORIGIN)).await.unwrap();
        let _ = app.clone().oneshot(keys()).await.unwrap();
    }
    let _ = app
        .clone()
        .oneshot(swap("https://evil.example"))
        .await
        .unwrap();
    let origin = unreachable_origin().await;
    let unreachable = router(&format!("{origin}/token"), &format!("{origin}/jwks"));
    let _ = unreachable.clone().oneshot(swap(APP_ORIGIN)).await.unwrap();
    let _ = unreachable.oneshot(keys()).await.unwrap();

    let logs = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    // The library's own failure lines were seen, so an empty capture can't pass.
    assert!(logs.contains("kind=\"too-large\""), "{logs}");
    assert!(logs.contains("kind=\"redirect\""), "{logs}");
    assert!(!logs.contains(TELEGRAM_SECRET), "{logs}");
    assert!(!logs.contains(ENCODED_CREDENTIALS), "{logs}");
}
