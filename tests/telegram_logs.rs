//! What a Telegram `502` logs: the failing endpoint's URL and the failure's
//! kind. Its own binary, so its global subscriber sees every event.

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
        StatusCode,
    },
};
use common::{
    telegram_config,
    FakeTelegram,
    TokenReply,
    TELEGRAM_REDIRECT_URI,
};
use libid_bridge_rs::{
    routes,
    Bridge,
};
use tower::ServiceExt;

const APP_ORIGIN: &str = "https://app.example";
const VERIFIER: &str = "iMSTNh6gQkRnBGlY1c0MUOsD7MCO4G8C7ph1_gIZs5I";

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

#[tokio::test]
async fn a_bad_gateway_logs_the_endpoint_and_the_kind() {
    let captured = Capture::default();
    let sink = captured.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish(),
    )
    .unwrap();

    // Past both the 8 KiB answer bound and the 64 KiB key-list bound.
    let big = format!(r#"{{"a":"{}"}}"#, "a".repeat(70 * 1024));
    let fake = FakeTelegram::serving(TokenReply::with(200, &big));
    let (mut settings, _secret) = telegram_config(fake.url());
    settings.telegram.as_mut().unwrap().jwks_url = fake.url().to_owned();
    let router = routes::build_router(Bridge::start(&settings).unwrap().state);

    let swap = serde_json::json!({
        "code": "c", "codeVerifier": VERIFIER, "redirectUri": TELEGRAM_REDIRECT_URI,
    });
    let requests = [
        Request::post(routes::TELEGRAM_TOKEN_PATH)
            .header(header::ORIGIN, APP_ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(swap.to_string()))
            .unwrap(),
        Request::get(routes::TELEGRAM_JWKS_PATH)
            .header(header::ORIGIN, APP_ORIGIN)
            .body(Body::empty())
            .unwrap(),
    ];
    for request in requests {
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    let logs = String::from_utf8_lossy(&captured.0.lock().unwrap()).into_owned();
    let lines: Vec<&str> = logs.lines().collect();
    assert_eq!(lines.len(), 2, "{logs}");
    for (line, what) in lines.iter().zip(["token endpoint", "key list"]) {
        assert!(line.contains(&format!("url=\"{}\"", fake.url())), "{line}");
        assert!(line.contains("kind=\"too-large\""), "{line}");
        assert!(line.contains(what), "{line}");
    }
}
