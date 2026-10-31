//! Telegram's code swap and key list, against a fake Telegram on loopback.

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
        HeaderMap,
        StatusCode,
    },
    response::Response,
    Router,
};
use bytes::Bytes;
use libid_bridge_rs::{
    deployment::TelegramSettings,
    routes::{
        build_router,
        TELEGRAM_JWKS_PATH as JWKS,
        TELEGRAM_TOKEN_PATH as TOKEN,
    },
};
use serde_json::json;
use tower::ServiceExt;

const APP: &str = "https://app.example";
const JSON: &str = "application/json";
const SECRET: &str = "SECRET-7f3a_Qz9";
/// `printf '8123456789:SECRET-7f3a_Qz9' | base64`, from coreutils.
const BASIC: &str = "Basic ODEyMzQ1Njc4OTpTRUNSRVQtN2YzYV9Rejk=";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// `{"keys":[{"kty":"RSA","kid":"oidc-1"}]}` through `gzip -n -9`.
const GZIPPED: &[u8] =
    b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\xab\x56\xca\x4e\xad\x2c\
    \x56\xb2\x8a\xae\x56\xca\x2e\xa9\x54\xb2\x52\x0a\x0a\x76\x54\xd2\x51\xca\xce\x4c\x01\
    \xb2\xf3\x33\x53\x92\x75\x0d\x95\x6a\x63\x6b\x01\xf0\xab\x93\x07\x27\x00\x00\x00";

/// Status, media type, encoding and body; `None` never answers.
type Reply = Option<(u16, &'static str, Option<&'static str>, Bytes)>;
type Seen = Arc<Mutex<Vec<(String, HeaderMap, Bytes)>>>;

/// Telegram on loopback: every path records the request and answers the reply,
/// with a `Location` to itself.
struct Fake {
    url: String,
    seen: Seen,
    reply: Arc<Mutex<Reply>>,
}

impl Fake {
    fn serving(reply: Reply) -> Fake {
        let (seen, reply) = (Seen::default(), Arc::new(Mutex::new(reply)));
        let state = (seen.clone(), reply.clone());
        let router = Router::new().fallback(fake).with_state(state);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        common::runtime().spawn(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, router).await
        });
        Fake { url, seen, reply }
    }

    fn serve(&self, reply: Reply) {
        *self.reply.lock().unwrap() = reply;
    }

    fn seen(&self) -> Vec<(String, HeaderMap, Bytes)> {
        self.seen.lock().unwrap().clone()
    }
}

async fn fake(
    axum::extract::State((seen, reply)): axum::extract::State<(Seen, Arc<Mutex<Reply>>)>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    seen.lock()
        .unwrap()
        .push((uri.path().to_owned(), headers, body));
    let reply = reply.lock().unwrap().clone();
    let Some((status, media, encoding, body)) = reply else {
        return std::future::pending().await;
    };
    let response = Response::builder()
        .status(status)
        .header("content-type", media);
    let response = response.header("location", "/elsewhere");
    let response = match encoding {
        Some(encoding) => response.header("content-encoding", encoding),
        None => response,
    };
    response.body(Body::from(body)).unwrap()
}

fn answering(status: u16, body: impl Into<Bytes>) -> Reply {
    Some((status, JSON, None, body.into()))
}

/// A deployment enabling Telegram at `url`, its secret in `secret`.
fn settings(
    url: &str,
    secret: &common::ScratchFile,
) -> libid_bridge_rs::config::Settings {
    let platforms = r#"[{"id":"telegram","client_id":"8123456789"}]"#;
    let mut settings = common::config(&["--platforms", platforms]);
    settings.telegram = Some(TelegramSettings {
        client_secret_file: secret.path().to_owned(),
        token_url: Some(format!("{url}/token")),
        jwks_url: Some(format!("{url}/jwks")),
    });
    settings
}

fn app(url: &str) -> Router {
    let secret = common::ScratchFile::holding(&format!("{SECRET}\n"));
    let bridge = libid_bridge_rs::Bridge::start(&settings(url, &secret)).unwrap();
    build_router(bridge.state)
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: impl Into<Body>,
) -> (StatusCode, HeaderMap, Bytes) {
    let mut request = axum::http::Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(body.into()).unwrap())
        .await;
    let (parts, body) = response.unwrap().into_parts();
    let body = http_body_util::BodyExt::collect(body)
        .await
        .unwrap()
        .to_bytes();
    (parts.status, parts.headers, body)
}

fn swap(code: &str, verifier: &str, redirect_uri: &str) -> String {
    json!({ "code": code, "codeVerifier": verifier, "redirectUri": redirect_uri })
        .to_string()
}

/// A valid swap (`POST`) or a key-list read (`GET`) from the application.
async fn call(app: &Router, method: &str) -> (StatusCode, HeaderMap, Bytes) {
    let (path, body) = match method {
        "POST" => (TOKEN, swap("c", VERIFIER, "x")),
        _ => (JWKS, String::new()),
    };
    let headers = [("origin", APP), ("content-type", JSON)];
    send(app, method, path, &headers, body).await
}

/// Whether `/metrics` counts `n` Telegram calls on `route` ending in `outcome`.
async fn counted(app: &Router, route: &str, outcome: &str, n: u32) -> bool {
    let (_, _, text) = send(app, "GET", "/metrics", &[], "").await;
    let line =
        format!("telegram_calls_total{{route=\"{route}\",outcome=\"{outcome}\"}} {n}\n");
    String::from_utf8_lossy(&text).contains(&line)
}

#[tokio::test]
async fn a_swap_posts_the_exact_form_and_passes_the_answer_through() {
    let fake = Fake::serving(answering(401, r#"{"error":"invalid_grant"}"#));
    let app = app(&fake.url);
    let redirect = "https://bridge.example/cb?a=b&redirect_uri=https%3A%2F%2Fevil";
    let body = swap("abc&client_id=1", VERIFIER, redirect);
    let headers = [("origin", APP), ("content-type", JSON)];
    let (status, headers, answer) = send(&app, "POST", TOKEN, &headers, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(&answer[..], br#"{"error":"invalid_grant"}"#);
    assert_eq!(headers["access-control-allow-origin"], APP);
    assert_eq!(headers["content-type"], JSON);

    let seen = fake.seen();
    let (path, headers, form) = &seen[0];
    assert_eq!((seen.len(), path.as_str()), (1, "/token"));
    assert_eq!(headers["authorization"], BASIC);
    assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
    assert_eq!(
        std::str::from_utf8(form).unwrap(),
        "grant_type=authorization_code&code=abc%26client_id%3D1\
         &redirect_uri=https%3A%2F%2Fbridge.example%2Fcb%3Fa%3Db%26redirect_uri%3D\
         https%253A%252F%252Fevil&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
         &client_id=8123456789"
    );

    let preflight = [("origin", APP), ("access-control-request-method", "POST")];
    let (status, headers, _) = send(&app, "OPTIONS", TOKEN, &preflight, "").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers["access-control-allow-methods"], "POST, OPTIONS");
    assert_eq!(headers["access-control-allow-headers"], "content-type");

    let gzipped = Bytes::from_static(GZIPPED);
    fake.serve(Some((200, JSON, Some("gzip"), gzipped)));
    let (status, headers, answer) = call(&app, "POST").await;
    assert_eq!((status, &answer[..]), (StatusCode::OK, GZIPPED));
    assert_eq!(headers["content-encoding"], "gzip");

    // Only a 2xx unencoded JSON answer without `error` counts as `ok`.
    let replies = [
        ("text/plain", "id_token=t", "upstream_error"),
        (JSON, r#"{"error":"invalid_grant"}"#, "upstream_error"),
        (JSON, r#"{"id_token":"t"}"#, "ok"),
    ];
    for (media, body, outcome) in replies {
        fake.serve(Some((200, media, None, Bytes::from(body))));
        let (status, headers, answer) = call(&app, "POST").await;
        assert_eq!((status, &answer[..]), (StatusCode::OK, body.as_bytes()));
        assert_eq!(headers["content-type"], media, "{outcome}");
    }
    assert!(counted(&app, "token", "upstream_error", 4).await);
    assert!(counted(&app, "token", "ok", 1).await);
}

#[tokio::test]
async fn a_refused_request_sends_nothing_upstream() {
    let fake = Fake::serving(answering(200, "{}"));
    let app = app(&fake.url);
    let valid = swap("c", VERIFIER, "x");
    let padded = |len: usize| format!("{valid}{}", " ".repeat(len - valid.len()));
    let a42 = "a".repeat(42);
    let (evil, mixed) = ("https://evil.example", "Application/JSON; charset=utf-8");
    let longest = swap(&"~".repeat(512), &"Z".repeat(128), &"!".repeat(512));
    // Method (`POST` the swap, `GET` the key list), query, origin, media type.
    let requests = [
        ("POST", "", evil, JSON, valid.as_str(), 403),
        ("GET", "", evil, "", "", 403),
        ("POST", "?a", APP, JSON, &valid, 400),
        ("GET", "?a", APP, "", "", 400),
        ("GET", "", APP, "", "{}", 400),
        ("POST", "", APP, "text/plain", &valid, 400),
        ("POST", "", APP, mixed, &valid, 200),
    ];
    let bodies = [
        (r#"{"code":"c"}"#.to_owned(), 400),
        (valid.replace('}', r#","a":1}"#), 400),
        (swap("a b", VERIFIER, "x"), 400),
        (swap(&"c".repeat(513), VERIFIER, "x"), 400),
        (swap("c", VERIFIER, "x\u{7f}"), 400),
        (swap("c", &a42, "x"), 400),
        (swap("c", &format!("{a42}+"), "x"), 400),
        (padded(2049), 400),
        (padded(2048), 200),
        (longest, 200),
    ];
    let cases = requests.map(|(m, q, o, t, b, s)| (m, q, o, t, b.to_owned(), s));
    let bodies = bodies.map(|(body, status)| ("POST", "", APP, JSON, body, status));
    for (method, query, origin, media, body, expected) in cases.into_iter().chain(bodies)
    {
        let uri = format!("{}{query}", if method == "POST" { TOKEN } else { JWKS });
        let headers = [("origin", origin), ("content-type", media)];
        let (status, headers, _) = send(&app, method, &uri, &headers, body.clone()).await;
        assert_eq!(status, expected, "{uri} {media} {body}");
        let allowed = headers.get("access-control-allow-origin");
        assert_eq!(allowed.is_some(), expected != 403, "{uri} {body}");
    }
    assert_eq!(fake.seen().len(), 3);
}

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
async fn an_upstream_failure_is_a_502_naming_only_its_kind() {
    let logs = Capture::default();
    let sink = logs.clone();
    // Global: a scoped subscriber misses callsites other tests hit first.
    let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE);
    let subscriber = subscriber
        .with_ansi(false)
        .with_writer(move || sink.clone());
    tracing::subscriber::set_global_default(subscriber.finish()).unwrap();
    let fake = Fake::serving(None);
    let app = app(&fake.url);
    let unreachable = self::app(&common::unreachable_origin().await);
    let moved = "answered a redirect this bridge does not follow";
    let big = "answered more than this bridge passes on";
    let cases = [
        (&app, "POST", answering(302, ""), moved),
        (&app, "POST", answering(200, vec![b'a'; 8 * 1024 + 1]), big),
        (&app, "GET", answering(302, ""), moved),
        (&app, "GET", answering(200, vec![b'a'; 64 * 1024 + 1]), big),
        (&app, "GET", answering(500, ""), "answered an error"),
        (&unreachable, "POST", None, "could not be reached"),
        (&unreachable, "GET", None, "could not be reached"),
    ];
    for (app, method, reply, kind) in cases {
        fake.serve(reply);
        let before = fake.seen().len();
        let (status, _, body) = call(app, method).await;
        let what = match method {
            "POST" => "Telegram's token endpoint",
            _ => "Telegram's key list",
        };
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{what} {kind}");
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({ "message": format!("{what} {kind}") }));
        // At most one request per call: a redirect is not followed.
        assert!(fake.seen().len() - before <= 1);
    }

    fake.serve(None);
    tokio::time::pause();
    let (status, _, body) = call(&app, "POST").await;
    tokio::time::resume();
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(String::from_utf8_lossy(&body).contains("did not answer in time"));

    for (method, len) in [("POST", 8 * 1024), ("GET", 64 * 1024)] {
        fake.serve(answering(200, vec![b'a'; len]));
        let (status, _, body) = call(&app, method).await;
        assert_eq!((status, body.len()), (StatusCode::OK, len), "{method}");
    }

    let failed = [
        ("token", "redirect"),
        ("token", "too_large"),
        ("token", "timeout"),
        ("keys", "redirect"),
        ("keys", "too_large"),
        ("keys", "status"),
    ];
    for (route, outcome) in failed {
        assert!(counted(&app, route, outcome, 1).await, "{route} {outcome}");
    }
    assert!(counted(&app, "keys", "ok", 1).await);
    assert!(counted(&unreachable, "token", "unreachable", 1).await);
    assert!(counted(&unreachable, "keys", "unreachable", 1).await);

    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    // The library's own failure lines were captured, and carry no secret.
    let lines = ["Telegram's token endpoint gave", "Telegram's key list gave"];
    assert!(lines.iter().all(|line| logs.contains(line)), "{logs}");
    assert!(
        !logs.contains(SECRET) && !logs.contains(&BASIC[6..]),
        "{logs}"
    );
}

#[tokio::test]
async fn the_key_list_passes_through_and_is_cached_for_an_hour() {
    let fake = Fake::serving(answering(500, ""));
    let app = app(&fake.url);
    let get = || send(&app, "GET", JWKS, &[("origin", APP)], Body::empty());
    assert_eq!(get().await.0, StatusCode::BAD_GATEWAY);

    // Passed through, and not cached: each is fetched again.
    for (media, body) in [("text/html", "<p>"), (JSON, "")] {
        fake.serve(Some((200, media, None, Bytes::from(body))));
        for _ in 0..2 {
            let (status, _, got) = get().await;
            assert_eq!((status, &got[..]), (StatusCode::OK, body.as_bytes()));
        }
    }

    let media = "application/json; charset=utf-8";
    fake.serve(Some((
        200,
        media,
        Some("gzip"),
        Bytes::from_static(GZIPPED),
    )));
    let (status, headers, body) = get().await;
    assert_eq!((status, &body[..]), (StatusCode::OK, GZIPPED));
    assert_eq!(headers["content-type"], media);
    assert_eq!(headers["content-encoding"], "gzip");
    assert_eq!(headers["access-control-allow-origin"], APP);
    let seen = fake.seen();
    assert_eq!((seen.len(), seen[5].0.as_str()), (6, "/jwks"));
    assert!(seen[5].1.get("authorization").is_none());

    fake.serve(answering(200, "{}"));
    // No I/O runs while the clock is paused: these reads are the cache.
    tokio::time::pause();
    assert_eq!(get().await.2, GZIPPED);
    tokio::time::advance(std::time::Duration::from_secs(3599)).await;
    assert_eq!(get().await.2, GZIPPED);
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::time::resume();
    assert_eq!(&get().await.2[..], b"{}");
    assert_eq!(fake.seen().len(), 7);

    // Stale, while refetches fail, for a day: each refetch times out in 10 s.
    fake.serve(None);
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(3600)).await;
    let (status, _, body) = get().await;
    assert_eq!((status, &body[..]), (StatusCode::OK, &b"{}"[..]));
    tokio::time::advance(std::time::Duration::from_secs(86_370)).await;
    assert_eq!(&get().await.2[..], b"{}");
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    assert_eq!(get().await.0, StatusCode::BAD_GATEWAY);
    tokio::time::resume();
    assert!(counted(&app, "keys", "timeout", 3).await);
    assert!(counted(&app, "keys", "ok", 6).await);
}

#[test]
fn startup_refuses_an_unusable_telegram_table_naming_the_setting() {
    let secret = common::ScratchFile::holding(&format!("{SECRET}\r\n"));
    let empty = common::ScratchFile::holding("\n");
    let spaced = common::ScratchFile::holding("two words\n");
    let plus = common::ScratchFile::holding("a+b\n");
    let good = settings("https://oauth.example", &secret);
    let table = |f: &dyn Fn(&mut TelegramSettings)| {
        let mut settings = good.clone();
        settings.telegram.as_mut().map(f);
        settings
    };
    let mut lettered = good.clone();
    lettered.platforms[0].client_id = "8123x".into();
    let mut untabled = good.clone();
    untabled.telegram = None;
    let mut lettered_untabled = untabled.clone();
    lettered_untabled.platforms[0].client_id = "8123x".into();
    let mut platformless = common::config(&[]);
    platformless.telegram = good.telegram.clone();
    let http = |key: &str| Some(format!("http://oauth.example/{key}"));
    let cases = [
        (
            table(&|t| t.client_secret_file = "/nonexistent".into()),
            "client_secret_file",
        ),
        (
            table(&|t| t.client_secret_file = empty.path().into()),
            "client_secret_file",
        ),
        (table(&|t| t.token_url = http("token")), "token_url"),
        (table(&|t| t.jwks_url = http("jwks")), "jwks_url"),
        (
            table(&|t| t.client_secret_file = spaced.path().into()),
            "client_secret_file",
        ),
        (
            table(&|t| t.client_secret_file = plus.path().into()),
            "client_secret_file",
        ),
        (lettered, "client_id"),
        (lettered_untabled, "client_id"),
        (untabled, "[telegram]"),
        (platformless, "[telegram]"),
    ];
    for (settings, key) in cases {
        let checked = libid_bridge_rs::deployment::Deployment::checked(&settings);
        let error = checked.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            error.contains(key) && !error.contains(SECRET),
            "{key}: {error}"
        );
    }

    // Read from a file, as the binary reads one, naming no endpoint.
    let file = common::ScratchFile::holding(&format!(
        "allowed_app_origins = [{APP:?}]\nccdp_origin = {:?}\n\
         [[platforms]]\nid = \"telegram\"\nclient_id = \"8123456789\"\n\
         [telegram]\nclient_secret_file = {:?}\n",
        common::Distribution::shared().origin(),
        secret.path(),
    ));
    let defaults = libid_bridge_rs::config::Settings::read(file.path()).unwrap();
    let deployment = libid_bridge_rs::deployment::Deployment::checked(&defaults);
    let client = deployment.unwrap().telegram.unwrap();
    assert_eq!(client.token_url, "https://oauth.telegram.org/token");
    assert_eq!(
        client.jwks_url,
        "https://oauth.telegram.org/.well-known/jwks.json"
    );
    let debug = format!("{client:?}");
    assert!(
        !debug.contains(SECRET) && !debug.contains(&BASIC[6..]),
        "{debug}"
    );
}

#[tokio::test]
async fn config_shows_only_the_client_id_and_the_routes_need_telegram() {
    let app = app("http://127.0.0.1:9");
    let origin = [("origin", APP)];
    let (_, _, body) = send(&app, "GET", "/api/v1/ceremony/config", &origin, "").await;
    let record: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let telegram = &record["platforms"]["telegram"];
    assert_eq!(telegram, &json!({ "clientId": "8123456789" }));

    let without = build_router(common::bridge(&[]).state);
    for method in ["POST", "GET"] {
        assert_eq!(call(&without, method).await.0, StatusCode::NOT_FOUND);
    }
}
