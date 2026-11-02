//! Telegram's code swap and key list, against a fake Telegram on loopback.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

use std::{
    sync::{
        Arc,
        Mutex,
        OnceLock,
    },
    time::Duration,
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
    config::Settings,
    deployment::{
        Deployment,
        PlatformProfile,
    },
    routes::{
        build_router,
        TELEGRAM_JWKS_PATH as JWKS,
        TELEGRAM_TOKEN_PATH as TOKEN,
    },
    Bridge,
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

/// A deployment enabling Telegram, its secret in `secret`.
fn settings(secret: &common::ScratchFile) -> Settings {
    let platforms = json!([{
        "id": "telegram",
        "client_id": "8123456789",
        "client_secret_file": secret.path(),
    }]);
    common::config(&["--platforms", &platforms.to_string()])
}

fn swap_body(code: &str, verifier: &str, redirect_uri: &str) -> String {
    json!({ "code": code, "codeVerifier": verifier, "redirectUri": redirect_uri })
        .to_string()
}

fn valid() -> String {
    swap_body("c", VERIFIER, "x")
}

/// What the bridge answered.
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

/// A bridge enabling Telegram, its client calling `fake` or an origin nothing
/// answers on.
struct Suite {
    fake: Fake,
    app: Router,
}

impl Suite {
    /// Telegram answering `reply`.
    fn new(reply: Reply) -> Suite {
        let fake = Fake::serving(reply);
        let app = Suite::app(&fake.url);
        Suite { fake, app }
    }

    /// Telegram unreachable.
    async fn unreachable() -> Suite {
        let fake = Fake::serving(None);
        let app = Suite::app(&common::unreachable_origin().await);
        Suite { fake, app }
    }

    fn app(url: &str) -> Router {
        let secret = common::ScratchFile::holding(&format!("{SECRET}\n"));
        let bridge = Bridge::start_with_telegram_at(&settings(&secret), url).unwrap();
        build_router(bridge.state)
    }

    async fn request(
        &self,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: impl Into<Body>,
    ) -> Answer {
        let mut request = axum::http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(body.into()).unwrap())
            .await;
        let (parts, body) = response.unwrap().into_parts();
        let body = http_body_util::BodyExt::collect(body)
            .await
            .unwrap()
            .to_bytes();
        Answer {
            status: parts.status,
            headers: parts.headers,
            body,
        }
    }

    /// A swap of `body` from the application.
    async fn swap(&self, body: String) -> Answer {
        let headers = [("origin", APP), ("content-type", JSON)];
        self.request("POST", TOKEN, &headers, body).await
    }

    /// A key-list read from the application.
    async fn keys(&self) -> Answer {
        self.request("GET", JWKS, &[("origin", APP)], "").await
    }

    /// A valid call to `route`, `token` or `keys`.
    async fn call(&self, route: &str) -> Answer {
        match route {
            "token" => self.swap(valid()).await,
            _ => self.keys().await,
        }
    }

    /// How many Telegram calls on `route` `/metrics` counts as `outcome`.
    async fn count(&self, route: &str, outcome: &str) -> u64 {
        let text = self.request("GET", "/metrics", &[], "").await.body;
        let series =
            format!("telegram_calls_total{{route=\"{route}\",outcome=\"{outcome}\"}} ");
        let text = String::from_utf8_lossy(&text);
        let line = text.lines().find_map(|l| l.split_once(&series));
        line.map_or(0, |(_, n)| n.parse().unwrap())
    }
}

#[tokio::test]
async fn a_swap_posts_the_form_with_basic_authentication() {
    let suite = Suite::new(answering(200, "{}"));
    let redirect = "https://bridge.example/cb?a=b&redirect_uri=https%3A%2F%2Fevil";
    suite
        .swap(swap_body("abc&client_id=1", VERIFIER, redirect))
        .await;
    let seen = suite.fake.seen();
    let (path, headers, form) = &seen[0];
    assert_eq!((seen.len(), path.as_str()), (1, "/token"));
    assert_eq!(headers["authorization"], BASIC);
    assert_eq!(headers["accept-encoding"], "identity");
    assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
    assert_eq!(
        std::str::from_utf8(form).unwrap(),
        "grant_type=authorization_code&code=abc%26client_id%3D1\
         &redirect_uri=https%3A%2F%2Fbridge.example%2Fcb%3Fa%3Db%26redirect_uri%3D\
         https%253A%252F%252Fevil&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
         &client_id=8123456789"
    );
}

#[tokio::test]
async fn a_swap_passes_telegrams_answer_through() {
    let gzipped = Bytes::from_static(GZIPPED);
    let suite = Suite::new(Some((401, JSON, Some("gzip"), gzipped)));
    let answer = suite.swap(valid()).await;
    assert_eq!(
        (answer.status, &answer.body[..]),
        (StatusCode::UNAUTHORIZED, GZIPPED)
    );
    assert_eq!(answer.headers["content-type"], JSON);
    assert_eq!(answer.headers["content-encoding"], "gzip");
    assert_eq!(answer.headers["access-control-allow-origin"], APP);
}

#[tokio::test]
async fn the_swap_preflight_grants_content_type() {
    let suite = Suite::new(None);
    let preflight = [("origin", APP), ("access-control-request-method", "POST")];
    let answer = suite.request("OPTIONS", TOKEN, &preflight, "").await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
    assert_eq!(
        answer.headers["access-control-allow-methods"],
        "POST, OPTIONS"
    );
    assert_eq!(
        answer.headers["access-control-allow-headers"],
        "content-type"
    );
}

#[tokio::test]
async fn only_a_2xx_unencoded_json_answer_without_error_counts_as_ok() {
    let replies = [
        (200, "text/plain", None, "id_token=t", "upstream_error"),
        (
            200,
            JSON,
            None,
            r#"{"error":"invalid_grant"}"#,
            "upstream_error",
        ),
        (401, JSON, None, r#"{"id_token":"t"}"#, "upstream_error"),
        (
            200,
            JSON,
            Some("gzip"),
            r#"{"id_token":"t"}"#,
            "upstream_error",
        ),
        (200, JSON, None, r#"{"id_token":"t"}"#, "ok"),
    ];
    for (status, media, encoding, body, outcome) in replies {
        let suite = Suite::new(Some((status, media, encoding, Bytes::from(body))));
        suite.swap(valid()).await;
        assert_eq!(suite.count("token", outcome).await, 1, "{body}");
    }
}

#[tokio::test]
async fn an_unadmitted_origin_is_refused_without_cors_or_a_call() {
    let suite = Suite::new(answering(200, "{}"));
    for (method, uri) in [("POST", TOKEN), ("GET", JWKS)] {
        let headers = [("origin", "https://evil.example"), ("content-type", JSON)];
        let answer = suite.request(method, uri, &headers, valid()).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{uri}");
        assert!(!answer.headers.contains_key("access-control-allow-origin"));
    }
    assert!(suite.fake.seen().is_empty());
}

#[tokio::test]
async fn a_malformed_request_is_a_400_without_a_call() {
    let suite = Suite::new(answering(200, "{}"));
    let a42 = "a".repeat(42);
    let padded = format!("{}{}", valid(), " ".repeat(2049 - valid().len()));
    let bodies = [
        r#"{"code":"c"}"#.to_owned(),
        valid().replace('}', r#","a":1}"#),
        swap_body("a b", VERIFIER, "x"),
        swap_body(&"c".repeat(513), VERIFIER, "x"),
        swap_body("c", VERIFIER, "x\u{7f}"),
        swap_body("c", &a42, "x"),
        swap_body("c", &format!("{a42}+"), "x"),
        padded,
    ];
    let json = [("origin", APP), ("content-type", JSON)];
    let text = [("origin", APP), ("content-type", "text/plain")];
    let mut requests = vec![
        ("POST", format!("{TOKEN}?a"), &json, valid()),
        ("GET", format!("{JWKS}?a"), &json, String::new()),
        ("GET", JWKS.to_owned(), &json, "{}".to_owned()),
        ("POST", TOKEN.to_owned(), &text, valid()),
    ];
    requests.extend(bodies.map(|body| ("POST", TOKEN.to_owned(), &json, body)));
    for (method, uri, headers, body) in requests {
        let answer = suite.request(method, &uri, headers, body.clone()).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{uri} {body}");
        assert_eq!(answer.headers["access-control-allow-origin"], APP);
    }
    assert!(suite.fake.seen().is_empty());
}

#[tokio::test]
async fn a_request_at_every_bound_is_swapped() {
    let suite = Suite::new(answering(200, "{}"));
    let padded = format!("{}{}", valid(), " ".repeat(2048 - valid().len()));
    let longest = swap_body(&"~".repeat(512), &"Z".repeat(128), &"!".repeat(512));
    let mixed = [
        ("origin", APP),
        ("content-type", "Application/JSON; charset=utf-8"),
    ];
    assert_eq!(suite.swap(padded).await.status, StatusCode::OK);
    assert_eq!(suite.swap(longest).await.status, StatusCode::OK);
    let answer = suite.request("POST", TOKEN, &mixed, valid()).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(suite.fake.seen().len(), 3);
}

/// Each failing call: the route, what Telegram does (`None`: unreachable),
/// the `502`'s words and the metric outcome.
fn failures() -> Vec<(&'static str, Option<Reply>, &'static str, &'static str)> {
    let moved = "answered a redirect this bridge does not follow";
    let big = "answered more than this bridge passes on";
    vec![
        ("token", Some(answering(302, "")), moved, "redirect"),
        (
            "token",
            Some(answering(200, vec![b'a'; 8 * 1024 + 1])),
            big,
            "too-large",
        ),
        ("token", None, "could not be reached", "unreachable"),
        ("keys", Some(answering(302, "")), moved, "redirect"),
        (
            "keys",
            Some(answering(200, vec![b'a'; 64 * 1024 + 1])),
            big,
            "too-large",
        ),
        (
            "keys",
            Some(answering(500, "")),
            "answered an error",
            "status",
        ),
        ("keys", None, "could not be reached", "unreachable"),
    ]
}

async fn failing(reply: Option<Reply>) -> Suite {
    match reply {
        Some(reply) => Suite::new(reply),
        None => Suite::unreachable().await,
    }
}

#[tokio::test]
async fn a_failed_call_is_a_502_naming_only_its_kind() {
    for (route, reply, kind, _) in failures() {
        let suite = failing(reply).await;
        let answer = suite.call(route).await;
        let what = match route {
            "token" => "Telegram's token endpoint",
            _ => "Telegram's key list",
        };
        assert_eq!(answer.status, StatusCode::BAD_GATEWAY, "{what} {kind}");
        let body: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
        assert_eq!(body, json!({ "message": format!("{what} {kind}") }));
        // A redirect is not followed.
        assert!(suite.fake.seen().len() <= 1);
    }
}

#[tokio::test]
async fn a_failed_call_is_counted_by_its_kind() {
    for (route, reply, _, outcome) in failures() {
        let suite = failing(reply).await;
        suite.call(route).await;
        assert_eq!(suite.count(route, outcome).await, 1, "{route} {outcome}");
    }
}

#[tokio::test]
async fn a_call_telegram_does_not_answer_times_out() {
    let suite = Suite::new(None);
    tokio::time::pause();
    let answer = suite.swap(valid()).await;
    tokio::time::resume();
    assert_eq!(answer.status, StatusCode::BAD_GATEWAY);
    assert!(String::from_utf8_lossy(&answer.body).contains("did not answer in time"));
    assert_eq!(suite.count("token", "timeout").await, 1);
}

#[tokio::test]
async fn an_answer_at_its_bound_passes_through() {
    for (route, len) in [("token", 8 * 1024), ("keys", 64 * 1024)] {
        let suite = Suite::new(answering(200, vec![b'a'; len]));
        let answer = suite.call(route).await;
        assert_eq!(
            (answer.status, answer.body.len()),
            (StatusCode::OK, len),
            "{route}"
        );
    }
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

/// Every log line this test binary writes.
fn logs() -> &'static Capture {
    static LOGS: OnceLock<Capture> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Capture::default();
        let sink = logs.clone();
        // Global: a scoped subscriber misses callsites other tests hit first.
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || sink.clone());
        tracing::subscriber::set_global_default(subscriber.finish()).unwrap();
        logs
    })
}

#[tokio::test]
async fn the_log_names_a_failure_and_holds_no_secret() {
    let logs = logs();
    let long = "Q".repeat(65);
    let suite = Suite::new(answering(400, json!({ "error": long }).to_string()));
    suite.swap(valid()).await;
    suite.fake.serve(answering(302, ""));
    suite.swap(valid()).await;

    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains(r#"error="unreadable""#), "{logs}");
    assert!(
        logs.contains(r#"kind="redirect" error=answered 302"#),
        "{logs}"
    );
    assert!(
        !logs.contains(SECRET) && !logs.contains(&BASIC[6..]) && !logs.contains(&long),
        "{logs}"
    );
}

#[tokio::test]
async fn the_key_list_passes_through_without_credentials() {
    let media = "application/json; charset=utf-8";
    let gzipped = Bytes::from_static(GZIPPED);
    let suite = Suite::new(Some((200, media, Some("gzip"), gzipped)));
    let answer = suite.keys().await;
    assert_eq!((answer.status, &answer.body[..]), (StatusCode::OK, GZIPPED));
    assert_eq!(answer.headers["content-type"], media);
    assert_eq!(answer.headers["content-encoding"], "gzip");
    assert_eq!(answer.headers["access-control-allow-origin"], APP);
    let seen = suite.fake.seen();
    assert_eq!((seen.len(), seen[0].0.as_str()), (1, "/jwks"));
    assert!(seen[0].1.get("authorization").is_none());
    assert_eq!(seen[0].1["accept-encoding"], "identity");
}

#[tokio::test]
async fn the_key_list_is_cached_for_an_hour() {
    let suite = Suite::new(answering(200, r#"{"keys":[]}"#));
    suite.keys().await;
    suite.fake.serve(answering(200, "{}"));
    // No I/O runs while the clock is paused: these reads are the cache.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(3599)).await;
    assert_eq!(&suite.keys().await.body[..], br#"{"keys":[]}"#);
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::time::resume();
    assert_eq!(&suite.keys().await.body[..], b"{}");
    assert_eq!(suite.fake.seen().len(), 2);
}

#[tokio::test]
async fn past_the_hour_a_failed_refetch_is_a_502() {
    let suite = Suite::new(answering(200, "{}"));
    suite.keys().await;
    suite.fake.serve(answering(500, ""));
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(3600)).await;
    tokio::time::resume();
    assert_eq!(suite.keys().await.status, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn a_200_that_is_not_a_key_list_passes_through_uncached() {
    for (media, body) in [("text/html", "<p>"), (JSON, "")] {
        let suite = Suite::new(Some((200, media, None, Bytes::from(body))));
        for _ in 0..2 {
            let answer = suite.keys().await;
            assert_eq!(
                (answer.status, &answer.body[..]),
                (StatusCode::OK, body.as_bytes())
            );
        }
        assert_eq!(suite.fake.seen().len(), 2, "{media}");
        assert_eq!(suite.count("keys", "upstream_error").await, 2, "{media}");
    }
}

#[tokio::test]
async fn a_key_list_fetched_is_counted_ok() {
    let suite = Suite::new(answering(200, "{}"));
    suite.keys().await;
    suite.keys().await;
    assert_eq!(suite.count("keys", "ok").await, 1);
}

#[test]
fn startup_refuses_an_unusable_telegram_entry_naming_the_key() {
    let secret = common::ScratchFile::holding(&format!("{SECRET}\r\n"));
    let empty = common::ScratchFile::holding("\n");
    let spaced = common::ScratchFile::holding("two words\n");
    let plus = common::ScratchFile::holding("a+b\n");
    let long = common::ScratchFile::holding(&"a".repeat(1025));
    let good = settings(&secret);
    let entry = |f: &dyn Fn(&mut PlatformProfile)| {
        let mut settings = good.clone();
        f(&mut settings.platforms[0]);
        settings
    };
    let file = |file: &common::ScratchFile| {
        let path = file.path().to_owned();
        entry(&move |p| p.client_secret_file = Some(path.clone()))
    };
    let mut github = common::config(&[]);
    github.platforms[0].client_secret_file = Some(secret.path().into());
    let cases = [
        (
            entry(&|p| p.client_secret_file = Some("/nonexistent".into())),
            "client_secret_file",
        ),
        (file(&empty), "client_secret_file"),
        (file(&long), "longer than 1024"),
        (file(&spaced), "client_secret_file"),
        (file(&plus), "client_secret_file"),
        (entry(&|p| p.client_id = "8123x".into()), "client_id"),
        (
            entry(&|p| p.client_secret_file = None),
            "telegram carries no client_secret_file",
        ),
        (github, "github carries a client_secret_file"),
    ];
    for (settings, key) in cases {
        let error = Deployment::checked(&settings).err().map(|e| e.to_string());
        let error = error.unwrap_or_default();
        assert!(
            error.contains(key) && !error.contains(SECRET),
            "{key}: {error}"
        );
    }
}

#[test]
fn a_file_names_the_secret_file_on_the_telegram_entry() {
    let secret = common::ScratchFile::holding(&format!("{SECRET}\n"));
    let file = common::ScratchFile::holding(&format!(
        "allowed_app_origins = [{APP:?}]\nccdp_origin = {:?}\n\
         [[platforms]]\nid = \"telegram\"\nclient_id = \"8123456789\"\n\
         client_secret_file = {:?}\n",
        common::Distribution::shared().origin(),
        secret.path(),
    ));
    let settings = Settings::read(file.path()).unwrap();
    assert!(Deployment::checked(&settings).unwrap().telegram.is_some());
}

#[test]
fn the_client_shows_no_secret_in_debug() {
    let secret = common::ScratchFile::holding(&format!("{SECRET}\n"));
    let deployment = Deployment::checked(&settings(&secret)).unwrap();
    let debug = format!("{:?}", deployment.telegram.unwrap());
    assert!(
        !debug.contains(SECRET) && !debug.contains(&BASIC[6..]),
        "{debug}"
    );
}

#[tokio::test]
async fn config_publishes_only_telegrams_client_id() {
    let suite = Suite::new(None);
    let answer = suite
        .request("GET", "/api/v1/ceremony/config", &[("origin", APP)], "")
        .await;
    let record: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
    let telegram = &record["platforms"]["telegram"];
    assert_eq!(telegram, &json!({ "clientId": "8123456789" }));
}

#[tokio::test]
async fn without_telegram_its_routes_are_absent() {
    let suite = Suite {
        fake: Fake::serving(None),
        app: build_router(common::bridge(&[]).state),
    };
    for route in ["token", "keys"] {
        assert_eq!(
            suite.call(route).await.status,
            StatusCode::NOT_FOUND,
            "{route}"
        );
    }
}
