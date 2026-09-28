//! What the tests build a deployment from: a Distribution on loopback serving
//! the fixture artifact and a version list, and a configuration naming it.
//! Compiled into each integration test that declares the module.

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        LazyLock,
        Mutex,
        OnceLock,
    },
};

use axum::{
    extract::State,
    response::IntoResponse,
    routing::get,
    Router,
};
use hyper::{
    header,
    HeaderMap,
    StatusCode,
};

use libid_bridge_rs::{
    artifact::upstream::{
        ARTIFACT_PATH,
        VERSIONS_PATH,
    },
    config,
    state::AppState,
    Bridge,
};

/// The artifact a live Distribution serves.
///
/// `tests/fixtures/callback.html` is the libID testnet Distribution's own
/// bytes, taken on 2026-09-22 with:
///
/// ```text
/// curl -s https://testnet.ccdp.lib.id/ccdp/callback.html \
///     -o tests/fixtures/callback.html
/// ```
///
/// Refreshing it needs nothing else: [`artifact_hashes`] hashes the module
/// the file carries, so the fixture Distribution serves the policy that file
/// deserves, the way a Distribution's build does.
pub const ARTIFACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/callback.html"
));

/// The version list a healthy Distribution serves: one version of each
/// platform this bridge knows.
pub const VERSIONS: &str = r#"{"github":[1],"google":[1],"x":[1]}"#;

/// The runtime shared fixtures are served on. `#[tokio::test]` drops each
/// test's runtime, and every task on it, when the test returns; this one is
/// never dropped.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a runtime for the shared fixtures")
    });
    &RUNTIME
}

/// The script hashes the fixture artifact is served with: what a Distribution
/// computes over the code it ships, and what the bridge carries into the
/// policy it composes.
pub fn artifact_hashes() -> Vec<String> {
    use base64::Engine as _;
    use sha2::Digest as _;

    const OPEN: &str = "<script type=\"module\">";
    let start = ARTIFACT.find(OPEN).expect("the fixture carries one module") + OPEN.len();
    let end = start + ARTIFACT[start..].find("</script>").expect("it closes");
    let digest = sha2::Sha256::digest(&ARTIFACT.as_bytes()[start..end]);
    vec![format!(
        "'sha256-{}'",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )]
}

/// The `Content-Security-Policy` a Distribution serves the fixture artifact
/// under: hash-only, as the artifact contract requires.
pub fn artifact_policy() -> String {
    format!(
        "default-src 'none'; script-src {}; style-src 'unsafe-inline'",
        artifact_hashes().join(" ")
    )
}

/// What the fixture Distribution answers with next.
#[derive(Clone)]
pub struct Reply {
    /// The status line.
    pub status: StatusCode,
    /// The `Content-Type`.
    pub media: &'static str,
    /// The `ETag`, when it sends one.
    pub etag: Option<&'static str>,
    /// The body.
    pub body: String,
    /// A `Content-Encoding` to claim, for a Distribution that ignores what
    /// the request admitted.
    pub encoding: Option<&'static str>,
    /// Send the body with no `content-length`, as a chunked answer does.
    pub chunked: bool,
    /// The `Content-Security-Policy` it is served under, which names the
    /// hashes of the code it carries. `None` sends none.
    pub policy: Option<String>,
}

impl Reply {
    /// The artifact, as a healthy Distribution serves it.
    pub fn artifact() -> Reply {
        Reply {
            status: StatusCode::OK,
            media: "text/html; charset=utf-8",
            etag: Some("W/\"the-artifact\""),
            body: ARTIFACT.to_owned(),
            encoding: None,
            chunked: false,
            policy: Some(artifact_policy()),
        }
    }

    /// The same artifact under a new validator.
    pub fn replacement() -> Reply {
        Reply {
            etag: Some("W/\"the-replacement\""),
            ..Reply::artifact()
        }
    }

    /// The version list, as a healthy Distribution serves it.
    pub fn versions() -> Reply {
        Reply {
            status: StatusCode::OK,
            media: "application/json; charset=utf-8",
            etag: Some("W/\"the-versions\""),
            body: VERSIONS.to_owned(),
            encoding: None,
            chunked: false,
            policy: None,
        }
    }

    /// A version list of `body`, under no validator: every retrieval gets
    /// the body, and the bridge decides whether it is a replacement.
    pub fn listing(body: &str) -> Reply {
        Reply {
            etag: None,
            body: body.to_owned(),
            ..Reply::versions()
        }
    }
}

/// What the fixture has been told to say about one resource, and what it has
/// been asked.
#[derive(Clone)]
struct Answers {
    /// Every request the fixture saw, in order.
    seen: Arc<Mutex<Vec<HeaderMap>>>,
    /// What it answers when nothing is queued.
    standing: Arc<Mutex<Reply>>,
    /// Answers for the next requests, ahead of the standing one.
    queued: Arc<Mutex<VecDeque<Reply>>>,
}

impl Answers {
    /// Answering `reply` until told otherwise.
    fn standing(reply: Reply) -> Answers {
        Answers {
            seen: Arc::default(),
            standing: Arc::new(Mutex::new(reply)),
            queued: Arc::default(),
        }
    }
}

/// A Distribution, on loopback and in plaintext, served on [`runtime`]. It
/// serves the artifact and the version list, each answered as told.
pub struct Distribution {
    origin: String,
    artifact: Answers,
    versions: Answers,
}

impl Distribution {
    /// A Distribution answering the artifact path with `reply`, and the
    /// version list path with the healthy list.
    pub async fn serving(reply: Reply) -> Distribution {
        let artifact = Answers::standing(reply);
        let versions = Answers::standing(Reply::versions());
        let router = Router::new()
            .route(ARTIFACT_PATH, get(answer).with_state(artifact.clone()))
            .route(VERSIONS_PATH, get(answer).with_state(versions.clone()));
        let (bound, address) = tokio::sync::oneshot::channel();
        runtime().spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let _ = bound.send(listener.local_addr().unwrap());
            let _ = axum::serve(listener, router).await;
        });
        let origin = format!("http://{}", address.await.unwrap());
        Distribution {
            origin,
            artifact,
            versions,
        }
    }

    /// A Distribution serving the artifact and the version list.
    pub async fn healthy() -> Distribution {
        Distribution::serving(Reply::artifact()).await
    }

    /// Where it is, as a deployment's `--ccdp-origin`.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Answer every artifact request from now on with this.
    pub fn now_serves(&self, reply: Reply) {
        *self.artifact.standing.lock().unwrap() = reply;
    }

    /// Answer the next artifact request with this, once.
    pub fn answers_next(&self, reply: Reply) {
        self.artifact.queued.lock().unwrap().push_back(reply);
    }

    /// How many queued artifact answers are still waiting to be given.
    pub fn still_queued(&self) -> usize {
        self.artifact.queued.lock().unwrap().len()
    }

    /// Every artifact request seen so far, in order.
    pub fn requests(&self) -> Vec<HeaderMap> {
        self.artifact.seen.lock().unwrap().clone()
    }

    /// Answer every version list request from now on with this.
    pub fn now_serves_versions(&self, reply: Reply) {
        *self.versions.standing.lock().unwrap() = reply;
    }

    /// Answer the next version list request with this, once.
    pub fn answers_next_versions(&self, reply: Reply) {
        self.versions.queued.lock().unwrap().push_back(reply);
    }

    /// Every version list request seen so far, in order.
    pub fn versions_requests(&self) -> Vec<HeaderMap> {
        self.versions.seen.lock().unwrap().clone()
    }
}

async fn answer(
    State(answers): State<Answers>,
    headers: HeaderMap,
) -> axum::response::Response {
    answers.seen.lock().unwrap().push(headers.clone());
    let reply = match answers.queued.lock().unwrap().pop_front() {
        Some(queued) => queued,
        None => answers.standing.lock().unwrap().clone(),
    };
    // Only a `200` revalidates into a `304`.
    let asked = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    if reply.status == StatusCode::OK && reply.etag.is_some() && asked == reply.etag {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    let mut response = axum::response::Response::builder()
        .status(reply.status)
        .header(header::CONTENT_TYPE, reply.media);
    if let Some(etag) = reply.etag {
        response = response.header(header::ETAG, etag);
    }
    if let Some(encoding) = reply.encoding {
        response = response.header(header::CONTENT_ENCODING, encoding);
    }
    if let Some(policy) = &reply.policy {
        response = response.header(header::CONTENT_SECURITY_POLICY, policy);
    }
    let body = if reply.chunked {
        axum::body::Body::from_stream(futures_util::stream::iter([Ok::<_, String>(
            bytes::Bytes::from(reply.body),
        )]))
    } else {
        axum::body::Body::from(reply.body)
    };
    response.body(body).unwrap().into_response()
}

impl Distribution {
    /// One healthy Distribution, started once and shared by every test that
    /// builds a deployment.
    pub fn shared() -> &'static Distribution {
        static SHARED: OnceLock<Distribution> = OnceLock::new();
        SHARED.get_or_init(|| {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| runtime().block_on(Distribution::healthy()))
                    .join()
                    .expect("the shared Distribution starts")
            })
        })
    }
}

/// A file for the duration of a test, removed when the test lets go of it.
pub struct ScratchFile(std::path::PathBuf);

impl ScratchFile {
    /// `contents`, in a file of this process's own.
    pub fn holding(contents: &str) -> ScratchFile {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "libid-{}-{}.toml",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("a scratch configuration file");
        ScratchFile(path)
    }

    /// Where it is.
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The client id every fixture deployment enables GitHub with.
pub const CLIENT_ID: &str = "Iv1.0123456789abcdef";

/// The public client credential every fixture deployment publishes
/// for GitHub.
pub const CLIENT_CREDENTIAL: &str = "d3b07384d113edec49eaa6238ad5ff00c1f2e3a4";

/// The deployment a test starts from, with `args` replacing any default it
/// names.
///
/// It is written to a file and read back, as the binary reads one.
/// `--allowed-app-origins`, `--ccdp-origin` and `--platforms` are this
/// fixture's own spellings of the file's keys; the first is a comma-separated
/// list because a test reads more easily that way, and the last carries the
/// JSON records a `[[platforms]]` table parses into. The CCDP origin is the
/// shared Distribution's unless `args` names another.
pub fn config(args: &[&str]) -> config::Settings {
    let mut origins = "https://app.example".to_owned();
    let mut ccdp_origin = Distribution::shared().origin().to_owned();
    let mut platforms = format!(
        r#"[{{"id":"github","default_client_id":"{CLIENT_ID}","default_client_credential":"{CLIENT_CREDENTIAL}"}}]"#
    );
    for pair in args.chunks(2) {
        let [flag, value] = pair else {
            panic!("test flags come in pairs, got {pair:?}")
        };
        match *flag {
            "--allowed-app-origins" => origins = (*value).to_owned(),
            "--ccdp-origin" => ccdp_origin = (*value).to_owned(),
            "--platforms" => platforms = (*value).to_owned(),
            other => panic!("the fixture names no {other}"),
        }
    }

    let listed = origins
        .split(',')
        .map(|o| format!("{o:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let file = ScratchFile::holding(&format!(
        "allowed_app_origins = [{listed}]\nccdp_origin = {ccdp_origin:?}\n"
    ));
    let mut settings = config::Settings::read(file.path()).expect("the fixture resolves");
    drop(file);
    // The records a `[[platforms]]` table would have produced. The file path
    // for them is covered by the configuration suite.
    settings.platforms =
        serde_json::from_str(&platforms).expect("the fixture's platform records");
    settings
}

/// An origin nothing answers on: a Distribution this deployment cannot reach.
pub async fn unreachable_origin() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    origin
}

/// A deployment started from [`config`], the way the binary starts one, with
/// nothing retrieved yet.
pub fn bridge(args: &[&str]) -> Bridge {
    Bridge::start(&config(args)).expect("a deployment the fixtures can serve")
}

/// One tick of the refresher, as the loop performs it: `Ok(true)` published
/// a document or a record, `Ok(false)` found both current, and an error
/// names the first resource whose retrieval failed, with whatever was
/// published left in place.
pub async fn retrieve_once(bridge: &Bridge) -> Result<bool, String> {
    let tick = bridge.refresher.revalidate().await;
    match (tick.callback, tick.versions) {
        (Ok(callback), Ok(versions)) => Ok(callback || versions),
        (Err(e), _) | (_, Err(e)) => Err(e.to_string()),
    }
}

/// The state of a deployment started from [`config`], with the artifact and
/// the version list its Distribution answered with already published.
pub async fn state(args: &[&str]) -> Arc<AppState> {
    let bridge = bridge(args);
    retrieve_once(&bridge)
        .await
        .expect("the fixture Distribution answers the artifact and the version list");
    bridge.state
}

/// The record the configuration route serves, as published.
pub fn record(state: &AppState) -> serde_json::Value {
    let published = state
        .ceremony_config
        .current
        .borrow()
        .clone()
        .expect("a record is published");
    serde_json::from_slice(&published.record).expect("the record is JSON")
}
