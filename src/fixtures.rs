//! What the tests build a deployment from: the artifact a live Distribution
//! serves, and a server on loopback that answers with it.
//!
//! [`ARTIFACT`] is `tests/fixtures/callback.html`, the libID testnet
//! Distribution's artifact saved byte for byte, and [`ARTIFACT_POLICY`] is the
//! `Content-Security-Policy` that response carried. Both were taken on
//! 2026-09-22 with:
//!
//! ```text
//! curl -sD - https://testnet.ccdp.lib.id/ccdp/callback.html \
//!     -o tests/fixtures/callback.html
//! ```
//!
//! They belong together: the policy names the hash of the module the file
//! carries, so a refresh replaces both or neither.
//!
//! Compiled for the crate's own tests and, under the `fixtures` feature, for
//! the integration tests.

use std::sync::{
    Arc,
    LazyLock,
    Mutex,
    OnceLock,
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

use crate::{
    artifact::upstream::ARTIFACT_PATH,
    config,
    state::AppState,
};

/// The artifact of a live Distribution.
pub const ARTIFACT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/callback.html"
));

/// The policy that artifact was served under.
pub const ARTIFACT_POLICY: &str = "default-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-LaBqitbp5EWwcs7p4ANPVImzGYSfuMs/n1gfR6aHsPI='; style-src 'unsafe-inline'";

/// The one script hash [`ARTIFACT_POLICY`] names.
pub fn artifact_hash() -> String {
    crate::artifact::policy::script_hashes(ARTIFACT_POLICY)
        .expect("the saved policy names hashes")
        .remove(0)
}

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

/// One answer a fixture Distribution gives.
#[derive(Clone)]
pub struct Reply {
    /// The status it answers with.
    pub status: StatusCode,
    /// Its `Content-Type`.
    pub media: &'static str,
    /// Its `ETag`, when it sends one.
    pub etag: Option<&'static str>,
    /// Its body.
    pub body: String,
    /// Its `Content-Encoding`, when it declares one.
    pub encoding: Option<&'static str>,
    /// Its `Content-Security-Policy`, when it sends one.
    pub policy: Option<String>,
    /// Its `Location`, when it redirects.
    pub location: Option<&'static str>,
}

impl Default for Reply {
    fn default() -> Reply {
        Reply::artifact()
    }
}

impl Reply {
    /// The artifact, as a Distribution serves it.
    pub fn artifact() -> Reply {
        Reply {
            status: StatusCode::OK,
            media: "text/html; charset=utf-8",
            etag: Some("\"the-artifact\""),
            body: ARTIFACT.to_owned(),
            encoding: None,
            policy: Some(ARTIFACT_POLICY.to_owned()),
            location: None,
        }
    }

    /// The artifact after a compatible change: a different validator, and a
    /// title the served document carries.
    pub fn replacement() -> Reply {
        Reply {
            etag: Some("\"the-replacement\""),
            body: ARTIFACT.replace("<title>libID</title>", "<title>libID.</title>"),
            ..Reply::artifact()
        }
    }

    /// The same answer with a different status.
    pub fn with_status(self, status: StatusCode) -> Reply {
        Reply { status, ..self }
    }

    /// The same answer with a different policy.
    pub fn with_policy(self, policy: &str) -> Reply {
        Reply {
            policy: Some(policy.to_owned()),
            ..self
        }
    }
}

/// A Distribution on loopback: it answers the artifact path with the reply it
/// is holding, and records the headers each request carried.
pub struct Distribution {
    origin: String,
    state: Arc<Mutex<Held>>,
}

/// What a fixture Distribution answers with, and what it has been asked.
#[derive(Default)]
struct Held {
    /// Answered once each, in order, before `standing`.
    queued: std::collections::VecDeque<Reply>,
    /// Answered whenever nothing is queued.
    standing: Option<Reply>,
    /// The headers of every request it received.
    seen: Vec<HeaderMap>,
}

impl Distribution {
    /// A Distribution answering `reply` until told otherwise. It serves on
    /// the shared runtime, so it outlives the test that started it.
    pub async fn serving(reply: Reply) -> Distribution {
        let state = Arc::new(Mutex::new(Held {
            standing: Some(reply),
            ..Held::default()
        }));
        let app = Router::new()
            .route(ARTIFACT_PATH, get(answer))
            .with_state(state.clone());
        let (bound, address) = tokio::sync::oneshot::channel();
        runtime().spawn(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let _ = bound.send(listener.local_addr().unwrap());
            let _ = axum::serve(listener, app).await;
        });
        Distribution {
            origin: format!("http://{}", address.await.unwrap()),
            state,
        }
    }

    /// A Distribution answering nothing: every retrieval fails to connect.
    pub async fn unreachable() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin =
            format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        drop(listener);
        origin
    }

    /// Where it serves.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// What it answers from now on.
    pub fn now_serves(&self, reply: Reply) {
        self.state.lock().unwrap().standing = Some(reply)
    }

    /// What it answers once, before whatever it is serving.
    pub fn answers_next(&self, reply: Reply) {
        self.state.lock().unwrap().queued.push_back(reply)
    }

    /// The headers of every request it received.
    pub fn requests(&self) -> Vec<HeaderMap> {
        self.state.lock().unwrap().seen.clone()
    }

    /// One Distribution every test that needs no answer of its own shares.
    /// It starts on a thread of its own, so a test already inside a runtime
    /// can ask for it.
    pub fn shared() -> &'static Distribution {
        static SHARED: OnceLock<Distribution> = OnceLock::new();
        SHARED.get_or_init(|| {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        runtime().block_on(Distribution::serving(Reply::artifact()))
                    })
                    .join()
                    .expect("the shared Distribution starts")
            })
        })
    }
}

/// The artifact path of a fixture Distribution.
async fn answer(
    State(state): State<Arc<Mutex<Held>>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let reply = {
        let mut held = state.lock().unwrap();
        held.seen.push(headers.clone());
        held.queued
            .pop_front()
            .or_else(|| held.standing.clone())
            .expect("a fixture Distribution answers something")
    };
    // A conditional request for the validator it is holding is answered `304`.
    let asked = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    if asked.is_some() && asked == reply.etag && reply.status == StatusCode::OK {
        return StatusCode::NOT_MODIFIED.into_response();
    }

    let mut out = HeaderMap::new();
    out.insert(header::CONTENT_TYPE, reply.media.parse().unwrap());
    for (name, value) in [
        (header::ETAG, reply.etag.map(str::to_owned)),
        (header::CONTENT_ENCODING, reply.encoding.map(str::to_owned)),
        (header::CONTENT_SECURITY_POLICY, reply.policy.clone()),
        (header::LOCATION, reply.location.map(str::to_owned)),
    ] {
        if let Some(value) = value {
            out.insert(name, value.parse().unwrap());
        }
    }
    (reply.status, out, reply.body).into_response()
}

/// A file that exists for as long as it is held.
pub struct ScratchFile(std::path::PathBuf);

impl ScratchFile {
    /// A file holding `contents`, named for this process and this file.
    pub fn holding(contents: &str) -> ScratchFile {
        use std::sync::atomic::{
            AtomicU32,
            Ordering,
        };
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "libid-bridge-{}-{}.toml",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("a scratch file is written");
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

/// The public client identifier a fixture deployment publishes.
pub const CLIENT_ID: &str = "Iv1.0123456789abcdef";

/// The public client credential a fixture deployment publishes.
pub const CLIENT_CREDENTIAL: &str = "d3b07384d113edec49eaa6238ad5ff00c1f2e3a4";

impl config::Config {
    /// A configuration that starts, with `args` replacing any default it
    /// names.
    ///
    /// Every flag that reads an environment variable is listed, so the
    /// process environment reaches nothing. `--platforms` is this fixture's
    /// own: the JSON records go to `Config::platforms`, which the binary
    /// fills from the configuration file. The CCDP origin is the shared
    /// Distribution's unless `args` names another.
    pub fn fixture(args: &[&str]) -> config::Config {
        let platforms = format!(
            r#"[{{"id":"github","client_id":"{CLIENT_ID}","versions":[1],"client_credential":"{CLIENT_CREDENTIAL}"}}]"#
        );
        let mut flags: Vec<(&str, &str)> = vec![
            ("--host", "127.0.0.1"),
            ("--port", "8722"),
            ("--allowed-app-origins", "https://app.example"),
            ("--ccdp-origin", Distribution::shared().origin()),
            ("--platforms", &platforms),
        ];
        for pair in args.chunks(2) {
            let [flag, value] = pair else {
                panic!("test flags come in pairs, got {pair:?}")
            };
            match flags.iter_mut().find(|(f, _)| f == flag) {
                Some(slot) => slot.1 = value,
                None => flags.push((flag, value)),
            }
        }
        let platforms = flags
            .iter()
            .position(|(f, _)| *f == "--platforms")
            .map(|i| flags.remove(i).1)
            .expect("the fixture lists --platforms");
        let mut argv = vec!["libid-server-rs"];
        for (flag, value) in &flags {
            argv.push(flag);
            argv.push(value);
        }
        let mut cfg = <config::Config as clap::Parser>::parse_from(argv);
        cfg.platforms =
            serde_json::from_str(platforms).expect("the fixture's platform records");
        cfg
    }
}

/// One retrieval against the deployment's Distribution, as the refresh
/// performs it. `Ok(true)` published a document, `Ok(false)` found the served
/// one current, and an error left whatever is published in place.
pub async fn retrieve_once(state: &Arc<AppState>) -> Result<bool, String> {
    crate::artifact::upstream::retrieve_once(state)
        .await
        .map_err(|e| e.to_string())
}

impl AppState {
    /// A deployment built from [`config::Config::fixture`], the way the
    /// binary builds one: no document published yet.
    pub fn fixture(args: &[&str]) -> Arc<AppState> {
        crate::build_state(&config::Config::fixture(args))
            .expect("a deployment the fixtures can serve")
    }

    /// The same, with the artifact already retrieved.
    pub async fn fixture_serving(args: &[&str]) -> Arc<AppState> {
        let state = AppState::fixture(args);
        retrieve_once(&state)
            .await
            .expect("the fixture Distribution answers the artifact");
        state
    }
}
