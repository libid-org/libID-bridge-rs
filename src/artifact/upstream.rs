//! Retrieving the callback artifact from the Distribution at startup and
//! revalidating it on a schedule. Nothing here sees a request: one connection
//! is opened per retrieval, carrying no cookie, credential or query, and a
//! redirect is refused.

use std::{
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{
    BodyExt,
    Empty,
    Limited,
};
use hyper::{
    header,
    StatusCode,
};
use hyper_util::{
    client::legacy::connect::HttpConnector,
    rt::TokioExecutor,
};
use tokio::sync::watch;

use super::{
    policy,
    CallbackDocument,
    DeploymentInputs,
    Published,
};
use crate::origin::Origin;

/// The artifact's path under the CCDP origin.
pub(crate) const ARTIFACT_PATH: &str = "/ccdp/callback.html";

/// How long opening the transport may take: resolution, the connection, and
/// the TLS handshake over it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the request and its answer may take once the transport is open.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// When the refresh loop revalidates. Not configurable.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Schedule {
    /// Between revalidations when the last one succeeded, and the ceiling the
    /// backoff climbs to.
    interval: Duration,
    /// The first retry delay after a failure, doubling up to `interval`.
    floor: Duration,
}

impl Schedule {
    /// What a deployment runs on.
    pub(crate) const DEPLOYED: Schedule = Schedule {
        interval: Duration::from_secs(300),
        floor: Duration::from_secs(30),
    };
}

/// The client one deployment retrieves with: one pooled connection over TLS
/// whose anchors are compiled in from `webpki-roots`. No system trust store
/// is read.
type Client = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<HttpConnector>,
    Empty<Bytes>,
>;

/// Why a retrieval did not produce a document. Every variant is a refusal,
/// never a repair.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FetchError {
    /// The Distribution could not be reached, or did not finish answering.
    #[error("{0}")]
    Unreachable(String),
    /// The Distribution answered with a redirect, which is refused.
    #[error("answered {0}, a redirect this bridge does not follow")]
    Redirect(StatusCode),
    /// The Distribution answered, and not with the artifact.
    #[error("answered {0}")]
    Status(StatusCode),
    /// The response was not HTML, so whatever it is, it is not the artifact.
    #[error("answered {0:?}, and the artifact is text/html")]
    Media(String),
    /// The body arrived encoded, which is not what the request admitted.
    #[error("answered Content-Encoding {0:?}, and the request admitted only identity")]
    Encoded(String),
    /// A `304` to a request that carried no validator.
    #[error("answered 304 Not Modified to a request carrying no If-None-Match")]
    UnaskedNotModified,
    /// The body ran past the bound before it ended.
    #[error("the body is over the {}-byte bound", policy::MAX_ARTIFACT_BYTES)]
    TooLarge,
    /// The body was not text.
    #[error("the body is not UTF-8")]
    NotUtf8,
    /// The artifact arrived and this bridge will not serve it.
    #[error(transparent)]
    Artifact(#[from] policy::ArtifactError),
}

impl FetchError {
    /// A Distribution that could not be reached, or stopped answering.
    fn unreachable(why: impl std::fmt::Display) -> FetchError {
        FetchError::Unreachable(why.to_string())
    }

    /// The same, from an error whose own message names only its layer: the
    /// chain is walked so the reason reaching an operator is the one the
    /// socket gave.
    fn from_source(error: impl std::error::Error) -> FetchError {
        let mut why = error.to_string();
        let mut source = error.source();
        while let Some(next) = source {
            let text = next.to_string();
            if !why.contains(&text) {
                why.push_str(": ");
                why.push_str(&text);
            }
            source = next.source();
        }
        FetchError::Unreachable(why)
    }

    /// The short name this failure is counted under.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            FetchError::Unreachable(_) => "unreachable",
            FetchError::Redirect(_) => "redirect",
            FetchError::Status(_) => "status",
            FetchError::Media(_) => "media",
            FetchError::Encoded(_) => "encoded",
            FetchError::UnaskedNotModified => "unasked-not-modified",
            FetchError::TooLarge => "too-large",
            FetchError::NotUtf8 => "not-utf8",
            FetchError::Artifact(_) => "artifact",
        }
    }
}

/// What a conditional GET produced.
enum Fetched {
    /// `304`: the document in hand is still the current one.
    Unchanged,
    /// `200`: a body, the script hashes its own policy named, and the
    /// validator to revalidate it with next time.
    Fresh {
        /// The artifact, decoded.
        html: String,
        /// The hash sources of its `script-src`, carried into the policy this
        /// bridge composes.
        hashes: Vec<String>,
        /// Its `ETag`, when it sent one; without one every refresh is an
        /// unconditional GET.
        etag: Option<String>,
    },
}

/// The Distribution this deployment retrieves its artifact from, parsed once
/// at startup from the canonical CCDP origin.
pub(crate) struct Upstream {
    /// The origin as configured: what `compose` inserts and what the policy
    /// admits a frame from.
    origin: Origin,
    /// The artifact's absolute URL, built once.
    url: String,
    /// The connections this deployment retrieves over.
    client: Client,
}

impl Upstream {
    /// A canonical origin as something retrievable.
    pub(crate) fn new(origin: &Origin) -> Upstream {
        // The connector dials by URL, so `enforce_http` must be off for the
        // https wrapper to see an `https` one.
        let mut http = HttpConnector::new();
        http.set_connect_timeout(Some(CONNECT_TIMEOUT));
        http.enforce_http(false);
        // A loopback deployment names its Distribution by `http`, which
        // `https_or_http` retrieves without a certificate.
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .wrap_connector(http);
        Upstream {
            url: format!("{origin}{ARTIFACT_PATH}"),
            origin: origin.clone(),
            client: hyper_util::client::legacy::Client::builder(TokioExecutor::new())
                .build(https),
        }
    }

    /// The URL this bridge retrieves, for a log line or a failure message.
    pub(crate) fn url(&self) -> String {
        self.url.clone()
    }

    /// One log line naming a document of this Distribution: its URL,
    /// validator and policy.
    fn announce(&self, published: &Published, event: &str) {
        tracing::info!(
            url = self.url(),
            etag = published.etag.as_deref().unwrap_or("<none>"),
            policy = published.document.csp.to_str().unwrap_or("<unreadable>"),
            "{event}"
        );
    }

    /// Retrieve the artifact and compose what would be served from it.
    /// `Ok(None)` is a `304`: the document in hand is current. Startup and the
    /// refresh loop both take this path.
    pub(crate) async fn retrieve(
        &self,
        allowed_origins: &[Origin],
        etag: Option<&str>,
    ) -> Result<Option<Published>, FetchError> {
        match self.fetch(etag).await? {
            Fetched::Unchanged => Ok(None),
            Fetched::Fresh { html, hashes, etag } => {
                let document = CallbackDocument::compose(
                    &html,
                    &hashes,
                    &DeploymentInputs {
                        ccdp_origin: &self.origin,
                        allowed_origins,
                    },
                )?;
                Ok(Some(Published { document, etag }))
            }
        }
    }

    /// One conditional GET, under one budget.
    async fn fetch(&self, etag: Option<&str>) -> Result<Fetched, FetchError> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.exchange(etag))
            .await
            .map_err(|_| FetchError::unreachable("the retrieval timed out"))?
    }

    /// Send the request and read the answer.
    async fn exchange(&self, etag: Option<&str>) -> Result<Fetched, FetchError> {
        let response = self
            .client
            .request(self.request(etag))
            .await
            .map_err(FetchError::from_source)?;
        let status = response.status();
        match status {
            // A `304` is refused unless the request carried a validator.
            StatusCode::NOT_MODIFIED if etag.is_some() => return Ok(Fetched::Unchanged),
            StatusCode::NOT_MODIFIED => return Err(FetchError::UnaskedNotModified),
            StatusCode::OK => {}
            // A redirect is refused, not followed.
            s if s.is_redirection() => return Err(FetchError::Redirect(s)),
            s => return Err(FetchError::Status(s)),
        }

        Fetched::of(response).await
    }

    /// The request: no cookie, credential or query, and `Accept-Encoding:
    /// identity`, so the bytes hashed are the bytes read.
    fn request(&self, etag: Option<&str>) -> hyper::Request<Empty<Bytes>> {
        let mut request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(&self.url)
            .header(header::ACCEPT, "text/html")
            .header(header::ACCEPT_ENCODING, "identity")
            .header(
                header::USER_AGENT,
                concat!("libid-bridge/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(etag) = etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        request
            .body(Empty::new())
            .expect("a request built from a validated origin and fixed headers")
    }
}

/// Whether a `Content-Type` names exactly `text/html`, case-insensitively,
/// with parameters after optional whitespace and a `;`. `text/htmlx` does not.
fn is_html(media: &str) -> bool {
    const HTML: &[u8] = b"text/html";

    let named = media.trim_start().as_bytes();
    named.len() >= HTML.len()
        && named[..HTML.len()].eq_ignore_ascii_case(HTML)
        && matches!(
            named.get(HTML.len()),
            None | Some(b';') | Some(b' ') | Some(b'\t')
        )
}

impl Fetched {
    /// The artifact read out of a `200`.
    async fn of(
        response: hyper::Response<hyper::body::Incoming>,
    ) -> Result<Fetched, FetchError> {
        let (parts, body) = response.into_parts();
        let header = |name: header::HeaderName| {
            parts.headers.get(name).and_then(|v| v.to_str().ok())
        };
        let media = header(header::CONTENT_TYPE).unwrap_or_default();
        if !is_html(media) {
            return Err(FetchError::Media(media.to_owned()));
        }
        // The request admitted `identity` alone; an encoded body is refused.
        if let Some(encoding) = header(header::CONTENT_ENCODING)
            .filter(|e| !e.trim().eq_ignore_ascii_case("identity"))
        {
            return Err(FetchError::Encoded(encoding.to_owned()));
        }
        let etag = header(header::ETAG).map(str::to_owned);
        // The artifact is served with the hashes of the code it carries; this
        // bridge carries them into its own policy and computes none.
        let hashes = policy::script_hashes(
            header(header::CONTENT_SECURITY_POLICY).unwrap_or_default(),
        )?;

        // Bounded while it is read, whatever `content-length` declares.
        let body = Limited::new(body, policy::MAX_ARTIFACT_BYTES)
            .collect()
            .await
            .map_err(
                |e| match e.downcast_ref::<http_body_util::LengthLimitError>() {
                    Some(_) => FetchError::TooLarge,
                    None => FetchError::unreachable(format!("reading the body: {e}")),
                },
            )?;
        let html = String::from_utf8(Vec::from(body.to_bytes()))
            .map_err(|_| FetchError::NotUtf8)?;
        Ok(Fetched::Fresh { html, hashes, etag })
    }
}

/// What keeps the callback document current, held apart from what a request
/// reads: the Distribution, the origins the document is composed for, and
/// the one sender that publishes a replacement. Replace-only: a refresh
/// either publishes a valid replacement or leaves the served document as it
/// is.
pub(crate) struct Refresher {
    upstream: Upstream,
    allowed_origins: Arc<[Origin]>,
    callback: watch::Sender<Option<Arc<Published>>>,
    failure: watch::Sender<Option<String>>,
    metrics: Arc<crate::metrics::Metrics>,
}

impl Refresher {
    /// The refresher of `callback`, from `upstream`, for `allowed_origins`.
    /// It records why a retrieval produced nothing in `failure`, which the
    /// callback route reports while it has no document.
    pub(crate) fn new(
        upstream: Upstream,
        allowed_origins: Arc<[Origin]>,
        callback: watch::Sender<Option<Arc<Published>>>,
        failure: watch::Sender<Option<String>>,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> Refresher {
        Refresher {
            upstream,
            allowed_origins,
            callback,
            failure,
            metrics,
        }
    }

    /// Retrieve the artifact on `schedule` for as long as the process runs;
    /// it returns only when the process ends.
    pub(crate) async fn run(self, schedule: Schedule) {
        let url = self.upstream.url();
        // The first retrieval is this loop's, not startup's, so a
        // Distribution that is unreachable delays the callback document and
        // stops nothing.
        let mut delay = Duration::ZERO;
        let mut backoff = schedule.floor;
        loop {
            tokio::time::sleep(delay).await;
            match self.revalidate().await {
                Ok(replaced) => {
                    if replaced {
                        if let Some(published) = self.callback.borrow().as_deref() {
                            self.upstream.announce(
                                published,
                                "the callback artifact was published",
                            )
                        }
                    } else {
                        tracing::debug!(url, "the callback artifact is unchanged");
                    }
                    delay = schedule.interval;
                    backoff = schedule.floor;
                }
                Err(e) => {
                    tracing::warn!(
                        url,
                        detail = %e,
                        kind = e.kind(),
                        serving = self.callback.borrow().is_some(),
                        "the callback artifact could not be retrieved"
                    );
                    delay = backoff;
                    backoff = (backoff * 2).min(schedule.interval);
                }
            }
        }
    }

    /// One retrieval, counted and recorded: `true` replaced the document,
    /// `false` found nothing to replace it with, and an error left everything
    /// as it was.
    ///
    /// Whatever it did is visible afterwards, in the metrics and in the
    /// reason the callback route gives while it has nothing to serve.
    pub(crate) async fn revalidate(&self) -> Result<bool, FetchError> {
        match self.published().await {
            Ok(true) => {
                self.failure.send_replace(None);
                self.metrics.published();
                Ok(true)
            }
            Ok(false) => {
                self.metrics.unchanged();
                Ok(false)
            }
            Err(e) => {
                self.metrics.failed(e.kind());
                self.failure
                    .send_replace(Some(format!("{}: {e}", self.upstream.url())));
                Err(e)
            }
        }
    }

    /// One retrieval, before anything is counted: `true` replaced what is
    /// served.
    async fn published(&self) -> Result<bool, FetchError> {
        // The borrow guard must not survive into the await below.
        let etag = self.callback.borrow().as_ref().and_then(|p| p.etag.clone());
        let Some(published) = self
            .upstream
            .retrieve(&self.allowed_origins, etag.as_deref())
            .await?
        else {
            return Ok(false);
        };
        // A Distribution that sends no validator answers every refresh with the
        // whole document. The same document under the same validator is what is
        // already served, so nothing is published and nothing is logged.
        let served = {
            let current = self.callback.borrow();
            current.as_ref().is_some_and(|c| {
                c.etag == published.etag && c.document.body == published.document.body
            })
        };
        if served {
            return Ok(false);
        }
        // The document and its policy replace the old pair together.
        self.callback.send_replace(Some(Arc::new(published)));
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        Distribution,
        Reply,
    };

    fn origin(spelling: &str) -> Origin {
        Origin::parse("T", spelling).expect("an origin the tests dial")
    }

    /// A Distribution as a deployment retrieves from it.
    fn upstream(distribution: &Distribution) -> Upstream {
        Upstream::new(&origin(distribution.origin()))
    }

    /// An `https` origin that presents a certificate nothing trusts.
    async fn untrusted_tls_origin() -> String {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a self-signed certificate");
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                    cert.key_pair.serialize_der().into(),
                ),
            )
            .expect("a server configuration");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(socket).await;
                });
            }
        });
        format!("https://localhost:{port}")
    }

    /// Retrieve, and answer with the refusal.
    async fn refused(upstream: Upstream, unless: &str) -> FetchError {
        match upstream.retrieve(&origins(), None).await {
            Err(refusal) => refusal,
            Ok(_) => panic!("{unless}"),
        }
    }

    /// The origins a deployment admits.
    fn origins() -> Vec<Origin> {
        vec![origin("https://app.example")]
    }

    /// A deployment pointed at a fixture Distribution, started the way the
    /// binary starts one and given the one retrieval its refresher would
    /// make first.
    async fn bridge(distribution: &Distribution) -> crate::Bridge {
        let bridge = crate::Bridge::start(&config(distribution.origin())).unwrap();
        bridge
            .refresher
            .revalidate()
            .await
            .expect("the fixture Distribution answers the artifact");
        bridge
    }

    /// A healthy Distribution, a deployment pointed at it, and what that
    /// deployment published.
    async fn deployed() -> (Distribution, crate::Bridge, Arc<Published>) {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        let before = published(&bridge);
        (distribution, bridge, before)
    }

    /// What a deployment is serving. It has published one by the time any of
    /// these tests looks.
    fn published(bridge: &crate::Bridge) -> Arc<Published> {
        bridge
            .state
            .callback
            .borrow()
            .clone()
            .expect("a document is published")
    }

    /// A deployment pointed at this test's own Distribution.
    fn config(ccdp_origin: &str) -> crate::config::Config {
        crate::config::Config::fixture(&["--ccdp-origin", ccdp_origin])
    }

    fn served(bridge: &crate::Bridge) -> String {
        String::from_utf8(published(bridge).document.body.to_vec()).unwrap()
    }

    /// A deployment serves the artifact its Distribution built.
    #[tokio::test]
    async fn a_retrieved_artifact_is_what_gets_served() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;

        let published = published(&bridge);
        assert_eq!(published.etag.as_deref(), Some("W/\"the-artifact\""));
        // Composed: the deployment's data is in the document, the marker gone.
        assert!(served(&bridge).contains("https://app.example"));
        assert!(!served(&bridge).contains(policy::MARKER));
        // And the policy names the hash of what is being served.
        assert!(published
            .document
            .csp
            .to_str()
            .unwrap()
            .contains("'sha256-"));
    }

    /// A deployment whose Distribution answers nothing it can serve starts
    /// anyway, publishes no document, and records why, naming the URL.
    #[tokio::test]
    async fn a_deployment_that_cannot_retrieve_starts_and_says_why() {
        let distribution = Distribution::serving(Reply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            ..Reply::artifact()
        })
        .await;
        let bridge = crate::Bridge::start(&config(distribution.origin()))
            .expect("a deployment starts without its Distribution");
        bridge
            .refresher
            .revalidate()
            .await
            .expect_err("a 500 produces no document");

        assert!(bridge.state.callback.borrow().is_none());
        let why = bridge.state.failure.borrow().clone().expect("a reason");
        assert!(why.contains(distribution.origin()), "{why}");
        assert!(why.contains(ARTIFACT_PATH), "{why}");
    }

    /// A Distribution that has nothing new says so, and nothing is republished.
    #[tokio::test]
    async fn an_unchanged_artifact_leaves_the_published_document_alone() {
        // The Distribution answers the revalidation, so it lives to the end.
        let (_distribution, bridge, before) = deployed().await;

        let replaced = bridge.refresher.revalidate().await.unwrap();
        assert!(!replaced, "a 304 replaces nothing");
        // The same value, not an equal one: nothing was composed again.
        assert!(Arc::ptr_eq(&before, &published(&bridge)));
    }

    /// A failed refresh retains the last valid result and its validator.
    #[tokio::test]
    async fn an_artifact_that_will_not_scan_retains_the_last_valid_one() {
        let (distribution, bridge, before) = deployed().await;

        distribution.now_serves(Reply {
            etag: Some("W/\"the-replacement\""),
            body: "<!doctype html><body><p>not an artifact".to_owned(),
            ..Reply::artifact()
        });
        let refusal = bridge
            .refresher
            .revalidate()
            .await
            .expect_err("an artifact with no slot is not serveable");
        assert!(matches!(refusal, FetchError::Artifact(_)), "{refusal}");

        assert!(Arc::ptr_eq(&before, &published(&bridge)));
        assert_eq!(
            published(&bridge).etag.as_deref(),
            Some("W/\"the-artifact\"")
        );
    }

    /// The publish itself: a Distribution with something new produces a new
    /// document, a new policy and a new validator, all at once.
    #[tokio::test]
    async fn a_new_artifact_replaces_the_published_one_whole() {
        let (distribution, bridge, before) = deployed().await;
        distribution.now_serves(Reply::replacement());

        assert!(bridge.refresher.revalidate().await.unwrap());

        let after = published(&bridge);
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.etag.as_deref(), Some("W/\"the-replacement\""));
        // One value replaced: the policy names the hashes of the document served.
        assert_eq!(
            after.document.csp, before.document.csp,
            "the same bundle hashes the same, whatever validator carried it"
        );
        assert!(String::from_utf8(after.document.body.to_vec())
            .unwrap()
            .contains("https://app.example"));
    }

    /// A schedule fast enough to assert on, in real time.
    const BRISK: Schedule = Schedule {
        interval: Duration::from_millis(10),
        floor: Duration::from_millis(10),
    };

    /// A refresh that fails, one that finds nothing new, and one that
    /// replaces: the first two leave the served document as it is, and the
    /// loop reaches the third.
    #[tokio::test]
    async fn the_loop_survives_a_failed_refresh_and_replaces_on_a_later_one() {
        let (distribution, bridge, before) = deployed().await;
        let crate::Bridge { state, refresher } = bridge;

        // Answered in order, then the standing replacement.
        distribution.answers_next(Reply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            ..Reply::artifact()
        });
        distribution.answers_next(Reply::artifact());
        distribution.now_serves(Reply::replacement());

        let mut published = state.callback.clone();
        // The channel starts empty, so the first document is itself a change:
        // mark it seen, and what follows is the replacement.
        published.borrow_and_update();
        let loop_task = tokio::spawn(refresher.run(BRISK));
        // Resolves on the first send, so nothing before it published.
        published.changed().await.expect("the loop publishes");
        // Stopped, though nothing below depends on how promptly it stops.
        loop_task.abort();

        let after = published
            .borrow_and_update()
            .clone()
            .expect("the loop published a document");
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.etag.as_deref(), Some("W/\"the-replacement\""));
        // Both queued answers were given before the replacement was reached.
        assert_eq!(distribution.still_queued(), 0);
        assert!(distribution.requests().len() >= 4);
    }

    /// A Distribution that sends no validator answers every refresh with the
    /// document itself; the same bytes are not a replacement, so nothing is
    /// published and the served value is the one startup published.
    #[tokio::test]
    async fn the_same_document_under_no_validator_is_not_republished() {
        let distribution = Distribution::healthy().await;
        distribution.now_serves(Reply {
            etag: None,
            ..Reply::artifact()
        });
        let bridge = bridge(&distribution).await;
        let before = published(&bridge);
        assert_eq!(before.etag, None, "the Distribution sent no validator");

        for _ in 0..3 {
            assert!(
                !bridge
                    .refresher
                    .revalidate()
                    .await
                    .expect("a refresh that reaches the Distribution"),
                "the same document is not a replacement"
            );
        }
        assert!(Arc::ptr_eq(&before, &published(&bridge)));

        // A document that did change is published, validator or not.
        distribution.now_serves(Reply {
            etag: None,
            // Outside the modules, so the hashes its policy names still hold.
            body: crate::fixtures::ARTIFACT.replace("<title>libID", "<title>libID "),
            ..Reply::artifact()
        });
        assert!(bridge
            .refresher
            .revalidate()
            .await
            .expect("a refresh that reaches the Distribution"));
        assert!(!Arc::ptr_eq(&before, &published(&bridge)));
    }

    /// An artifact served without a hash-only `script-src` is refused: the
    /// hashes of the code it carries are what the composed policy names, and
    /// this bridge computes none of its own.
    #[tokio::test]
    async fn an_artifact_whose_policy_is_not_hash_only_is_refused() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;

        for policy in [
            None,
            Some("default-src 'none'".to_owned()),
            Some("script-src 'unsafe-inline'".to_owned()),
            Some("script-src https://cdn.example".to_owned()),
        ] {
            distribution.now_serves(Reply {
                etag: Some("W/\"the-replacement\""),
                policy,
                ..Reply::artifact()
            });
            let refusal = bridge
                .refresher
                .revalidate()
                .await
                .expect_err("an artifact this bridge cannot write a policy for");
            assert!(
                matches!(
                    refusal,
                    FetchError::Artifact(policy::ArtifactError::UpstreamPolicy(_))
                ),
                "{refusal}"
            );
        }

        // What the deployment published at startup is still what it serves.
        assert_eq!(
            published(&bridge).etag.as_deref(),
            Some("W/\"the-artifact\"")
        );
    }

    /// A `3xx` is refused, not followed.
    #[tokio::test]
    async fn a_redirect_is_refused_rather_than_followed() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        distribution.now_serves(Reply {
            status: StatusCode::FOUND,
            etag: None,
            ..Reply::artifact()
        });

        let refusal = bridge
            .refresher
            .revalidate()
            .await
            .expect_err("a redirect is not an artifact");
        assert!(
            matches!(refusal, FetchError::Redirect(StatusCode::FOUND)),
            "{refusal}"
        );
        // One request, so nothing was followed.
        assert_eq!(distribution.requests().len(), 2);
    }

    /// A body over the bound is refused, with or without a `content-length`.
    #[tokio::test]
    async fn a_body_over_the_bound_is_refused() {
        let oversize = "x".repeat(policy::MAX_ARTIFACT_BYTES + 1);
        for chunked in [false, true] {
            let distribution = Distribution::serving(Reply {
                etag: None,
                body: oversize.clone(),
                chunked,
                ..Reply::artifact()
            })
            .await;
            let refusal = refused(
                upstream(&distribution),
                &format!("chunked={chunked}: an oversize body is refused"),
            )
            .await;
            assert!(
                matches!(refusal, FetchError::TooLarge),
                "chunked={chunked}: {refusal}"
            );
        }
    }

    /// A response that is not `text/html` is refused before scanning.
    #[tokio::test]
    async fn an_answer_that_is_not_html_is_refused() {
        for media in [
            "application/json",
            "text/plain",
            "text/htmlx",
            "text/html-fragment",
            "",
        ] {
            let distribution = Distribution::serving(Reply {
                media,
                etag: None,
                body: "{}".to_owned(),
                ..Reply::artifact()
            })
            .await;
            let refusal =
                refused(upstream(&distribution), "this is not the artifact").await;
            assert!(
                matches!(refusal, FetchError::Media(_)),
                "{media:?}: {refusal}"
            );
        }
    }

    /// Every spelling of `text/html` is admitted: the type is
    /// case-insensitive, and parameters begin after optional whitespace and a
    /// `;`.
    #[test]
    fn every_spelling_of_text_html_is_the_artifact() {
        for media in [
            "text/html",
            "text/html; charset=utf-8",
            "text/html;charset=utf-8",
            "TEXT/HTML",
            "Text/HTML; charset=UTF-8",
            "  text/html",
            "text/html ",
        ] {
            assert!(is_html(media), "{media:?} names the artifact");
        }
        for media in ["text/htmlx", "text/html-fragment", "application/json", ""] {
            assert!(!is_html(media), "{media:?} does not name the artifact");
        }
    }

    /// The request carries nothing a deployment did not configure.
    #[tokio::test]
    async fn the_request_carries_nothing_a_deployment_did_not_configure() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        bridge.refresher.revalidate().await.unwrap();

        let requests = distribution.requests();
        let [first, second] = &requests[..] else {
            panic!("startup and one revalidation, got {}", requests.len())
        };
        for request in [first, second] {
            for absent in [
                header::COOKIE,
                header::AUTHORIZATION,
                header::REFERER,
                header::ORIGIN,
            ] {
                assert!(request.get(&absent).is_none(), "{absent} was sent");
            }
            assert_eq!(
                request.get(header::ACCEPT_ENCODING).unwrap(),
                "identity",
                "the artifact must arrive as the bytes that get hashed"
            );
        }
        // The first retrieval is unconditional; the second carries the
        // validator the first was published with.
        assert!(first.get(header::IF_NONE_MATCH).is_none());
        assert_eq!(
            second.get(header::IF_NONE_MATCH).unwrap(),
            "W/\"the-artifact\""
        );
    }

    /// A Distribution outlives the runtime that started it: the shared one is
    /// started by whichever test reaches it first, and that test's runtime is
    /// dropped when the test returns.
    #[test]
    fn a_distribution_outlives_the_runtime_that_started_it() {
        let runtime = || tokio::runtime::Runtime::new().unwrap();
        let distribution = runtime().block_on(Distribution::healthy());
        let published =
            runtime().block_on(upstream(&distribution).retrieve(&origins(), None));
        assert!(published.unwrap().is_some());
    }
    /// A peer presenting a certificate the compiled-in anchors do not carry is
    /// refused, and the refusal names the certificate.
    #[tokio::test]
    async fn an_untrusted_certificate_is_refused_as_a_certificate() {
        let untrusted = untrusted_tls_origin().await;
        let refusal = refused(
            Upstream::new(&origin(&untrusted)),
            "an untrusted peer is not a Distribution",
        )
        .await;
        let detail = format!("{refusal}");
        assert!(
            detail.contains("certificate") && detail.contains("UnknownIssuer"),
            "the refusal must name the certificate, and this one says: {detail}"
        );
    }

    /// An encoded body is refused: the request admitted `identity` alone.
    #[tokio::test]
    async fn a_body_that_arrives_encoded_is_refused() {
        let distribution = Distribution::serving(Reply {
            etag: None,
            encoding: Some("br"),
            ..Reply::artifact()
        })
        .await;
        let refusal = refused(
            upstream(&distribution),
            "an encoded body is not the artifact this bridge would hash",
        )
        .await;
        assert!(matches!(refusal, FetchError::Encoded(_)), "{refusal}");
    }

    /// A `304` to a request that carried no validator is refused, and a
    /// deployment cannot start on it.
    #[tokio::test]
    async fn a_304_to_a_request_that_asked_nothing_is_refused() {
        let distribution = Distribution::serving(Reply {
            status: StatusCode::NOT_MODIFIED,
            etag: None,
            ..Reply::artifact()
        })
        .await;
        let refusal = refused(
            upstream(&distribution),
            "an unasked 304 leaves nothing to serve",
        )
        .await;
        assert!(
            matches!(refusal, FetchError::UnaskedNotModified),
            "{refusal}"
        );
        let bridge = crate::Bridge::start(&config(distribution.origin())).unwrap();
        assert!(bridge.refresher.revalidate().await.is_err());
        assert!(bridge.state.callback.borrow().is_none());
    }

    /// `Host` carries the port only when it is not the scheme's default.
    /// The client writes it from the URL, so it is read off a request a
    /// Distribution actually received.
    #[tokio::test]
    async fn the_host_header_omits_a_default_port() {
        let distribution = Distribution::healthy().await;
        let _ = bridge(&distribution).await;
        let host = distribution.requests()[0][hyper::header::HOST]
            .to_str()
            .unwrap()
            .to_owned();
        let port = distribution
            .origin()
            .rsplit_once(':')
            .expect("a loopback origin carries its port")
            .1;
        assert_eq!(host, format!("127.0.0.1:{port}"));
        assert_eq!(
            Upstream::new(&origin("https://lib.id:443")).url(),
            format!("https://lib.id{ARTIFACT_PATH}"),
            "a default port is not part of the URL the client dials"
        );
    }
}
