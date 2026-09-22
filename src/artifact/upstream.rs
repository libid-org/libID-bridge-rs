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
pub const ARTIFACT_PATH: &str = "/ccdp/callback.html";

/// How long opening the transport may take: resolution, the connection, and
/// the TLS handshake over it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the request and its answer may take once the transport is open.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// When the refresh loop revalidates. Not configurable.
#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    /// Between revalidations when the last one succeeded, and the ceiling the
    /// backoff climbs to.
    pub interval: Duration,
    /// The first retry delay after a failure, doubling up to `interval`.
    pub floor: Duration,
}

impl Schedule {
    /// What a deployment runs on.
    pub const DEPLOYED: Schedule = Schedule {
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
pub enum FetchError {
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
    pub fn kind(&self) -> &'static str {
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
pub struct Upstream {
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
    pub fn new(origin: &Origin) -> Upstream {
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
    pub fn url(&self) -> String {
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
    pub async fn retrieve(
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
pub fn is_html(media: &str) -> bool {
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
pub struct Refresher {
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
    pub fn new(
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
    pub async fn run(self, schedule: Schedule) {
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
    pub async fn revalidate(&self) -> Result<bool, FetchError> {
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
