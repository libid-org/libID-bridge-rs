//! Retrieving the Distribution's two resources, the callback artifact and
//! the version list, and revalidating each on a schedule. Nothing here sees
//! a request: one connection is opened per retrieval, carrying no cookie,
//! credential or query, and a redirect is refused. The first retrieval is
//! the refresh loop's, so startup opens no connection.
//!
//! Each resource is published on its own: a version list this bridge refuses
//! leaves the callback document alone, and the other way round. A tick of
//! the loop counts as failed, for its backoff, when either retrieval did.

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
    HeaderMap,
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
use crate::{
    deployment::{
        Deployment,
        PublishedConfig,
    },
    origin::{
        Admitted,
        Origin,
    },
    state::Retrieved,
    versions::{
        self,
        Versions,
    },
};

/// The callback artifact's path under the CCDP origin.
pub const ARTIFACT_PATH: &str = "/ccdp/callback.html";

/// The version list's path under the CCDP origin, beside the artifact and
/// unversioned like it: the list is a property of the Distribution, not of
/// one CCDP version.
pub const VERSIONS_PATH: &str = "/ccdp/versions.json";

/// How long opening the transport may take: resolution, the connection, and
/// the TLS handshake over it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the request and its answer may take once the transport is open.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The resources of the Distribution this bridge retrieves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter)]
pub enum Resource {
    /// The callback artifact.
    Callback,
    /// The version list.
    Versions,
}

impl Resource {
    /// Its path under the CCDP origin.
    pub fn path(self) -> &'static str {
        match self {
            Resource::Callback => ARTIFACT_PATH,
            Resource::Versions => VERSIONS_PATH,
        }
    }

    /// The media type its `Content-Type` must name: what the request asks
    /// for, and what a response is refused without.
    pub fn media(self) -> &'static str {
        match self {
            Resource::Callback => "text/html",
            Resource::Versions => "application/json",
        }
    }

    /// The largest body this bridge reads of it; the retrieval stops there.
    pub fn max_bytes(self) -> usize {
        match self {
            Resource::Callback => policy::MAX_ARTIFACT_BYTES,
            Resource::Versions => versions::MAX_VERSIONS_BYTES,
        }
    }

    /// The `resource` label its retrievals are counted under.
    pub fn label(self) -> &'static str {
        match self {
            Resource::Callback => "callback",
            Resource::Versions => "versions",
        }
    }

    /// Whether `content_type` names exactly this resource's media type,
    /// case-insensitively, with parameters after optional whitespace and a
    /// `;`. `text/htmlx` does not name `text/html`.
    pub fn is_served_as(self, content_type: &str) -> bool {
        let wanted = self.media().as_bytes();
        let named = content_type.trim_start().as_bytes();
        named.len() >= wanted.len()
            && named[..wanted.len()].eq_ignore_ascii_case(wanted)
            && matches!(
                named.get(wanted.len()),
                None | Some(b';') | Some(b' ') | Some(b'\t')
            )
    }
}

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
    /// What a deployment runs on: five minutes between ticks whose every
    /// retrieval succeeded, and a second after one that did not, doubling to
    /// the same five minutes. A Distribution that is briefly unreachable
    /// costs a ceremony a second rather than half a minute.
    pub const DEPLOYED: Schedule = Schedule {
        interval: Duration::from_secs(300),
        floor: Duration::from_secs(1),
    };
}

/// The client one deployment retrieves with: one pooled connection over TLS
/// whose anchors are compiled in from `webpki-roots`. No system trust store
/// is read.
type Client = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<HttpConnector>,
    Empty<Bytes>,
>;

/// Why a retrieval produced nothing. Every variant is a refusal, never a
/// repair.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The Distribution could not be reached, or did not finish answering.
    #[error("{0}")]
    Unreachable(String),
    /// The Distribution answered with a redirect, which is refused.
    #[error("answered {0}, a redirect this bridge does not follow")]
    Redirect(StatusCode),
    /// The Distribution answered, and not with the resource.
    #[error("answered {0}")]
    Status(StatusCode),
    /// The response is not the media type the resource is served as, so
    /// whatever it is, it is not the resource.
    #[error("answered Content-Type {found:?}, and the resource is {wanted}")]
    Media {
        /// What the `Content-Type` named.
        found: String,
        /// What the resource is served as.
        wanted: &'static str,
    },
    /// The body arrived encoded, which is not what the request admitted.
    #[error("answered Content-Encoding {0:?}, and the request admitted only identity")]
    Encoded(String),
    /// A `304` to a request that carried no validator.
    #[error("answered 304 Not Modified to a request carrying no If-None-Match")]
    UnaskedNotModified,
    /// The body ran past the resource's bound before it ended.
    #[error("the body is over the {0}-byte bound")]
    TooLarge(usize),
    /// The body was not text.
    #[error("the body is not UTF-8")]
    NotUtf8,
    /// The artifact arrived and this bridge will not serve it.
    #[error(transparent)]
    Artifact(#[from] policy::ArtifactError),
    /// The version list arrived and this bridge will not accept it.
    #[error("the version list is refused: {0}")]
    Versions(#[from] serde_json::Error),
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
            FetchError::Media { .. } => "media",
            FetchError::Encoded(_) => "encoded",
            FetchError::UnaskedNotModified => "unasked-not-modified",
            FetchError::TooLarge(_) => "too-large",
            FetchError::NotUtf8 => "not-utf8",
            FetchError::Artifact(_) => "artifact",
            FetchError::Versions(_) => "grammar",
        }
    }
}

/// What a conditional GET produced.
enum Fetched {
    /// `304`: what is in hand is still the current one.
    Unchanged,
    /// `200`: the body, within the resource's bound, the headers it arrived
    /// under, and the validator to revalidate it with next time.
    Fresh {
        /// The body, unencoded.
        body: Bytes,
        /// Every response header, for what a resource reads of them.
        headers: HeaderMap,
        /// Its `ETag`, when it sent one; without one every refresh is an
        /// unconditional GET.
        etag: Option<String>,
    },
}

/// The Distribution this deployment retrieves from, parsed once at startup
/// from the canonical CCDP origin.
pub struct Upstream {
    /// The origin as configured: what `compose` inserts and what the policy
    /// admits a frame from.
    origin: Origin,
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
            origin: origin.clone(),
            client: hyper_util::client::legacy::Client::builder(TokioExecutor::new())
                .build(https),
        }
    }

    /// The URL `resource` is retrieved from, for a log line or a failure
    /// message.
    pub fn url(&self, resource: Resource) -> String {
        format!("{}{}", self.origin, resource.path())
    }

    /// Retrieve the callback artifact and compose what would be served from
    /// it. `Ok(None)` is a `304`: the document in hand is current. Every
    /// tick of the refresh loop takes this path, the first included.
    pub async fn retrieve_callback(
        &self,
        allowed_origins: &[Admitted],
        etag: Option<&str>,
    ) -> Result<Option<Published>, FetchError> {
        let Fetched::Fresh {
            body,
            headers,
            etag,
        } = self.fetch(Resource::Callback, etag).await?
        else {
            return Ok(None);
        };
        // The artifact is served with the hashes of the code it carries; this
        // bridge carries them into its own policy and computes none.
        let hashes = policy::script_hashes(
            headers
                .get(header::CONTENT_SECURITY_POLICY)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
        )?;
        let html = String::from_utf8(Vec::from(body)).map_err(|_| FetchError::NotUtf8)?;
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

    /// Retrieve the version list. `Ok(None)` is a `304`: the list in hand is
    /// current. Otherwise the list, accepted, and the validator it arrived
    /// with.
    pub async fn retrieve_versions(
        &self,
        etag: Option<&str>,
    ) -> Result<Option<(Versions, Option<String>)>, FetchError> {
        let Fetched::Fresh { body, etag, .. } =
            self.fetch(Resource::Versions, etag).await?
        else {
            return Ok(None);
        };
        Ok(Some((Versions::parse(&body)?, etag)))
    }

    /// One conditional GET of `resource`, under one budget.
    async fn fetch(
        &self,
        resource: Resource,
        etag: Option<&str>,
    ) -> Result<Fetched, FetchError> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.exchange(resource, etag))
            .await
            .map_err(|_| FetchError::unreachable("the retrieval timed out"))?
    }

    /// Send the request and read the answer.
    async fn exchange(
        &self,
        resource: Resource,
        etag: Option<&str>,
    ) -> Result<Fetched, FetchError> {
        let response = self
            .client
            .request(self.request(resource, etag))
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

        Fetched::of(resource, response).await
    }

    /// The request: no cookie, credential or query, and `Accept-Encoding:
    /// identity`, so the bytes hashed are the bytes read.
    fn request(
        &self,
        resource: Resource,
        etag: Option<&str>,
    ) -> hyper::Request<Empty<Bytes>> {
        let mut request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(self.url(resource))
            .header(header::ACCEPT, resource.media())
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

impl Fetched {
    /// `resource` read out of a `200`: served as its media type, unencoded,
    /// and within its bound.
    async fn of(
        resource: Resource,
        response: hyper::Response<hyper::body::Incoming>,
    ) -> Result<Fetched, FetchError> {
        let (parts, body) = response.into_parts();
        let header = |name: header::HeaderName| {
            parts.headers.get(name).and_then(|v| v.to_str().ok())
        };
        let media = header(header::CONTENT_TYPE).unwrap_or_default();
        if !resource.is_served_as(media) {
            return Err(FetchError::Media {
                found: media.to_owned(),
                wanted: resource.media(),
            });
        }
        // The request admitted `identity` alone; an encoded body is refused.
        if let Some(encoding) = header(header::CONTENT_ENCODING)
            .filter(|e| !e.trim().eq_ignore_ascii_case("identity"))
        {
            return Err(FetchError::Encoded(encoding.to_owned()));
        }
        let etag = header(header::ETAG).map(str::to_owned);

        // Bounded while it is read, whatever `content-length` declares.
        let body = Limited::new(body, resource.max_bytes())
            .collect()
            .await
            .map_err(
                |e| match e.downcast_ref::<http_body_util::LengthLimitError>() {
                    Some(_) => FetchError::TooLarge(resource.max_bytes()),
                    None => FetchError::unreachable(format!("reading the body: {e}")),
                },
            )?
            .to_bytes();
        Ok(Fetched::Fresh {
            body,
            headers: parts.headers,
            etag,
        })
    }
}

/// The sending half of a [`Retrieved`]: what the refresher publishes one
/// resource's product through. Replace-only: a retrieval either publishes a
/// replacement or leaves what is served as it is.
pub struct Publisher<T> {
    /// Which resource the product comes from.
    resource: Resource,
    /// Where it is retrieved from: what a failure names.
    url: String,
    /// What is published, replaced whole.
    current: watch::Sender<Option<Arc<T>>>,
    /// Why the last retrieval failed, cleared by one that succeeds.
    failure: watch::Sender<Option<String>>,
}

impl<T> Publisher<T> {
    /// A publisher of what `resource` yields from `upstream`, and the half
    /// the routes read. Nothing is published until a retrieval accepts
    /// something.
    pub fn of(upstream: &Upstream, resource: Resource) -> (Publisher<T>, Retrieved<T>) {
        let url = upstream.url(resource);
        let (current, read_current) = watch::channel(None);
        let (failure, read_failure) = watch::channel(None);
        (
            Publisher {
                resource,
                url: url.clone(),
                current,
                failure,
            },
            Retrieved {
                current: read_current,
                failure: read_failure,
                url,
            },
        )
    }

    /// What is published now. A clone, so no borrow of the channel outlives
    /// the call: one must not survive into an await.
    fn current(&self) -> Option<Arc<T>> {
        self.current.borrow().clone()
    }

    /// `product` replaces what is published.
    fn publish(&self, product: T) {
        self.current.send_replace(Some(Arc::new(product)));
    }

    /// The retrieval just made succeeded, a `304` included: whatever failure
    /// came before it is forgotten.
    fn succeeded(&self) {
        self.failure
            .send_if_modified(|failure| failure.take().is_some());
    }

    /// Why the retrieval just made failed: what the route reports while it
    /// has nothing to serve.
    fn failed(&self, why: &FetchError) {
        self.failure
            .send_replace(Some(format!("{}: {why}", self.url)));
    }
}

/// What one tick of the refresh loop did: each resource retrieved, counted
/// and recorded on its own, `true` where a replacement was published.
pub struct Tick {
    /// The callback artifact.
    pub callback: Result<bool, FetchError>,
    /// The version list, and the record composed from it.
    pub versions: Result<bool, FetchError>,
}

impl Tick {
    /// Whether either retrieval failed, which is what the backoff counts.
    pub fn failed(&self) -> bool {
        self.callback.is_err() || self.versions.is_err()
    }
}

/// What keeps both resources current, held apart from what a request reads:
/// the Distribution, the deployment the products are composed for, and the
/// two publishers. Replace-only: a retrieval either publishes a valid
/// replacement or leaves what is served as it is.
pub struct Refresher {
    upstream: Upstream,
    deployment: Deployment,
    callback: Publisher<Published>,
    config: Publisher<PublishedConfig>,
    metrics: Arc<crate::metrics::Metrics>,
}

impl Refresher {
    /// The refresher of `callback` and `config`, from `upstream`, for
    /// `deployment`. Each publisher records why a retrieval produced
    /// nothing, which its route reports while it has nothing to serve.
    pub fn new(
        upstream: Upstream,
        deployment: Deployment,
        callback: Publisher<Published>,
        config: Publisher<PublishedConfig>,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> Refresher {
        Refresher {
            upstream,
            deployment,
            callback,
            config,
            metrics,
        }
    }

    /// Retrieve both resources on `schedule` for as long as the process
    /// runs; it returns only when the process ends.
    pub async fn run(self, schedule: Schedule) {
        // The first retrieval is this loop's, not startup's, so a
        // Distribution that is unreachable delays what it serves and stops
        // nothing.
        let mut delay = Duration::ZERO;
        let mut backoff = schedule.floor;
        loop {
            tokio::time::sleep(delay).await;
            if self.revalidate().await.failed() {
                delay = backoff;
                backoff = (backoff * 2).min(schedule.interval);
            } else {
                delay = schedule.interval;
                backoff = schedule.floor;
            }
        }
    }

    /// One tick: the callback artifact and the version list, retrieved
    /// concurrently. Neither waits on the other, and each is published on
    /// its own.
    pub async fn revalidate(&self) -> Tick {
        let (callback, versions) =
            tokio::join!(self.revalidate_callback(), self.revalidate_versions());
        Tick { callback, versions }
    }

    /// One retrieval of the callback artifact, counted, recorded and logged:
    /// `true` replaced the document, `false` found nothing to replace it
    /// with, and an error left everything as it was.
    ///
    /// Whatever it did is visible afterwards, in the metrics and in the
    /// reason the callback route gives while it has nothing to serve.
    pub async fn revalidate_callback(&self) -> Result<bool, FetchError> {
        let outcome = self.published_callback().await;
        self.account(&self.callback, &outcome);
        outcome
    }

    /// One retrieval of the version list, counted, recorded and logged:
    /// `true` composed and published a record, `false` found nothing to
    /// replace the record with, and an error left everything as it was.
    ///
    /// Whatever it did is visible afterwards, in the metrics and in the
    /// reason the configuration route gives while it has no record.
    pub async fn revalidate_versions(&self) -> Result<bool, FetchError> {
        let outcome = self.published_versions().await;
        self.account(&self.config, &outcome);
        outcome
    }

    /// `outcome` of one retrieval through `publisher`, in the metrics, in the
    /// failure its route reports, and in the log.
    fn account<T>(&self, publisher: &Publisher<T>, outcome: &Result<bool, FetchError>) {
        let resource = publisher.resource;
        match outcome {
            Ok(true) => {
                self.metrics.published(resource);
                publisher.succeeded();
            }
            Ok(false) => {
                self.metrics.unchanged(resource);
                publisher.succeeded();
                tracing::debug!(
                    resource = resource.label(),
                    url = publisher.url,
                    "the resource is unchanged"
                );
            }
            Err(e) => {
                self.metrics.failed(resource, e.kind());
                publisher.failed(e);
                tracing::warn!(
                    resource = resource.label(),
                    url = publisher.url,
                    detail = %e,
                    kind = e.kind(),
                    serving = publisher.current().is_some(),
                    "the resource could not be retrieved"
                );
            }
        }
    }

    /// One retrieval of the callback artifact, before anything is counted:
    /// `true` replaced what is served.
    async fn published_callback(&self) -> Result<bool, FetchError> {
        let current = self.callback.current();
        let validator = current.as_ref().and_then(|p| p.etag.as_deref());
        let Some(published) = self
            .upstream
            .retrieve_callback(&self.deployment.allowed_origins, validator)
            .await?
        else {
            return Ok(false);
        };
        // A Distribution that sends no validator answers every refresh with the
        // whole document. The same document under the same validator is what is
        // already served, so nothing is published and nothing is logged.
        if current.is_some_and(|c| {
            c.etag == published.etag && c.document.body == published.document.body
        }) {
            return Ok(false);
        }
        tracing::info!(
            resource = Resource::Callback.label(),
            url = self.callback.url,
            etag = published.etag.as_deref().unwrap_or("<none>"),
            policy = published.document.csp.to_str().unwrap_or("<unreadable>"),
            "the callback artifact was published"
        );
        // The document and its policy replace the old pair together.
        self.callback.publish(published);
        Ok(true)
    }

    /// One retrieval of the version list, before anything is counted: `true`
    /// composed a record from it and published the pair.
    async fn published_versions(&self) -> Result<bool, FetchError> {
        let current = self.config.current();
        let validator = current.as_ref().and_then(|c| c.etag.as_deref());
        let Some((versions, etag)) = self.upstream.retrieve_versions(validator).await?
        else {
            return Ok(false);
        };
        // The same list under the same validator is what the record in hand
        // was composed from, so nothing is composed, published or logged.
        if current.is_some_and(|c| c.etag == etag && c.versions == versions) {
            return Ok(false);
        }
        // Composed once per accepted list, which is where what the list and
        // the file disagree on is logged.
        let record = self.deployment.ceremony_config(&versions);
        tracing::info!(
            resource = Resource::Versions.label(),
            url = self.config.url,
            etag = etag.as_deref().unwrap_or("<none>"),
            versions = %versions,
            "the version list was published"
        );
        self.config.publish(PublishedConfig {
            record,
            versions,
            etag,
        });
        Ok(true)
    }
}
