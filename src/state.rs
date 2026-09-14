//! What the bridge holds while it runs: configuration read once at startup.
//!
//! There is no ceremony state. Each request is answered in isolation; up to
//! [`MAX_CONCURRENT_EXCHANGES`] exchanges run at once and share nothing
//! mutable. A timeout, a duplicate request, a restart or a lost response
//! leaves no record.

use std::sync::Arc;

use tokio::sync::{
    watch,
    Semaphore,
};

use crate::oauth::OAuthCredentials;

/// How many exchanges may be in flight at once. Each is a full MPC-TLS
/// session and one outbound request carrying the client secret; a request
/// past the ceiling is shed with `503`.
pub const MAX_CONCURRENT_EXCHANGES: usize = 8;

/// Everything the confidential exchange needs, and nothing any other route
/// does. Present exactly when GitHub is enabled: the token route is mounted
/// with it or not mounted.
pub struct GithubExchange {
    /// GitHub's confidential client.
    pub(crate) credentials: OAuthCredentials,
    /// The redirect URI every exchange sends GitHub: the configured public
    /// origin followed by `/auth/callback`, the OAuth App's registration.
    pub(crate) redirect_uri: String,
    /// Dials the notary each token request names, on the wire port; refuses
    /// private and internal addresses.
    pub(crate) egress: crate::routes::github_token::NotaryEgress,
    /// The effective admission set `allowedAppOrigins ∪ {ccdpOrigin}`, as the
    /// `Origin` header values the token route and its preflight compare with.
    pub(crate) admitted: Vec<axum::http::HeaderValue>,
    /// The exchange permits, [`MAX_CONCURRENT_EXCHANGES`] of them. A request
    /// that finds none is shed, not queued.
    pub(crate) permits: Semaphore,
}

/// Configuration every route reads.
pub struct AppState {
    /// The callback document, the policy it is served under, and the validator
    /// it was retrieved with. Never empty: startup retrieves an artifact or the
    /// process does not start. A refresh replaces the whole value at once.
    pub(crate) callback: watch::Receiver<Arc<crate::artifact::Published>>,
    /// The publishing end, for the refresh task.
    pub(crate) callback_tx: watch::Sender<Arc<crate::artifact::Published>>,
    /// The Distribution the artifact was retrieved from, and is revalidated
    /// against on the refresh schedule.
    pub(crate) upstream: crate::artifact::upstream::Upstream,
    /// The effective admission set `allowedAppOrigins ∪ {ccdpOrigin}`: the one
    /// rule every gated route applies, and what the callback document is told.
    /// Exact canonical strings, compared against what a browser sends.
    pub(crate) allowed_origins: Arc<[String]>,
    /// The public ceremony configuration, serialized once: the exact bytes
    /// every admitted caller receives.
    pub(crate) ceremony_config: bytes::Bytes,
    /// Whether the configured public origin is itself in the effective set:
    /// then a same-origin `GET` of the configuration, which carries no
    /// `Origin`, is admitted on `Sec-Fetch-Site: same-origin`.
    pub(crate) public_origin_admitted: bool,
    /// The confidential exchange, present when the deployment enables GitHub.
    /// `None` means the token route is not mounted.
    pub(crate) github: Option<Arc<GithubExchange>>,
}

impl AppState {
    /// The exchange permits, when GitHub is enabled.
    pub fn exchange_permits(&self) -> Option<&Semaphore> {
        self.github.as_ref().map(|g| &g.permits)
    }
}
