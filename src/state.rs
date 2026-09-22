//! What the bridge holds while it runs: configuration read once at startup,
//! the callback document as last retrieved, and the numbers it publishes.
//!
//! There is no ceremony state. Each request is answered in isolation and
//! shares nothing mutable with another; a restart or a lost response leaves
//! no record.

use std::sync::Arc;

use tokio::sync::watch;

/// What a route reads. Nothing here retrieves or publishes; the refresher
/// that does holds the sender of `callback` and nothing else of this.
pub struct AppState {
    /// The callback document, the policy it is served under, and the validator
    /// it was retrieved with: read by the callback route, replaced whole by
    /// the refresher. `None` until the first retrieval produces one, which is
    /// the refresher's and not startup's. A test that waits for a replacement
    /// clones the receiver and awaits a change.
    pub(crate) callback: watch::Receiver<Option<Arc<crate::artifact::Published>>>,
    /// The effective admission set `allowedAppOrigins ∪ {ccdpOrigin}`: the one
    /// rule the configuration route applies, and what the callback document
    /// is told.
    pub(crate) allowed_origins: Arc<[crate::origin::Origin]>,
    /// The public ceremony configuration, serialized once: the exact bytes
    /// every admitted caller receives.
    pub(crate) ceremony_config: bytes::Bytes,
    /// Why the last retrieval produced no document, cleared by one that does.
    /// It is what the callback route reports while it has nothing to serve,
    /// and names only this deployment's own Distribution URL.
    pub(crate) failure: watch::Receiver<Option<String>>,
    /// What this deployment counts.
    pub(crate) metrics: Arc<crate::metrics::Metrics>,
}
