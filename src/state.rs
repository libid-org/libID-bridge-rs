//! What the bridge holds while it runs: configuration read once at startup,
//! and the callback document as last retrieved.
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
    /// the refresher. Never empty: startup retrieves an artifact or the
    /// process does not start. A test that waits for a replacement clones the
    /// receiver and awaits a change.
    pub(crate) callback: watch::Receiver<Arc<crate::artifact::Published>>,
    /// The effective admission set `allowedAppOrigins ∪ {ccdpOrigin}`: the one
    /// rule the configuration route applies, and what the callback document
    /// is told.
    pub(crate) allowed_origins: Arc<[crate::origin::Origin]>,
    /// The public ceremony configuration, serialized once: the exact bytes
    /// every admitted caller receives.
    pub(crate) ceremony_config: bytes::Bytes,
}
