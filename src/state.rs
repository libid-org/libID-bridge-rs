//! What the bridge holds while it runs: configuration read once at startup,
//! each product of the Distribution as last accepted, and the numbers it
//! publishes.
//!
//! There is no ceremony state. Each request is answered in isolation and
//! shares nothing mutable with another; a restart or a lost response leaves
//! no record.

use std::sync::Arc;

use tokio::sync::watch;

/// One product of the Distribution's retrievals as the routes read it: what
/// the last accepting retrieval produced, and why the last retrieval failed.
/// The refresher holds the sending halves and replaces each product
/// independently of the other. A test that waits for a replacement clones
/// `current` and awaits a change.
pub struct Retrieved<T> {
    /// What was last accepted, replaced whole. `None` until a retrieval
    /// accepts one, which is the refresher's and not startup's.
    pub current: watch::Receiver<Option<Arc<T>>>,
    /// Why the last retrieval failed, cleared by one that succeeds, a `304`
    /// included. It names only this deployment's own Distribution URL.
    pub failure: watch::Receiver<Option<String>>,
    /// Where the product is retrieved from: what a route says it is waiting
    /// on before any retrieval has ended.
    pub url: String,
}

impl<T> Retrieved<T> {
    /// Why a route has nothing to serve: the last failure, or, while no
    /// retrieval has ended, that the resource has not been retrieved yet.
    pub fn why_nothing(&self) -> String {
        self.failure
            .borrow()
            .clone()
            .unwrap_or_else(|| format!("{} has not been retrieved yet", self.url))
    }
}

/// What a route reads. Nothing here retrieves or publishes; the refresher
/// that does holds the sending halves and nothing else of this.
pub struct AppState {
    /// The callback document, the policy it is served under, and the validator
    /// it was retrieved with: read by the callback route.
    pub callback: Retrieved<crate::artifact::Published>,
    /// The public ceremony configuration, serialized once per accepted
    /// version list: the exact bytes every admitted caller receives, read by
    /// the configuration route.
    pub ceremony_config: Retrieved<crate::deployment::PublishedConfig>,
    /// The effective admission set `allowedAppOrigins ∪ {ccdpOrigin}`: the one
    /// rule the configuration route applies, and what the callback document
    /// is told. A member admits one origin or the subdomains of one host
    /// suffix; the CCDP origin is a member of it literally.
    pub allowed_origins: Arc<[crate::origin::Admitted]>,
    /// What this deployment counts.
    pub metrics: Arc<crate::metrics::Metrics>,
}
