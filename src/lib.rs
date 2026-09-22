//! The OAuth Bridge of a libID ceremony. The contract is `specs/oauth-bridge.md`
//! in the libid repository.
//!
//! It publishes the configuration an application starts from and serves the
//! one callback document the OAuth platforms redirect back to. `/health` is a
//! liveness probe for the container healthcheck and `/metrics` is what this
//! deployment counts.
//!
//! The callback document is the CCDP Distribution's artifact with this
//! deployment's data inserted into its one slot; everything the browser runs
//! after the callback is served by that Distribution. This service performs
//! no token exchange, opens no notary connection, verifies no proof, holds no
//! secret and no key of its own, keeps no ceremony state, and talks to no
//! chain.
//!
//! The Distribution is a separate deployment and this one starts without it.
//! The callback route says it has no document until a retrieval produces one,
//! and keeps serving the last one it has when a later retrieval does not.

#![warn(missing_docs)]

pub mod artifact;
pub mod config;
pub mod deployment;
pub mod error;
pub mod metrics;
pub mod origin;
pub mod routes;
pub mod state;

use std::sync::Arc;

use error::Result;
use state::AppState;

/// A deployment that has started: the state its routes read, and the
/// refresher that keeps the callback document current.
pub struct Bridge {
    /// What the routes read.
    pub state: Arc<AppState>,
    /// What keeps the callback document current.
    pub refresher: artifact::upstream::Refresher,
}

impl Bridge {
    /// Check the deployment and build what the routes read. Everything that
    /// must be well-formed for a request to succeed is checked here, at
    /// startup; the error is the first thing that was not.
    ///
    /// No network request is made. The callback artifact is retrieved by the
    /// refresher, so a Distribution that is unreachable delays the callback
    /// document and stops nothing.
    pub fn start(cfg: &config::Config) -> Result<Bridge> {
        let deployment = deployment::Deployment::checked(cfg)?;
        let upstream = artifact::upstream::Upstream::new(&deployment.ccdp_origin);
        let (sender, callback) = tokio::sync::watch::channel(None);
        let (failed, failure) = tokio::sync::watch::channel(None);
        let metrics = Arc::new(metrics::Metrics::new());
        let state = Arc::new(AppState {
            callback,
            allowed_origins: deployment.allowed_origins.clone(),
            ceremony_config: deployment.ceremony_config(),
            failure,
            metrics: metrics.clone(),
        });
        let refresher = artifact::upstream::Refresher::new(
            upstream,
            deployment.allowed_origins,
            sender,
            failed,
            metrics,
        );
        Ok(Bridge { state, refresher })
    }
}

/// Serve `bridge` on `listener` until `shutdown` resolves; in-flight requests
/// finish first. The callback artifact is revalidated for as long as this
/// runs.
pub async fn serve(
    bridge: Bridge,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let app = routes::build_router(bridge.state);
    let refreshing =
        tokio::spawn(bridge.refresher.run(artifact::upstream::Schedule::DEPLOYED));
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await;
    refreshing.abort();
    served
}
