//! The OAuth Bridge of a libID ceremony. The contract is `specs/oauth-bridge.md`
//! in the libid repository.
//!
//! It publishes the configuration an application starts from and serves the
//! one callback document the OAuth platforms redirect back to. `/health` is a
//! liveness probe for the container healthcheck and `/metrics` is what this
//! deployment counts.
//!
//! Both come from the CCDP Distribution. The callback document is the
//! Distribution's artifact with this deployment's data inserted into its one
//! slot; the configuration names, per platform, the ceremony versions the
//! Distribution says it bundles, each with the OAuth client this
//! deployment's file assigns it. Everything the browser runs after the
//! callback is served by that Distribution. This service performs no token
//! exchange, opens no notary connection, verifies no proof, holds no secret
//! and no key of its own, keeps no ceremony state, and talks to no chain.
//!
//! The Distribution is a separate deployment and this one starts without it.
//! The callback route says it has no document and the configuration route
//! says it has no record until a retrieval produces one, and each keeps
//! serving the last it has when a later retrieval does not.

#![warn(missing_docs)]

pub mod artifact;
pub mod config;
pub mod deployment;
pub mod error;
pub mod metrics;
pub mod origin;
pub mod routes;
pub mod state;
pub mod versions;

use std::sync::Arc;

use artifact::upstream::{
    Publisher,
    Refresher,
    Resource,
    Upstream,
};
use error::Result;
use state::AppState;

/// A deployment that has started: the state its routes read, and the
/// refresher that keeps the callback document and the configuration current.
pub struct Bridge {
    /// What the routes read.
    pub state: Arc<AppState>,
    /// What keeps the callback document and the configuration current.
    pub refresher: Refresher,
}

impl Bridge {
    /// Check the deployment written in `settings` and build what the routes
    /// read. Everything that must be well-formed for a request to succeed is
    /// checked here, at startup; the error is the first thing that was not.
    ///
    /// No network request is made. The callback artifact and the version
    /// list are retrieved by the refresher, so a Distribution that is
    /// unreachable delays the callback document and the configuration and
    /// stops nothing.
    pub fn start(settings: &config::Settings) -> Result<Bridge> {
        let deployment = deployment::Deployment::checked(settings)?;
        let upstream = Upstream::new(&deployment.ccdp_origin);
        let (callback_publisher, callback) = Publisher::of(&upstream, Resource::Callback);
        let (config_publisher, ceremony_config) =
            Publisher::of(&upstream, Resource::Versions);
        let metrics = Arc::new(metrics::Metrics::new());
        let state = Arc::new(AppState {
            callback,
            ceremony_config,
            allowed_origins: deployment.allowed_origins.clone(),
            metrics: metrics.clone(),
        });
        let refresher = Refresher::new(
            upstream,
            deployment,
            callback_publisher,
            config_publisher,
            metrics,
        );
        Ok(Bridge { state, refresher })
    }
}

/// Serve `bridge` on `listener` until `shutdown` resolves; in-flight requests
/// finish first. The callback artifact and the version list are revalidated
/// for as long as this runs.
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
