//! The OAuth Bridge's route table:
//!
//! - `GET  /health`
//! - `GET  /metrics`
//! - `GET`, `OPTIONS` `/api/v1/ceremony/config`
//! - `GET  /auth/callback`
//!
//! Everything the browser runs is served by the CCDP Distribution at the
//! configured `ccdpOrigin`. The configuration route admits exactly one
//! `Origin`, in the effective set `allowedAppOrigins ∪ {ccdpOrigin}`, echoes
//! it as the one origin allowed, and answers on `OPTIONS` the preflight a
//! caller sending its own header needs. The callback carries no CORS: it is a
//! top-level navigation. No other path is served, and no route performs a
//! token exchange or opens a notary connection.

pub(crate) mod callback;
pub(crate) mod config;

use std::sync::Arc;

use axum::{
    http::{
        header,
        HeaderValue,
        StatusCode,
    },
    response::{
        IntoResponse,
        Response,
    },
    routing::get,
    Router,
};

use crate::state::AppState;

/// How many `Origin` headers a request carried. The configuration route
/// admits exactly one, matching an admitted origin.
pub(crate) enum Origins<'a> {
    /// No `Origin`.
    Absent,
    /// Exactly one.
    One(&'a axum::http::HeaderValue),
    /// More than one; refused.
    Several,
}

impl<'a> Origins<'a> {
    /// The `Origin` headers of `headers`.
    pub(crate) fn of(headers: &'a axum::http::HeaderMap) -> Self {
        let mut seen = headers.get_all(axum::http::header::ORIGIN).iter();
        match (seen.next(), seen.next()) {
            (Some(one), None) => Origins::One(one),
            (Some(_), Some(_)) => Origins::Several,
            (None, _) => Origins::Absent,
        }
    }
}

/// `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`, put on
/// every response this service writes, a refusal and an unrouted path
/// included.
async fn standing_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Liveness probe: `OK`. Not one of the contract's routes; the published
/// image's `HEALTHCHECK` targets it. It reads nothing from the request, and
/// answers whether or not a callback document is available, because the
/// Distribution's availability is not this deployment's.
async fn health() -> impl axum::response::IntoResponse {
    "OK"
}

/// What this deployment counts, in the Prometheus text exposition format.
/// Scraped from the pod; not part of the ceremony contract.
async fn metrics(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        state.metrics.rendered(),
    )
        .into_response()
}

/// Every path this service does not serve.
async fn unrouted() -> Response {
    (StatusCode::NOT_FOUND, "").into_response()
}

/// The liveness probe.
pub(crate) const HEALTH_PATH: &str = "/health";
/// What this deployment counts.
pub(crate) const METRICS_PATH: &str = "/metrics";
/// The registered OAuth callback: the callback document.
pub const CALLBACK_PATH: &str = "/auth/callback";
/// The public ceremony configuration.
pub const CONFIG_PATH: &str = "/api/v1/ceremony/config";

/// The route table: the same routes for every deployment.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(HEALTH_PATH, get(health))
        .route(METRICS_PATH, get(metrics))
        .route(CONFIG_PATH, get(config::config).options(config::preflight))
        .route(CALLBACK_PATH, get(callback::callback))
        .fallback(unrouted)
        .layer(axum::middleware::map_response(standing_headers))
        .with_state(state)
}
