//! The OAuth Bridge's route table:
//!
//! - `GET  /health`
//! - `GET  /api/v1/ceremony/config`
//! - `GET  /auth/callback`
//! - `OPTIONS`, `POST /api/v1/ceremony/github-token` (only when GitHub is enabled)
//!
//! Everything the browser runs is served by the CCDP Distribution at the
//! configured `ccdpOrigin`. One admission rule gates every route that has one:
//! exactly one `Origin`, in the effective set `allowedAppOrigins ∪
//! {ccdpOrigin}`. CORS is answered in two places: the configuration route
//! echoes the admitted origin itself, and the token route carries a layer
//! answering the preflight for the admitted origins (`POST`, `Content-Type`,
//! no credentials). The callback carries none: it is a top-level navigation.

pub(crate) mod callback;
pub(crate) mod config;
pub(crate) mod github_token;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    http::{
        header,
        HeaderName,
        HeaderValue,
    },
    routing::{
        get,
        post,
    },
    Router,
};

use tower_http::cors::{
    AllowOrigin,
    CorsLayer,
};

use crate::state::AppState;

/// How many `Origin` headers a request carried. Both gated routes admit
/// exactly one, matching an admitted origin.
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

/// `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`, on every
/// response this service writes.
pub(crate) const ON_EVERY_RESPONSE: [(HeaderName, HeaderValue); 2] = [
    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
    (
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ),
];

/// Liveness probe: `OK`. Not one of the contract's three routes; the published
/// image's `HEALTHCHECK` targets it. It is the one route that accepts a query.
async fn health() -> impl axum::response::IntoResponse {
    (ON_EVERY_RESPONSE, "OK")
}

/// The liveness probe.
pub(crate) const HEALTH_PATH: &str = "/health";
/// The registered OAuth callback: the callback document.
pub const CALLBACK_PATH: &str = "/auth/callback";
/// The public ceremony configuration.
pub(crate) const CONFIG_PATH: &str = "/api/v1/ceremony/config";
/// The confidential GitHub exchange.
pub(crate) const TOKEN_PATH: &str = "/api/v1/ceremony/github-token";

/// The route table for this deployment: the token route only where GitHub is
/// enabled.
pub fn build_router(state: Arc<AppState>) -> Router {
    let mut router = Router::new()
        .route(HEALTH_PATH, get(health))
        .route(CONFIG_PATH, get(config::config))
        .route(CALLBACK_PATH, get(callback::callback))
        .with_state(state.clone());

    if let Some(github) = &state.github {
        router = router.merge(
            Router::new()
                .route(TOKEN_PATH, post(github_token::github_token))
                // A `TokenRequest` is a 1 KiB code, a 43-character verifier
                // and a notary origin; the extractor runs before the handler.
                .layer(DefaultBodyLimit::max(8 * 1024))
                // `route_layer` applies only where this route matched; `layer`
                // would also wrap the fallback `merge` carries to every path.
                .route_layer(token_cors(&github.admitted))
                .with_state(github.clone()),
        );
    }
    router
}

/// The token route's CORS layer: the admitted origins as a list, so a caller
/// from any other origin gets no allow-origin header; `POST`, `Content-Type`,
/// no credentials.
fn token_cors(admitted: &[HeaderValue]) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(admitted.iter().cloned()))
        .allow_methods([axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
}
