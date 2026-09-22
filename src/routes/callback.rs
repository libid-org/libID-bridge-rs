//! The registered OAuth callback: one document, served at the configured
//! path, identical for every request. The handler reads nothing from the
//! request: no URI, query, `Origin` or `Referer`.
//!
//! A deployment whose Distribution has not answered yet has no document, and
//! says so with an inert page carrying no script, style, link or form. The
//! ceremony cannot start, and nothing else this bridge serves is affected.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{
        header,
        HeaderName,
        StatusCode,
    },
    response::{
        IntoResponse,
        Response,
    },
};

use crate::state::AppState;

/// `cross-origin-opener-policy`, which is not one of the constants `header`
/// names.
const COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");

/// What a deployment with no document answers with: no script, no link, no
/// form, and nothing derived from the request. `why` is the last retrieval
/// failure, which names this deployment's own Distribution and no secret.
fn no_document(why: Option<&str>) -> String {
    let detail = why.map(escaped).unwrap_or_else(|| {
        "The ceremony documents have not been retrieved yet.".to_owned()
    });
    format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>libID</title><body><main><p>libID cannot complete this sign-in \
         right now. Return to the application and start again.</p>\
         <p>{detail}</p></main></body></html>"
    )
}

/// `text` with the three characters a parser reads as markup written as
/// entities, so a failure detail is read as text wherever it came from.
fn escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The policy of the inert page: everything denied.
const NO_DOCUMENT_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'";

/// How long a caller is asked to wait before the ceremony is retried.
const RETRY_AFTER: &str = "30";

/// `GET {callback path}`.
pub(crate) async fn callback(State(state): State<Arc<AppState>>) -> Response {
    // The borrow guard is released before the response is built.
    let published = state.callback.borrow().clone();
    let Some(published) = published else {
        state.metrics.callback_unavailable();
        let why = state.failure.borrow().clone();
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [
                (COOP, "unsafe-none"),
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::REFERRER_POLICY, "no-referrer"),
                (header::RETRY_AFTER, RETRY_AFTER),
                (header::CONTENT_SECURITY_POLICY, NO_DOCUMENT_POLICY),
            ],
            no_document(why.as_deref()),
        )
            .into_response();
    };

    state.metrics.callback_served();
    (
        [
            // `unsafe-none` keeps the opener the application holds.
            (COOP, "unsafe-none"),
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        // Computed when the document was composed, over the bytes served.
        [(
            header::CONTENT_SECURITY_POLICY,
            published.document.csp.clone(),
        )],
        published.document.body.clone(),
    )
        .into_response()
}
