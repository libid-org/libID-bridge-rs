//! The public ceremony configuration: `{ ccdpOrigin, platforms }`, one record
//! built at startup and served to every admitted origin, and to a same-origin
//! read. It carries no secret, no admitted origin, no asset URL and no notary
//! setting. A browser that must preflight its `GET` is answered here too, by
//! the same admission rule.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{
        RawQuery,
        State,
    },
    http::{
        header,
        HeaderMap,
        HeaderValue,
        StatusCode,
    },
    response::{
        IntoResponse,
        Response,
    },
};

use super::{
    admission,
    bodiless_get_refusal,
    refuse,
    VARY_ON,
};
use crate::state::AppState;

/// What a refusal of an unadmitted origin says.
const UNADMITTED: &str = "this configuration is readable only from an admitted origin";

/// `OPTIONS /api/v1/ceremony/config`: the preflight a browser sends before a
/// `GET` carrying a header a simple request may not.
///
/// It admits what the `GET` admits: exactly one `Origin`, in the effective
/// set. A preflight carries one by definition, so the same-origin case is not
/// one and is refused like any other. The answer grants `GET`, the headers the
/// request asked for, and no credentials.
pub async fn preflight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    // The record is public and read without credentials, so the headers a
    // caller wants to send are granted as asked rather than from a list this
    // service would have to keep.
    let asked = headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS).cloned();
    super::preflight(&state, &headers, UNADMITTED, "GET", asked)
}

/// `GET /api/v1/ceremony/config`.
pub async fn config(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Admission is decided before anything else is looked at.
    let Some(admission) = admission(&state, &headers) else {
        return refuse(StatusCode::FORBIDDEN, UNADMITTED, None);
    };

    let admitted = admission.allow_origin();
    if let Some(message) = bodiless_get_refusal(query.as_deref(), &body) {
        return refuse(StatusCode::BAD_REQUEST, message, admitted);
    }

    // `insert`, not append: the `Bytes` body would otherwise add its own
    // content type.
    let mut out = HeaderMap::new();
    out.insert(header::VARY, HeaderValue::from_static(VARY_ON));
    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // The exact origin that asked, never `*`; no credentials. A same-origin
    // read gets no allow-origin.
    if let Some(origin) = admitted {
        out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }

    (StatusCode::OK, out, state.ceremony_config.clone()).into_response()
}
