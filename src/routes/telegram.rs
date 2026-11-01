//! Telegram's code swap and key list. Telegram answers no CORS, so the browser
//! calls these: the swap is sent with the private client secret, the key list
//! fetched without credentials, and Telegram's answers pass through as they
//! arrived. Neither a request nor an answer is logged, a swap's error code
//! aside.

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
    response::Response,
};
use bytes::Bytes;

use super::{
    admission,
    grant,
    refuse,
    Admission,
    UNADMITTED,
    VARY_ON,
};
use crate::{
    deployment::printable_without_whitespace,
    state::AppState,
    telegram::{
        is_json,
        Failure,
    },
};

/// The largest swap request body read, in bytes.
const MAX_SWAP_BYTES: usize = 2048;
/// The longest `code` or `redirectUri`, in bytes.
const MAX_FIELD_BYTES: usize = 512;

/// A swap's answer as read for its outcome: its `error` field alone.
#[derive(serde::Deserialize)]
struct Answer {
    error: Option<serde_json::Value>,
}

/// The swap request body.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Swap {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

/// Whether `value` is 1 to [`MAX_FIELD_BYTES`] of printable ASCII without
/// spaces.
fn printable(value: &str) -> bool {
    (1..=MAX_FIELD_BYTES).contains(&value.len()) && printable_without_whitespace(value)
}

/// Whether `value` is an RFC 7636 code verifier.
fn is_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// The swap a request carries, or why it is refused, quoting none of it.
async fn read_swap(
    query: Option<String>,
    headers: &HeaderMap,
    body: Body,
) -> Result<Swap, String> {
    if let Some(message) = super::queried(query) {
        return Err(message.into());
    }
    if !is_json(headers) {
        return Err("the request body must be Content-Type: application/json".into());
    }
    let bytes = axum::body::to_bytes(body, MAX_SWAP_BYTES)
        .await
        .map_err(|_| {
            format!("the request body could not be read within {MAX_SWAP_BYTES} bytes")
        })?;
    let swap: Swap = serde_json::from_slice(&bytes).map_err(|_| {
        "the request body must be {\"code\", \"codeVerifier\", \"redirectUri\"}, all strings"
    })?;
    let printable_rule =
        format!("must be 1 to {MAX_FIELD_BYTES} bytes of printable ASCII");
    if !printable(&swap.code) {
        Err(format!("code {printable_rule}"))
    } else if !printable(&swap.redirect_uri) {
        Err(format!("redirectUri {printable_rule}"))
    } else if !is_verifier(&swap.code_verifier) {
        Err("codeVerifier must be 43 to 128 characters of [A-Za-z0-9-._~]".into())
    } else {
        Ok(swap)
    }
}

/// `status`, `headers` and `body`, under the admitted-origin CORS.
fn answer(
    status: StatusCode,
    mut headers: HeaderMap,
    origin: Option<HeaderValue>,
    body: Bytes,
) -> Response {
    headers.insert(header::VARY, HeaderValue::from_static(VARY_ON));
    if let Some(origin) = origin {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

/// A `502` naming only the kind of failure; the detail goes to the log.
fn bad_gateway(what: &str, failure: Failure, origin: Option<HeaderValue>) -> Response {
    let (kind, detail) = failure;
    tracing::warn!(detail, "{what} gave no answer to pass on");
    let message = format!("{what} {}", kind.message());
    refuse(StatusCode::BAD_GATEWAY, &message, origin)
}

/// `ok` for a `2xx` unencoded JSON answer without `error`, else
/// `upstream_error`; a refusal's `error` is logged.
fn swap_outcome(status: StatusCode, headers: &HeaderMap, body: &Bytes) -> &'static str {
    let readable = is_json(headers) && !headers.contains_key(header::CONTENT_ENCODING);
    let read = readable.then(|| serde_json::from_slice::<Answer>(body).ok());
    match read.flatten() {
        Some(Answer { error: Some(code) }) => {
            tracing::warn!(error = %code, "Telegram refused the swap");
            "upstream_error"
        }
        Some(Answer { error: None }) if status.is_success() => "ok",
        _ => "upstream_error",
    }
}

/// `OPTIONS` on the swap: granting `POST` with `Content-Type`.
pub async fn preflight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    grant(&state, &headers, "POST, OPTIONS", Some("content-type"))
}

/// `OPTIONS` on the key list: granting `GET`.
pub async fn keys_preflight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    grant(&state, &headers, "GET", None)
}

/// `POST /api/v1/ceremony/telegram/token`.
pub async fn token(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let telegram = state.telegram.as_ref().expect("routed only with Telegram");
    let Some(origin) = admission(&state, &headers).map(Admission::allow_origin) else {
        return refuse(StatusCode::FORBIDDEN, UNADMITTED, None);
    };
    let swap = match read_swap(query, &headers, body).await {
        Ok(swap) => swap,
        Err(message) => return refuse(StatusCode::BAD_REQUEST, &message, origin),
    };
    let swapped = telegram.swap(&swap.code, &swap.redirect_uri, &swap.code_verifier);
    match swapped.await {
        Ok((status, headers, body)) => {
            state
                .metrics
                .telegram("token", swap_outcome(status, &headers, &body));
            answer(status, headers, origin, body)
        }
        Err(e) => {
            state.metrics.telegram("token", e.0.label());
            bad_gateway("Telegram's token endpoint", e, origin)
        }
    }
}

/// `GET /api/v1/ceremony/telegram/jwks`.
pub async fn keys(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let telegram = state.telegram.as_ref().expect("routed only with Telegram");
    let Some(origin) = admission(&state, &headers).map(Admission::allow_origin) else {
        return refuse(StatusCode::FORBIDDEN, UNADMITTED, None);
    };
    if let Some(message) = super::malformed(query, &body) {
        return refuse(StatusCode::BAD_REQUEST, message, origin);
    }
    let fetched = |outcome| state.metrics.telegram("keys", outcome);
    match telegram.keys(fetched).await {
        Ok((headers, body)) => answer(StatusCode::OK, headers, origin, body),
        Err(e) => bad_gateway("Telegram's key list", e, origin),
    }
}
