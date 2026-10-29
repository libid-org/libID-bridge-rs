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

use super::config::{
    admission,
    refuse,
    Admission,
    VARY_ON,
};
use crate::{
    state::AppState,
    telegram::{
        copied,
        is_json,
        Failure,
    },
};

const UNADMITTED: &str = "this route is callable only from an admitted origin";

/// An error Telegram answers a swap with; any other field is ignored.
#[derive(serde::Deserialize)]
struct Refusal {
    error: String,
}

/// The swap request body.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Swap {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

/// Whether `value` is 1 to 512 bytes of printable ASCII without spaces.
fn printable(value: &str) -> bool {
    (1..=512).contains(&value.len()) && value.bytes().all(|b| (0x21..=0x7E).contains(&b))
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
) -> Result<Swap, &'static str> {
    if query.is_some_and(|q| !q.is_empty()) {
        return Err("this route takes no query");
    }
    if !is_json(headers) {
        return Err("the request body must be Content-Type: application/json");
    }
    let bytes = axum::body::to_bytes(body, 2048)
        .await
        .map_err(|_| "the request body could not be read within 2048 bytes")?;
    let swap: Swap = serde_json::from_slice(&bytes).map_err(|_| {
        "the request body must be {\"code\", \"codeVerifier\", \"redirectUri\"}, all strings"
    })?;
    if !printable(&swap.code) {
        Err("code must be 1 to 512 bytes of printable ASCII")
    } else if !printable(&swap.redirect_uri) {
        Err("redirectUri must be 1 to 512 bytes of printable ASCII")
    } else if !is_verifier(&swap.code_verifier) {
        Err("codeVerifier must be 43 to 128 characters of [A-Za-z0-9-._~]")
    } else {
        Ok(swap)
    }
}

/// The allow-origin of an admitted request, or `None` for an unadmitted one.
fn admitted(state: &AppState, headers: &HeaderMap) -> Option<Option<HeaderValue>> {
    admission(state, headers).map(|admitted| match admitted {
        Admission::Listed(origin) => Some(origin),
        Admission::SameOrigin => None,
    })
}

/// `status`, `headers` and `body`, under the CORS of `/config`.
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
fn bad_gateway(
    what: &str,
    url: &axum::http::Uri,
    failure: Failure,
    origin: Option<HeaderValue>,
) -> Response {
    let (public, detail) = failure;
    tracing::warn!(%url, detail, "{what} gave no answer to pass on");
    let message = format!("{what} {public}");
    refuse(StatusCode::BAD_GATEWAY, &message, origin)
}

/// `OPTIONS` on the swap: `/config`'s preflight, granting `POST` with
/// `Content-Type`.
pub async fn preflight(state: State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let mut response = super::config::preflight(state, headers).await;
    if response.status() == StatusCode::NO_CONTENT {
        let out = response.headers_mut();
        let methods = HeaderValue::from_static("POST, OPTIONS");
        out.insert(header::ACCESS_CONTROL_ALLOW_METHODS, methods);
        let allowed = HeaderValue::from_static("content-type");
        out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, allowed);
    }
    response
}

/// `POST /api/v1/ceremony/telegram/token`.
pub async fn token(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let telegram = state.telegram.as_ref().expect("routed only with Telegram");
    let Some(origin) = admitted(&state, &headers) else {
        return refuse(StatusCode::FORBIDDEN, UNADMITTED, None);
    };
    let swap = match read_swap(query, &headers, body).await {
        Ok(swap) => swap,
        Err(message) => return refuse(StatusCode::BAD_REQUEST, message, origin),
    };
    let swapped = telegram.swap(&swap.code, &swap.redirect_uri, &swap.code_verifier);
    match swapped.await {
        Ok((status, upstream, body)) => {
            let outcome = match serde_json::from_slice::<Refusal>(&body) {
                Ok(Refusal { error: code }) => {
                    tracing::warn!(error = %code, "Telegram refused the swap");
                    "upstream_error"
                }
                Err(_) => "ok",
            };
            state.metrics.telegram("token", outcome);
            let mut headers = copied(&upstream, &[header::CONTENT_ENCODING]);
            let json = HeaderValue::from_static("application/json");
            headers.insert(header::CONTENT_TYPE, json);
            answer(status, headers, origin, body)
        }
        Err(e) => {
            state.metrics.telegram("token", "unreachable");
            bad_gateway(
                "Telegram's token endpoint",
                &telegram.client.token_url,
                e,
                origin,
            )
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
    let Some(origin) = admitted(&state, &headers) else {
        return refuse(StatusCode::FORBIDDEN, UNADMITTED, None);
    };
    if query.is_some_and(|q| !q.is_empty()) {
        return refuse(StatusCode::BAD_REQUEST, "this route takes no query", origin);
    }
    if super::carries_body(&body) {
        let message = "this route takes no request body";
        return refuse(StatusCode::BAD_REQUEST, message, origin);
    }
    match telegram.keys().await {
        Ok((headers, body)) => {
            state.metrics.telegram("keys", "ok");
            answer(StatusCode::OK, headers, origin, body)
        }
        Err(e) => {
            state.metrics.telegram("keys", "unreachable");
            bad_gateway("Telegram's key list", &telegram.client.jwks_url, e, origin)
        }
    }
}
