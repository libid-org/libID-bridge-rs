//! Telegram's two routes, served only where Telegram is enabled:
//!
//! - the code swap, `POST {"code", "codeVerifier", "redirectUri"}` from an
//!   admitted origin, answered with Telegram's token endpoint's status and
//!   body as they arrived. The client secret is this deployment's; the caller
//!   never sends it.
//! - the key list, `GET` under the admission and CORS of `/config`, answered
//!   with Telegram's key-list bytes, media type and encoding as fetched.
//!
//! Neither a request nor an answer is logged.

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
use serde::Deserialize;

use super::{
    admission,
    bodiless_get_refusal,
    refuse,
    VARY_ON,
};
use crate::{
    state::AppState,
    telegram::ExchangeError,
};

/// The longest redirect URI passed on, in bytes.
pub const MAX_REDIRECT_URI_BYTES: usize = 512;

/// The largest request body read, in bytes.
pub const MAX_REQUEST_BYTES: usize = 2 * 1024;

/// The longest code passed on, in bytes.
pub const MAX_CODE_BYTES: usize = 512;

/// What a refusal of an unadmitted origin says.
const UNADMITTED: &str = "this route is callable only from an admitted origin";

/// The request body.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Swap {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

/// Whether `value` is 1 to `max` bytes of printable ASCII without spaces.
fn printable(value: &str, max: usize) -> bool {
    (1..=max).contains(&value.len()) && value.bytes().all(|b| (0x21..=0x7E).contains(&b))
}

/// Whether `headers` carry exactly one `Content-Type`, and it is JSON.
fn is_json(headers: &HeaderMap) -> bool {
    let mut media = headers.get_all(header::CONTENT_TYPE).iter();
    match (media.next(), media.next()) {
        (Some(one), None) => one.to_str().is_ok_and(|m| {
            m.split(';')
                .next()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
        }),
        _ => false,
    }
}

/// Whether `value` is an RFC 7636 code verifier.
fn is_pkce_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

impl Swap {
    /// The body of a request carrying no query, read and checked: JSON, within
    /// [`MAX_REQUEST_BYTES`], a code of 1 to [`MAX_CODE_BYTES`] and a redirect
    /// URI of 1 to [`MAX_REDIRECT_URI_BYTES`] printable ASCII, and an RFC 7636
    /// verifier. A refusal quotes none of it.
    async fn read(
        query: Option<String>,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<Swap, String> {
        if query.is_some_and(|q| !q.is_empty()) {
            return Err("this route takes no query".into());
        }
        if !is_json(headers) {
            return Err("the request body must be Content-Type: application/json".into());
        }
        let bytes = axum::body::to_bytes(body, MAX_REQUEST_BYTES)
            .await
            .map_err(|_| {
                format!(
                    "the request body could not be read within {MAX_REQUEST_BYTES} bytes"
                )
            })?;
        let swap: Swap = serde_json::from_slice(&bytes).map_err(|_| {
            "the request body must be {\"code\", \"codeVerifier\", \"redirectUri\"}, \
             all strings"
                .to_owned()
        })?;
        if !printable(&swap.code, MAX_CODE_BYTES) {
            return Err(format!(
                "code must be 1 to {MAX_CODE_BYTES} bytes of printable ASCII"
            ));
        }
        if !printable(&swap.redirect_uri, MAX_REDIRECT_URI_BYTES) {
            return Err(format!(
                "redirectUri must be 1 to {MAX_REDIRECT_URI_BYTES} bytes of printable \
                 ASCII"
            ));
        }
        if !is_pkce_verifier(&swap.code_verifier) {
            return Err(
                "codeVerifier must be 43 to 128 characters of [A-Za-z0-9-._~]".into(),
            );
        }
        Ok(swap)
    }
}

/// `OPTIONS /api/v1/ceremony/telegram/token`: grants `POST` with a
/// `Content-Type` header to an admitted origin.
pub async fn preflight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    super::preflight(
        &state,
        &headers,
        UNADMITTED,
        "POST, OPTIONS",
        Some(HeaderValue::from_static("content-type")),
    )
}

/// `POST /api/v1/ceremony/telegram/token`.
pub async fn token(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(exchange) = state.telegram.as_ref().map(|t| &t.exchange) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Admission is decided before anything else is looked at.
    let Some(admission) = admission(&state, &headers) else {
        return refuse(StatusCode::FORBIDDEN, UNADMITTED, None);
    };
    let admitted = admission.allow_origin();

    let swap = match Swap::read(query, &headers, body).await {
        Ok(swap) => swap,
        Err(message) => return refuse(StatusCode::BAD_REQUEST, &message, admitted),
    };

    let answer = match exchange
        .exchange(&swap.code, &swap.code_verifier, &swap.redirect_uri)
        .await
    {
        Ok(answer) => answer,
        Err(e) => {
            return bad_gateway(exchange.url(), "Telegram's token endpoint", &e, admitted)
        }
    };

    let mut out = HeaderMap::new();
    out.insert(header::VARY, HeaderValue::from_static(VARY_ON));
    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // The exact origin that asked, never `*`; no credentials.
    if let Some(origin) = admitted {
        out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    (answer.status, out, answer.body).into_response()
}

/// A `502` naming the kind of failure; the detail stays in the log.
fn bad_gateway(
    url: &str,
    what: &str,
    e: &ExchangeError,
    admitted: Option<HeaderValue>,
) -> Response {
    tracing::warn!(
        url,
        detail = %e,
        kind = e.kind(),
        "{what} gave no answer to pass on"
    );
    refuse(
        StatusCode::BAD_GATEWAY,
        &format!("{what} {}", e.public()),
        admitted,
    )
}

/// `OPTIONS /api/v1/ceremony/telegram/jwks`: the preflight of `/config`.
pub async fn keys_preflight(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    // The key list is public and read without credentials, as `/config` is.
    let asked = headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS).cloned();
    super::preflight(&state, &headers, UNADMITTED, "GET", asked)
}

/// `GET /api/v1/ceremony/telegram/jwks`.
pub async fn keys(
    State(state): State<Arc<AppState>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(list) = state.telegram.as_ref().map(|t| &t.keys) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Admission is decided before anything else is looked at.
    let Some(admission) = admission(&state, &headers) else {
        return refuse(StatusCode::FORBIDDEN, UNADMITTED, None);
    };
    let admitted = admission.allow_origin();

    if let Some(message) = bodiless_get_refusal(query.as_deref(), &body) {
        return refuse(StatusCode::BAD_REQUEST, message, admitted);
    }

    let keys = match list.keys().await {
        Ok(keys) => keys,
        Err(e) => return bad_gateway(list.url(), "Telegram's key list", &e, admitted),
    };

    // Built bare, so no content type is added that Telegram did not send.
    let mut response = Response::new(Body::from(keys.body));
    let out = response.headers_mut();
    out.insert(header::VARY, HeaderValue::from_static(VARY_ON));
    if let Some(media) = keys.content_type {
        out.insert(header::CONTENT_TYPE, media);
    }
    if let Some(encoding) = keys.content_encoding {
        out.insert(header::CONTENT_ENCODING, encoding);
    }
    if let Some(origin) = admitted {
        out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    response
}
