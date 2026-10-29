//! Telegram's code swap: `POST {"code", "codeVerifier"}` from an admitted
//! origin, answered with Telegram's token endpoint's status and body as they
//! arrived. Served only where Telegram is enabled. The redirect URI and the
//! client secret are this deployment's; the caller sends neither. Neither the
//! request nor the answer is logged.

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
    refuse,
    Admission,
    VARY_ON,
};
use crate::{
    state::AppState,
    telegram::ExchangeError,
};

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
}

impl Swap {
    /// The body of a request carrying no query, read and checked: JSON, within
    /// [`MAX_REQUEST_BYTES`], a code of 1 to [`MAX_CODE_BYTES`] printable
    /// ASCII, and an RFC 7636 verifier. A refusal quotes none of it.
    async fn read(
        query: Option<String>,
        headers: &HeaderMap,
        body: Body,
    ) -> Result<Swap, String> {
        if query.is_some_and(|q| !q.is_empty()) {
            return Err("this route takes no query".into());
        }
        let mut media = headers.get_all(header::CONTENT_TYPE).iter();
        let json = match (media.next(), media.next()) {
            (Some(one), None) => one.to_str().is_ok_and(|m| {
                m.split(';')
                    .next()
                    .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
            }),
            _ => false,
        };
        if !json {
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
            "the request body must be {\"code\", \"codeVerifier\"}, both strings"
                .to_owned()
        })?;
        let code_ok = (1..=MAX_CODE_BYTES).contains(&swap.code.len())
            && swap.code.bytes().all(|b| (0x21..=0x7E).contains(&b));
        if !code_ok {
            return Err(format!(
                "code must be 1 to {MAX_CODE_BYTES} bytes of printable ASCII"
            ));
        }
        let verifier_ok = (43..=128).contains(&swap.code_verifier.len())
            && swap
                .code_verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
        if !verifier_ok {
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
    let Some(exchange) = state.telegram.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Admission is decided before anything else is looked at.
    let Some(admission) = admission(&state, &headers) else {
        return refuse(StatusCode::FORBIDDEN, UNADMITTED, None);
    };
    let admitted = match admission {
        Admission::Listed(origin) => Some(origin),
        Admission::SameOrigin => None,
    };

    let swap = match Swap::read(query, &headers, body).await {
        Ok(swap) => swap,
        Err(message) => return refuse(StatusCode::BAD_REQUEST, &message, admitted),
    };

    let answer = match exchange.exchange(&swap.code, &swap.code_verifier).await {
        Ok(answer) => answer,
        Err(e) => {
            tracing::warn!(
                url = exchange.url(),
                detail = %e,
                kind = e.kind(),
                "Telegram's token endpoint gave no answer to pass on"
            );
            // The operator's detail stays in the log.
            let message = match e {
                ExchangeError::Unreachable(_) => {
                    "Telegram's token endpoint could not be reached".to_owned()
                }
                e => format!("Telegram's token endpoint {e}"),
            };
            return refuse(StatusCode::BAD_GATEWAY, &message, admitted);
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
