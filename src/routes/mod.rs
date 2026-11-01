//! The OAuth Bridge's route table:
//!
//! - `GET  /health`
//! - `GET  /metrics`
//! - `GET`, `OPTIONS` `/api/v1/ceremony/config`
//! - `GET  /auth/callback`
//! - `POST`, `OPTIONS` `/api/v1/ceremony/telegram/token` and `GET`, `OPTIONS`
//!   `/api/v1/ceremony/telegram/jwks`, where Telegram is enabled
//!
//! Everything the browser runs is served by the CCDP Distribution at the
//! configured `ccdpOrigin`. The configuration route admits exactly one
//! `Origin`, and only one a member of the effective set
//! `allowedAppOrigins ∪ {ccdpOrigin}` admits, echoes that origin itself as
//! the one origin allowed, and answers on `OPTIONS` the preflight a
//! caller sending its own header needs. The callback carries no CORS: it is a
//! top-level navigation. The Telegram routes admit as the configuration
//! route does. No other path is served, no route opens a notary connection,
//! and no route but Telegram's swap performs a token exchange. Any other method
//! on a ceremony route, `HEAD` included, is a `405` naming the methods it serves,
//! and a request carrying a body is a `400`, Telegram's swap aside.

pub mod callback;
pub mod config;
pub mod telegram;

use std::sync::Arc;

use axum::{
    body::{
        Body,
        HttpBody as _,
    },
    http::{
        header,
        HeaderMap,
        HeaderName,
        HeaderValue,
        StatusCode,
    },
    response::{
        IntoResponse,
        Response,
    },
    routing::{
        get,
        post,
        MethodRouter,
    },
    Json,
    Router,
};
use serde_json::json;

use crate::{
    origin::Observed,
    state::AppState,
};

/// How many `Origin` headers a request carried. The configuration route
/// admits exactly one, and only where a member of the admission set admits
/// it.
pub enum Origins<'a> {
    /// No `Origin`.
    Absent,
    /// Exactly one.
    One(&'a axum::http::HeaderValue),
    /// More than one; refused.
    Several,
}

impl<'a> Origins<'a> {
    /// The `Origin` headers of `headers`.
    pub fn of(headers: &'a axum::http::HeaderMap) -> Self {
        let mut seen = headers.get_all(axum::http::header::ORIGIN).iter();
        match (seen.next(), seen.next()) {
            (Some(one), None) => Origins::One(one),
            (Some(_), Some(_)) => Origins::Several,
            (None, _) => Origins::Absent,
        }
    }
}

/// Whether a request carries a body: whether its body stream is still open
/// after the head, as any `Transfer-Encoding` or a `Content-Length` above zero
/// leaves it over HTTP/1. Only Telegram's swap takes one.
pub fn carries_body(body: &Body) -> bool {
    !body.is_end_stream()
}

/// Why a route taking no query refuses this request.
fn queried(query: Option<String>) -> Option<&'static str> {
    query
        .is_some_and(|q| !q.is_empty())
        .then_some("this route takes no query")
}

/// Why a route taking neither a query nor a body refuses this request.
fn malformed(query: Option<String>, body: &Body) -> Option<&'static str> {
    queried(query)
        .or_else(|| carries_body(body).then_some("this route takes no request body"))
}

/// What `Vary` names on every admitted-origin response: `Origin` and
/// `Sec-Fetch-Site` decide the body, on refusals too.
const VARY_ON: &str = "origin, sec-fetch-site";

/// The `403` of a route callable only from an admitted origin.
const UNADMITTED: &str = "this route is callable only from an admitted origin";

/// The fetch metadata header saying where a browser request came from,
/// relative to its target.
const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// What `Vary` names on a preflight: the origin admitted and the headers the
/// answer grants.
const PREFLIGHT_VARY_ON: &str = "origin, access-control-request-headers";

/// How long a browser may reuse one preflight answer. The admission set and
/// the method granted are fixed at startup.
const PREFLIGHT_MAX_AGE: &str = "600";

/// How a request is admitted to an admitted-origin route.
enum Admission {
    /// One `Origin` a member of the admission set admits; echoed as the
    /// allow-origin, exactly as it was sent.
    Listed(HeaderValue),
    /// No `Origin`: a same-origin browser `GET`, which carries none, on
    /// `Sec-Fetch-Site: same-origin`. It needs no CORS header.
    SameOrigin,
}

impl Admission {
    /// The allow-origin to answer with: the listed origin, or none.
    fn allow_origin(self) -> Option<HeaderValue> {
        match self {
            Admission::Listed(origin) => Some(origin),
            Admission::SameOrigin => None,
        }
    }
}

/// How this request is admitted, or `None`.
///
/// One `Origin` must be admitted by a member of the admission set: `null`, a
/// malformed value, an unadmitted one and two headers are refused whatever
/// else the request carries. With no `Origin`, exactly one `Sec-Fetch-Site:
/// same-origin` admits. `Referer`, the request host and absent fetch
/// metadata admit nothing.
fn admission(state: &AppState, headers: &HeaderMap) -> Option<Admission> {
    match Origins::of(headers) {
        Origins::One(origin) => {
            // Canonicality is the precondition of every membership test and
            // depends on no member, so the header is read once however long
            // the admission set is.
            let observed = Observed::stamped(origin.to_str().ok()?)?;
            state
                .allowed_origins
                .iter()
                .any(|member| member.admits(observed))
                .then(|| Admission::Listed(origin.clone()))
        }
        Origins::Several => None,
        Origins::Absent => {
            let mut sites = headers.get_all(SEC_FETCH_SITE).iter();
            match (sites.next(), sites.next()) {
                (Some(site), None) if site == "same-origin" => {
                    Some(Admission::SameOrigin)
                }
                _ => None,
            }
        }
    }
}

/// A preflight answer granting `methods` and `allow_headers`, or, where that
/// is `None`, the headers asked for. Admission is the read's.
fn grant(
    state: &AppState,
    headers: &HeaderMap,
    methods: &'static str,
    allow_headers: Option<&'static str>,
) -> Response {
    let Some(Admission::Listed(origin)) = admission(state, headers) else {
        return refuse(StatusCode::FORBIDDEN, UNADMITTED, None);
    };

    let mut out = HeaderMap::new();
    out.insert(header::VARY, HeaderValue::from_static(PREFLIGHT_VARY_ON));
    out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    out.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(methods),
    );
    out.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static(PREFLIGHT_MAX_AGE),
    );
    // Unlisted, the headers are granted as asked: no preflight grants
    // credentials, so there is no list worth keeping.
    let asked = headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS).cloned();
    if let Some(granted) = allow_headers.map(HeaderValue::from_static).or(asked) {
        out.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, granted);
    }

    (StatusCode::NO_CONTENT, out).into_response()
}

/// A refusal carries no configuration, so a caller cannot read the record out
/// of an error.
///
/// `admitted` is the origin the request was admitted from, where it was: a
/// caller refused for something other than its origin gets the header that
/// lets its browser surface the status, and one refused for its origin gets
/// nothing, so it cannot tell an unlisted origin from a malformed request.
fn refuse(status: StatusCode, message: &str, admitted: Option<HeaderValue>) -> Response {
    let mut out = HeaderMap::new();
    out.insert(header::VARY, HeaderValue::from_static(VARY_ON));
    if let Some(origin) = admitted {
        out.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    (status, out, Json(json!({ "message": message }))).into_response()
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

/// `route`, answering every method it does not name with a `405` whose
/// `Allow` is `allow`. axum's `get` answers `HEAD` by running the `GET`
/// handler, so `HEAD` is refused explicitly.
fn refusing_other_methods(
    route: MethodRouter<Arc<AppState>>,
    allow: &'static str,
) -> MethodRouter<Arc<AppState>> {
    let refuse = move || async move {
        (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, allow)]).into_response()
    };
    route.head(refuse).fallback(refuse)
}

/// The liveness probe.
pub const HEALTH_PATH: &str = "/health";
/// What this deployment counts.
pub const METRICS_PATH: &str = "/metrics";
/// The registered OAuth callback: the callback document.
pub const CALLBACK_PATH: &str = "/auth/callback";
/// The public ceremony configuration.
pub const CONFIG_PATH: &str = "/api/v1/ceremony/config";
/// Telegram's code swap.
pub const TELEGRAM_TOKEN_PATH: &str = "/api/v1/ceremony/telegram/token";
/// Telegram's key list.
pub const TELEGRAM_JWKS_PATH: &str = "/api/v1/ceremony/telegram/jwks";

/// The route table: the same for every deployment, Telegram's routes only
/// where Telegram is enabled.
pub fn build_router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        .route(HEALTH_PATH, get(health))
        .route(METRICS_PATH, get(metrics))
        .route(
            CONFIG_PATH,
            refusing_other_methods(
                get(config::config).options(config::preflight),
                "GET, OPTIONS",
            ),
        )
        .route(
            CALLBACK_PATH,
            refusing_other_methods(get(callback::callback), "GET"),
        );
    let router = match state.telegram {
        Some(_) => router
            .route(
                TELEGRAM_TOKEN_PATH,
                refusing_other_methods(
                    post(telegram::token).options(telegram::preflight),
                    "POST, OPTIONS",
                ),
            )
            .route(
                TELEGRAM_JWKS_PATH,
                refusing_other_methods(
                    get(telegram::keys).options(telegram::keys_preflight),
                    "GET, OPTIONS",
                ),
            ),
        None => router,
    };
    router
        .fallback(unrouted)
        .layer(axum::middleware::map_response(standing_headers))
        .with_state(state)
}
