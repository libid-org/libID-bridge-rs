//! Telegram's code swap and key list. Telegram answers no CORS, so the browser
//! calls these: the swap is sent with the private client secret, the key list
//! fetched without credentials, and Telegram's answers pass through as they
//! arrived. Neither a request nor an answer is logged.

use std::sync::{
    Arc,
    Mutex,
};

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
use http_body_util::{
    BodyExt,
    Full,
};

use super::config::{
    admission,
    refuse,
    Admission,
    VARY_ON,
};
use crate::{
    artifact::upstream::USER_AGENT,
    state::AppState,
};

/// How long one upstream call may take, dialing included.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long a fetched key list is served from cache: the keeper's cadence,
/// since a new key is unusable on chain until the keeper rotates it in.
const KEYS_TTL: std::time::Duration = std::time::Duration::from_secs(3600);
const UNADMITTED: &str = "this route is callable only from an admitted origin";

type Client = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

/// Why an upstream call gave nothing to pass on: what the caller is told,
/// and the detail the log gets.
type Failure = (&'static str, String);

const UNREACHABLE: &str = "could not be reached";

/// Telegram's client, the connections to it, and the cached key list.
pub struct Telegram {
    client: crate::deployment::TelegramClient,
    http: Client,
    keys: Mutex<Option<(tokio::time::Instant, HeaderMap, Bytes)>>,
}

impl Telegram {
    /// The routes' upstream for `client`.
    pub fn new(client: crate::deployment::TelegramClient) -> Telegram {
        Telegram {
            client,
            http: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build(crate::artifact::upstream::connector()),
            keys: Mutex::default(),
        }
    }

    /// One request within [`TIMEOUT`]: a redirect refused, the body bounded.
    async fn call(
        &self,
        request: hyper::Request<Full<Bytes>>,
        limit: usize,
    ) -> Result<(StatusCode, HeaderMap, Bytes), Failure> {
        let call = async {
            let response = self
                .http
                .request(request)
                .await
                .map_err(|e| (UNREACHABLE, format!("{e:?}")))?;
            if response.status().is_redirection() {
                let detail = response.status().to_string();
                return Err(("answered a redirect this bridge does not follow", detail));
            }
            let (parts, body) = response.into_parts();
            let body = http_body_util::Limited::new(body, limit)
                .collect()
                .await
                .map_err(|e| match e.is::<http_body_util::LengthLimitError>() {
                    true => ("answered more than this bridge passes on", e.to_string()),
                    false => (UNREACHABLE, e.to_string()),
                })?;
            Ok((parts.status, parts.headers, body.to_bytes()))
        };
        tokio::time::timeout(TIMEOUT, call)
            .await
            .map_err(|_| ("did not answer in time", String::new()))?
    }

    /// The key list's media type, encoding and bytes: cached while fresh, else
    /// fetched. The lock is never held across a fetch.
    async fn keys(&self) -> Result<(HeaderMap, Bytes), Failure> {
        let cached = self.keys.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some((_, headers, body)) =
            cached.filter(|(at, ..)| at.elapsed() < KEYS_TTL)
        {
            return Ok((headers, body));
        }
        let request = hyper::Request::get(self.client.jwks_url.clone())
            .header(header::USER_AGENT, USER_AGENT)
            .body(Full::default())
            .expect("a URI checked at startup");
        let (status, upstream, body) = self.call(request, 64 * 1024).await?;
        if status != StatusCode::OK {
            return Err(("answered an error", status.to_string()));
        }
        let mut headers = HeaderMap::new();
        for name in [header::CONTENT_TYPE, header::CONTENT_ENCODING] {
            if let Some(value) = upstream.get(&name) {
                headers.insert(name, value.clone());
            }
        }
        *self.keys.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((tokio::time::Instant::now(), headers.clone(), body.clone()));
        Ok((headers, body))
    }
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

/// Whether `headers` carry exactly one `Content-Type`, and it is JSON.
fn is_json(headers: &HeaderMap) -> bool {
    let mut media = headers.get_all(header::CONTENT_TYPE).iter();
    match (media.next(), media.next()) {
        (Some(one), None) => one.to_str().is_ok_and(|m| {
            let essence = m.split(';').next().unwrap_or_default();
            essence.trim().eq_ignore_ascii_case("application/json")
        }),
        _ => false,
    }
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
    let client = &telegram.client;
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &swap.code)
        .append_pair("redirect_uri", &swap.redirect_uri)
        .append_pair("code_verifier", &swap.code_verifier)
        .append_pair("client_id", &client.client_id)
        .finish();
    let request = hyper::Request::post(client.token_url.clone())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .header(header::USER_AGENT, USER_AGENT)
        .header(header::AUTHORIZATION, client.authorization.clone())
        .body(Full::from(form))
        .expect("a URI checked at startup");
    match telegram.call(request, 8 * 1024).await {
        Ok((status, _, body)) => {
            let json = HeaderValue::from_static("application/json");
            let headers = HeaderMap::from_iter([(header::CONTENT_TYPE, json)]);
            answer(status, headers, origin, body)
        }
        Err(e) => bad_gateway("Telegram's token endpoint", &client.token_url, e, origin),
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
        Ok((headers, body)) => answer(StatusCode::OK, headers, origin, body),
        Err(e) => {
            bad_gateway("Telegram's key list", &telegram.client.jwks_url, e, origin)
        }
    }
}
