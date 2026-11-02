//! Telegram's private client and the calls made with it: the code swap and
//! the key list, each bounded in time and size, the key list cached.

use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{
    BodyExt,
    Full,
    LengthLimitError,
    Limited,
};
use hyper::{
    header,
    header::HeaderValue,
    HeaderMap,
    StatusCode,
    Uri,
};
use hyper_util::rt::TokioExecutor;
use tokio::{
    sync::Mutex,
    time::{
        error::Elapsed,
        Instant,
    },
};

use crate::outbound::{
    connector,
    reason,
    Connector,
    USER_AGENT,
};

/// How long one upstream call may take, dialing included.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The largest token answer passed on, in bytes.
const MAX_TOKEN_BYTES: usize = 8 * 1024;
/// The largest key list passed on, in bytes.
const MAX_KEYS_BYTES: usize = 64 * 1024;
/// How long a fetched key list is served from cache: the keeper's cadence,
/// since a new key is unusable on chain until the keeper rotates it in.
const KEYS_TTL: Duration = Duration::from_secs(3600);

/// Telegram's token endpoint.
const TOKEN_URL: &str = "https://oauth.telegram.org/token";
/// Telegram's key list.
const JWKS_URL: &str = "https://oauth.telegram.org/.well-known/jwks.json";

type Client = hyper_util::client::legacy::Client<Connector, Full<Bytes>>;

/// Why a call to Telegram gave nothing to pass on.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CallError {
    /// Telegram could not be reached, or did not finish answering.
    #[error("{0}")]
    Unreachable(String),
    /// Telegram answered with a redirect, which is refused.
    #[error("answered {0}, a redirect this bridge does not follow")]
    Redirect(StatusCode),
    /// The key list answered other than `200`.
    #[error("answered {0}")]
    Status(StatusCode),
    /// The body ran past its bound before it ended.
    #[error("the body is over the {0}-byte bound")]
    TooLarge(usize),
    /// No answer within [`TIMEOUT`].
    #[error("no answer within {limit} s: {0}", limit = TIMEOUT.as_secs())]
    Timeout(#[from] Elapsed),
}

impl CallError {
    /// The short name this failure is counted and logged under.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            CallError::Unreachable(_) => "unreachable",
            CallError::Redirect(_) => "redirect",
            CallError::Status(_) => "status",
            CallError::TooLarge(_) => "too-large",
            CallError::Timeout(_) => "timeout",
        }
    }

    /// What the caller is told.
    pub(crate) fn message(&self) -> &'static str {
        match self {
            CallError::Unreachable(_) => "could not be reached",
            CallError::Redirect(_) => "answered a redirect this bridge does not follow",
            CallError::Status(_) => "answered an error",
            CallError::TooLarge(_) => "answered more than this bridge passes on",
            CallError::Timeout(_) => "did not answer in time",
        }
    }
}

/// An answer passed on: Telegram's status, its media type and encoding, and
/// its body.
#[derive(Clone)]
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

/// A key list held, and when its fetch started.
struct Cached {
    at: Instant,
    reply: Reply,
}

/// Telegram's client, checked at startup. `Debug` shows no secret.
#[derive(Clone, Debug)]
pub struct TelegramClient {
    /// The public client id.
    client_id: String,
    /// `Basic base64(client_id:secret)`, marked sensitive.
    authorization: HeaderValue,
    /// The token endpoint.
    token_url: Uri,
    /// The key list.
    jwks_url: Uri,
}

impl TelegramClient {
    /// The client `client_id` authenticating with `secret`; both form-encode
    /// to themselves.
    pub(crate) fn new(client_id: &str, secret: &str) -> TelegramClient {
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id}:{secret}"));
        let mut authorization = HeaderValue::from_str(&format!("Basic {basic}"))
            .expect("base64 is a header value");
        authorization.set_sensitive(true);
        TelegramClient {
            client_id: client_id.to_owned(),
            authorization,
            token_url: Uri::from_static(TOKEN_URL),
            jwks_url: Uri::from_static(JWKS_URL),
        }
    }

    /// This client calling `origin`'s `/token` and `/jwks` instead.
    #[cfg(feature = "test-helpers")]
    pub(crate) fn at(self, origin: &str) -> TelegramClient {
        TelegramClient {
            token_url: format!("{origin}/token").parse().expect("a test origin"),
            jwks_url: format!("{origin}/jwks").parse().expect("a test origin"),
            ..self
        }
    }
}

/// Telegram's client, the connections to it, and the cached key list.
pub struct Telegram {
    /// The client every call is made as.
    client: TelegramClient,
    http: Client,
    keys: Mutex<Option<Cached>>,
}

impl Telegram {
    /// The upstream for `client`.
    pub fn new(client: TelegramClient) -> Telegram {
        Telegram {
            client,
            http: hyper_util::client::legacy::Client::builder(TokioExecutor::new())
                .build(connector()),
            keys: Mutex::default(),
        }
    }

    /// One request within [`TIMEOUT`]: a redirect refused, the body bounded,
    /// the answer's media type and encoding kept.
    async fn call(
        &self,
        request: hyper::Request<Full<Bytes>>,
        limit: usize,
    ) -> Result<Reply, CallError> {
        let call = async {
            let response = self
                .http
                .request(request)
                .await
                .map_err(|e| CallError::Unreachable(reason(&e)))?;
            if response.status().is_redirection() {
                return Err(CallError::Redirect(response.status()));
            }
            let (parts, body) = response.into_parts();
            let body = Limited::new(body, limit).collect().await.map_err(|e| {
                match e.is::<LengthLimitError>() {
                    true => CallError::TooLarge(limit),
                    false => CallError::Unreachable(reason(&*e)),
                }
            })?;
            Ok(Reply {
                status: parts.status,
                headers: copied(
                    &parts.headers,
                    &[header::CONTENT_TYPE, header::CONTENT_ENCODING],
                ),
                body: body.to_bytes(),
            })
        };
        tokio::time::timeout(TIMEOUT, call).await?
    }

    /// Telegram's answer to swapping `code`, sent with the client secret.
    pub(crate) async fn swap(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<Reply, CallError> {
        let client = &self.client;
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code_verifier", code_verifier)
            .append_pair("client_id", &client.client_id)
            .finish();
        let request = hyper::Request::post(client.token_url.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::USER_AGENT, USER_AGENT)
            .header(header::AUTHORIZATION, client.authorization.clone())
            .body(Full::from(form))
            .expect("a URI and constant headers");
        self.call(request, MAX_TOKEN_BYTES).await
    }

    /// The key list: cached while fresh, else fetched, and cached only when a
    /// nonempty JSON `200`; any other `200` passes through. Each fetch's
    /// outcome goes to `fetched`. One fetch runs at a time, holding the cache;
    /// a caller that waited on it gets what it cached.
    pub(crate) async fn keys(
        &self,
        fetched: impl FnOnce(&'static str),
    ) -> Result<Reply, CallError> {
        let mut keys = self.keys.lock().await;
        if let Some(fresh) = keys.as_ref().filter(|c| c.at.elapsed() < KEYS_TTL) {
            return Ok(fresh.reply.clone());
        }
        let started = Instant::now();
        let reply = match self.fetch_keys().await {
            Ok(reply) => reply,
            Err(e) => {
                fetched(e.kind());
                return Err(e);
            }
        };
        if is_json(&reply.headers) && !reply.body.is_empty() {
            fetched("ok");
            *keys = Some(Cached {
                at: started,
                reply: reply.clone(),
            });
        } else {
            fetched("upstream-error");
        }
        Ok(reply)
    }

    /// One fetch of the key list, a status other than `200` refused.
    async fn fetch_keys(&self) -> Result<Reply, CallError> {
        let request = hyper::Request::get(self.client.jwks_url.clone())
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::USER_AGENT, USER_AGENT)
            .body(Full::default())
            .expect("a URI and constant headers");
        let reply = self.call(request, MAX_KEYS_BYTES).await?;
        match reply.status {
            StatusCode::OK => Ok(reply),
            status => Err(CallError::Status(status)),
        }
    }
}

/// The `names` headers of `upstream`, where present.
fn copied(upstream: &HeaderMap, names: &[header::HeaderName]) -> HeaderMap {
    let present = names
        .iter()
        .filter_map(|n| Some((n.clone(), upstream.get(n)?.clone())));
    present.collect()
}

/// Whether `headers` carry exactly one `Content-Type`, and it is JSON.
pub(crate) fn is_json(headers: &HeaderMap) -> bool {
    let mut media = headers.get_all(header::CONTENT_TYPE).iter();
    match (media.next(), media.next()) {
        (Some(one), None) => one.to_str().is_ok_and(|m| {
            let essence = m.split(';').next().unwrap_or_default();
            essence.trim().eq_ignore_ascii_case("application/json")
        }),
        _ => false,
    }
}
