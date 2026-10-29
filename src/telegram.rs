//! Telegram's two routes upstream: the code swap and the key list.
//! Telegram's endpoints answer no CORS, so the browser hands its code, PKCE
//! verifier and redirect URI here, and this bridge posts them authenticated
//! with the private client secret and returns Telegram's answer as it
//! arrived. The key list is passed through as fetched, and cached. Nothing of
//! a request or an answer is logged.

use std::{
    sync::Mutex,
    time::Duration,
};

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{
    BodyExt,
    Empty,
    Full,
    Limited,
};
use hyper::{
    body::Incoming,
    header::{
        self,
        HeaderValue,
    },
    StatusCode,
    Uri,
};
use hyper_util::rt::TokioExecutor;
use tokio::time::Instant;

use crate::{
    deployment::TelegramClient,
    error::Error,
    outbound,
};

/// How long one swap or key fetch may take, from dialing to the end of the
/// answer.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest swap answer passed on, in bytes.
pub const MAX_ANSWER_BYTES: usize = 8 * 1024;

/// The largest key list passed on, in bytes.
pub const MAX_KEYS_BYTES: usize = 64 * 1024;

/// How long a fetched key list is served before it is fetched again.
pub const KEYS_TTL: Duration = Duration::from_secs(600);

/// The client a swap is sent with.
type Client = hyper_util::client::legacy::Client<outbound::Connector, Full<Bytes>>;

/// Telegram's answer to a swap: its status and body, untouched.
pub struct Answer {
    /// Telegram's status.
    pub status: StatusCode,
    /// Telegram's body.
    pub body: Bytes,
}

/// Why a swap or a key fetch produced no answer to pass on.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    /// No complete answer within the budget.
    #[error("did not answer in time")]
    TimedOut,
    /// The endpoint could not be reached, or stopped answering.
    #[error("could not be reached: {0}")]
    Unreachable(String),
    /// A redirect, which is not followed.
    #[error("answered {0}, a redirect this bridge does not follow")]
    Redirect(StatusCode),
    /// A key list answered with something other than `200`.
    #[error("answered {0}")]
    Status(StatusCode),
    /// The body ran past its bound, in bytes.
    #[error("answered more than {0} bytes")]
    TooLarge(usize),
}

impl ExchangeError {
    /// The short name this failure is logged under.
    pub fn kind(&self) -> &'static str {
        match self {
            ExchangeError::TimedOut => "timed-out",
            ExchangeError::Unreachable(_) => "unreachable",
            ExchangeError::Redirect(_) => "redirect",
            ExchangeError::Status(_) => "status",
            ExchangeError::TooLarge(_) => "too-large",
        }
    }

    /// What a caller is told: the kind of failure, and nothing Telegram or
    /// the network said.
    pub fn public(&self) -> &'static str {
        match self {
            ExchangeError::TimedOut => "did not answer in time",
            ExchangeError::Unreachable(_) => "could not be reached",
            ExchangeError::Redirect(_) => {
                "answered a redirect this bridge does not follow"
            }
            ExchangeError::Status(_) => "answered an error",
            ExchangeError::TooLarge(_) => "answered more than this bridge passes on",
        }
    }
}

/// Telegram's routes upstream, exactly where Telegram is enabled.
pub struct Telegram {
    /// The code swap.
    pub exchange: TokenExchange,
    /// The key list.
    pub keys: KeyList,
}

impl Telegram {
    /// Both, for `telegram`, each request bounded by `timeout`.
    pub fn new(telegram: TelegramClient, timeout: Duration) -> Result<Telegram, Error> {
        Ok(Telegram {
            keys: KeyList::new(&telegram.jwks_url, timeout)?,
            exchange: TokenExchange::new(telegram, timeout)?,
        })
    }
}

/// `url` as a request target, checked once at startup.
fn target(key: &str, url: &url::Url) -> Result<Uri, Error> {
    url.as_str().parse::<Uri>().map_err(|e| Error::Config {
        detail: format!("telegram: {key} {url} is not an HTTP request target: {e}"),
    })
}

/// A body read whole, bounded by `limit` while it is read.
async fn bounded(body: Incoming, limit: usize) -> Result<Bytes, ExchangeError> {
    Ok(Limited::new(body, limit)
        .collect()
        .await
        .map_err(
            |e| match e.downcast_ref::<http_body_util::LengthLimitError>() {
                Some(_) => ExchangeError::TooLarge(limit),
                None => ExchangeError::Unreachable(format!("reading the body: {e}")),
            },
        )?
        .to_bytes())
}

/// Telegram's token endpoint, and the client this deployment swaps codes for.
pub struct TokenExchange {
    telegram: TelegramClient,
    uri: Uri,
    /// `Basic base64(client_id:client_secret)`, marked sensitive.
    authorization: HeaderValue,
    timeout: Duration,
    client: Client,
}

impl TokenExchange {
    /// The swap for `telegram`, each bounded by `timeout`.
    pub fn new(
        telegram: TelegramClient,
        timeout: Duration,
    ) -> Result<TokenExchange, Error> {
        let uri = target("token_url", &telegram.token_url)?;
        let credentials = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            telegram.client_id,
            telegram.client_secret.expose()
        ));
        let mut authorization = HeaderValue::from_str(&format!("Basic {credentials}"))
            .expect("base64 is a valid header value");
        authorization.set_sensitive(true);
        Ok(TokenExchange {
            telegram,
            uri,
            authorization,
            timeout,
            client: hyper_util::client::legacy::Client::builder(TokioExecutor::new())
                .build(outbound::connector()),
        })
    }

    /// The token endpoint, for a log line.
    pub fn url(&self) -> &str {
        self.telegram.token_url.as_str()
    }

    /// Swap `code`, `code_verifier` and `redirect_uri` for Telegram's answer,
    /// whatever its status.
    pub async fn exchange(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<Answer, ExchangeError> {
        tokio::time::timeout(self.timeout, self.send(code, code_verifier, redirect_uri))
            .await
            .map_err(|_| ExchangeError::TimedOut)?
    }

    /// One `client_secret_basic` request and its answer, bounded.
    async fn send(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<Answer, ExchangeError> {
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code_verifier", code_verifier)
            .append_pair("client_id", &self.telegram.client_id)
            .finish();
        let request = hyper::Request::post(self.uri.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .header(header::USER_AGENT, outbound::USER_AGENT)
            .header(header::AUTHORIZATION, self.authorization.clone())
            .body(Full::new(Bytes::from(form)))
            .expect("a request of a URI checked at startup and valid header values");

        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| ExchangeError::Unreachable(outbound::reason(&e)))?;
        let status = response.status();
        if status.is_redirection() {
            return Err(ExchangeError::Redirect(status));
        }
        let body = bounded(response.into_body(), MAX_ANSWER_BYTES).await?;
        Ok(Answer { status, body })
    }
}

/// A key list as Telegram served it: its bytes, media type and encoding.
#[derive(Clone)]
pub struct Keys {
    /// Telegram's `Content-Type`, where it sent one.
    pub content_type: Option<HeaderValue>,
    /// Telegram's `Content-Encoding`, where it sent one.
    pub content_encoding: Option<HeaderValue>,
    /// The body, unparsed.
    pub body: Bytes,
}

/// Telegram's key list, fetched without credentials and cached for
/// [`KEYS_TTL`] after a successful fetch.
pub struct KeyList {
    url: url::Url,
    uri: Uri,
    timeout: Duration,
    client: outbound::GetClient,
    cache: Mutex<Option<(Instant, Keys)>>,
}

impl KeyList {
    /// The key list at `url`, each fetch bounded by `timeout`.
    pub fn new(url: &url::Url, timeout: Duration) -> Result<KeyList, Error> {
        Ok(KeyList {
            uri: target("jwks_url", url)?,
            url: url.clone(),
            timeout,
            client: outbound::get_client(),
            cache: Mutex::new(None),
        })
    }

    /// The key list, for a log line.
    pub fn url(&self) -> &str {
        self.url.as_str()
    }

    /// The cached key list while it is fresh, or a fresh fetch. Two first
    /// reads may both fetch; the lock is never held across one.
    pub async fn keys(&self) -> Result<Keys, ExchangeError> {
        if let Some(keys) = self.cached() {
            return Ok(keys);
        }
        let keys = tokio::time::timeout(self.timeout, self.fetch())
            .await
            .map_err(|_| ExchangeError::TimedOut)??;
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((Instant::now(), keys.clone()));
        Ok(keys)
    }

    /// The cached key list, while it is younger than [`KEYS_TTL`].
    fn cached(&self) -> Option<Keys> {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache
            .as_ref()
            .filter(|(at, _)| at.elapsed() < KEYS_TTL)
            .map(|(_, keys)| keys.clone())
    }

    /// One `GET`, carrying no credential, and its `200`, bounded.
    async fn fetch(&self) -> Result<Keys, ExchangeError> {
        let request = hyper::Request::get(self.uri.clone())
            .header(header::USER_AGENT, outbound::USER_AGENT)
            .body(Empty::new())
            .expect("a request of a URI checked at startup and valid header values");
        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| ExchangeError::Unreachable(outbound::reason(&e)))?;
        match response.status() {
            StatusCode::OK => {}
            s if s.is_redirection() => return Err(ExchangeError::Redirect(s)),
            s => return Err(ExchangeError::Status(s)),
        }
        let (parts, body) = response.into_parts();
        Ok(Keys {
            content_type: parts.headers.get(header::CONTENT_TYPE).cloned(),
            content_encoding: parts.headers.get(header::CONTENT_ENCODING).cloned(),
            body: bounded(body, MAX_KEYS_BYTES).await?,
        })
    }
}
