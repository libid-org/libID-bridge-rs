//! Telegram's code swap: the one request this bridge sends on a caller's
//! behalf. Telegram's token endpoint answers no CORS, so the browser hands the
//! code and its PKCE verifier here, and this bridge posts them with the
//! private client secret and returns Telegram's answer as it arrived. Nothing
//! is kept, and nothing of the request or the answer is logged.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{
    BodyExt,
    Full,
    Limited,
};
use hyper::{
    header,
    StatusCode,
    Uri,
};
use hyper_util::rt::TokioExecutor;

use crate::{
    deployment::TelegramClient,
    error::Error,
    outbound,
};

/// How long one swap may take, from dialing to the end of the answer.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest answer passed on, in bytes.
pub const MAX_ANSWER_BYTES: usize = 8 * 1024;

/// The client a swap is sent with.
type Client = hyper_util::client::legacy::Client<outbound::Connector, Full<Bytes>>;

/// Telegram's answer to a swap: its status and body, untouched.
pub struct Answer {
    /// Telegram's status.
    pub status: StatusCode,
    /// Telegram's body.
    pub body: Bytes,
}

/// Why a swap produced no answer to pass on.
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
    /// The body ran past [`MAX_ANSWER_BYTES`].
    #[error("answered more than {MAX_ANSWER_BYTES} bytes")]
    TooLarge,
}

impl ExchangeError {
    /// The short name this failure is logged under.
    pub fn kind(&self) -> &'static str {
        match self {
            ExchangeError::TimedOut => "timed-out",
            ExchangeError::Unreachable(_) => "unreachable",
            ExchangeError::Redirect(_) => "redirect",
            ExchangeError::TooLarge => "too-large",
        }
    }
}

/// Telegram's token endpoint, and the client this deployment swaps codes for.
pub struct TokenExchange {
    telegram: TelegramClient,
    uri: Uri,
    timeout: Duration,
    client: Client,
}

impl TokenExchange {
    /// The swap for `telegram`, each bounded by `timeout`.
    pub fn new(
        telegram: TelegramClient,
        timeout: Duration,
    ) -> Result<TokenExchange, Error> {
        let uri =
            telegram
                .token_url
                .as_str()
                .parse::<Uri>()
                .map_err(|e| Error::Config {
                    detail: format!(
                        "telegram: token_url {} is not an HTTP request target: {e}",
                        telegram.token_url
                    ),
                })?;
        Ok(TokenExchange {
            telegram,
            uri,
            timeout,
            client: hyper_util::client::legacy::Client::builder(TokioExecutor::new())
                .build(outbound::connector()),
        })
    }

    /// The token endpoint, for a log line.
    pub fn url(&self) -> &str {
        self.telegram.token_url.as_str()
    }

    /// Swap `code` and `code_verifier` for Telegram's answer, whatever its
    /// status.
    pub async fn exchange(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<Answer, ExchangeError> {
        tokio::time::timeout(self.timeout, self.send(code, code_verifier))
            .await
            .map_err(|_| ExchangeError::TimedOut)?
    }

    /// One `client_secret_post` request and its answer, bounded.
    async fn send(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<Answer, ExchangeError> {
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.telegram.redirect_uri)
            .append_pair("client_id", &self.telegram.client_id)
            .append_pair("client_secret", self.telegram.client_secret.expose())
            .append_pair("code_verifier", code_verifier)
            .finish();
        let request = hyper::Request::post(self.uri.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .header(header::USER_AGENT, outbound::USER_AGENT)
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
        let body = Limited::new(response.into_body(), MAX_ANSWER_BYTES)
            .collect()
            .await
            .map_err(
                |e| match e.downcast_ref::<http_body_util::LengthLimitError>() {
                    Some(_) => ExchangeError::TooLarge,
                    None => ExchangeError::Unreachable(format!("reading the body: {e}")),
                },
            )?
            .to_bytes();
        Ok(Answer { status, body })
    }
}
