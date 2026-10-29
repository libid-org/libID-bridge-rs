//! Telegram's private client and the calls made with it: the code swap and
//! the key list, each bounded in time and size, the key list cached.

use std::sync::Mutex;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{
    BodyExt,
    Full,
};
use hyper::{
    header,
    header::HeaderValue,
    HeaderMap,
    StatusCode,
    Uri,
};

use crate::outbound::USER_AGENT;

/// How long one upstream call may take, dialing included.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long a fetched key list is served from cache: the keeper's cadence,
/// since a new key is unusable on chain until the keeper rotates it in.
const KEYS_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

type Client = hyper_util::client::legacy::Client<crate::outbound::Connector, Full<Bytes>>;

/// Why an upstream call gave nothing to pass on: what the caller is told,
/// and the detail the log gets.
pub(crate) type Failure = (&'static str, String);

const UNREACHABLE: &str = "could not be reached";

/// Telegram's client, checked at startup. `Debug` shows no secret.
#[derive(Clone, Debug)]
pub struct TelegramClient {
    /// The public client id.
    pub client_id: String,
    /// `Basic base64(client_id:secret)`, marked sensitive.
    authorization: HeaderValue,
    /// The token endpoint.
    pub token_url: Uri,
    /// The key list.
    pub jwks_url: Uri,
}

impl TelegramClient {
    /// The client `client_id` authenticating with `secret`; both form-encode
    /// to themselves.
    pub(crate) fn new(
        client_id: &str,
        secret: &str,
        token_url: Uri,
        jwks_url: Uri,
    ) -> TelegramClient {
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id}:{secret}"));
        let mut authorization = HeaderValue::from_str(&format!("Basic {basic}"))
            .expect("base64 is a header value");
        authorization.set_sensitive(true);
        TelegramClient {
            client_id: client_id.to_owned(),
            authorization,
            token_url,
            jwks_url,
        }
    }
}

/// Telegram's client, the connections to it, and the cached key list.
pub struct Telegram {
    /// The client every call is made as.
    pub(crate) client: TelegramClient,
    http: Client,
    keys: Mutex<Option<(tokio::time::Instant, HeaderMap, Bytes)>>,
}

impl Telegram {
    /// The upstream for `client`.
    pub fn new(client: TelegramClient) -> Telegram {
        Telegram {
            client,
            http: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build(crate::outbound::connector()),
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

    /// Telegram's answer to swapping `code`, sent with the client secret.
    pub(crate) async fn swap(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<(StatusCode, HeaderMap, Bytes), Failure> {
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
            .header(header::USER_AGENT, USER_AGENT)
            .header(header::AUTHORIZATION, client.authorization.clone())
            .body(Full::from(form))
            .expect("a URI checked at startup");
        self.call(request, 8 * 1024).await
    }

    /// The key list's media type, encoding and bytes: cached while fresh, else
    /// fetched, and cached only when a nonempty JSON `200`. The lock is never
    /// held across a fetch, and an older fetch never replaces a newer one.
    pub(crate) async fn keys(&self) -> Result<(HeaderMap, Bytes), Failure> {
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
        let started = tokio::time::Instant::now();
        let (status, upstream, body) = self.call(request, 64 * 1024).await?;
        if status != StatusCode::OK {
            return Err(("answered an error", status.to_string()));
        }
        let headers =
            copied(&upstream, &[header::CONTENT_TYPE, header::CONTENT_ENCODING]);
        if is_json(&headers) && !body.is_empty() {
            let mut slot = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            if slot.as_ref().is_none_or(|(at, ..)| *at < started) {
                *slot = Some((started, headers.clone(), body.clone()));
            }
        }
        Ok((headers, body))
    }
}

/// The `names` headers of `upstream`, where present.
pub(crate) fn copied(upstream: &HeaderMap, names: &[header::HeaderName]) -> HeaderMap {
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
