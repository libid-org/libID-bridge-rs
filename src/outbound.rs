//! What every outbound request shares: its `User-Agent` and its connector.

use std::time::Duration;

use hyper_util::client::legacy::connect::HttpConnector;

/// How long opening the transport may take: resolution, the connection, and
/// the TLS handshake over it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The `User-Agent` of every outbound request.
pub(crate) const USER_AGENT: &str = concat!("libid-bridge/", env!("CARGO_PKG_VERSION"));

/// TLS over compiled-in `webpki-roots`; no system trust store is read.
pub(crate) type Connector = hyper_rustls::HttpsConnector<HttpConnector>;

/// The connector every outbound request dials with: compiled-in roots, and
/// plaintext `http` for a loopback URL the caller has checked.
pub(crate) fn connector() -> Connector {
    // The connector dials by URL, so `enforce_http` must be off for the
    // https wrapper to see an `https` one.
    let mut http = HttpConnector::new();
    http.set_connect_timeout(Some(CONNECT_TIMEOUT));
    http.enforce_http(false);
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http)
}
