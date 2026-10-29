//! The connector every request this bridge sends is dialed with: TLS whose
//! trust anchors are compiled in from `webpki-roots`, plaintext `http` for a
//! loopback peer, and a bound on opening the transport. No system trust store
//! is read.

use std::time::Duration;

use hyper_util::client::legacy::connect::HttpConnector;

/// How long opening the transport may take: resolution, the connection, and
/// the TLS handshake over it.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The `User-Agent` every outbound request carries.
pub const USER_AGENT: &str = concat!("libid-bridge/", env!("CARGO_PKG_VERSION"));

/// What an outbound client dials with.
pub type Connector = hyper_rustls::HttpsConnector<HttpConnector>;

/// A fresh connector. Which URLs reach it is the caller's to check: a
/// loopback peer named by `http` is dialed without a certificate.
pub fn connector() -> Connector {
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

/// What went wrong, from an error whose own message names only its layer: the
/// chain is walked so the reason reaching an operator is the one the socket
/// gave.
pub fn reason(error: &dyn std::error::Error) -> String {
    let mut why = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        let text = next.to_string();
        if !why.contains(&text) {
            why.push_str(": ");
            why.push_str(&text);
        }
        source = next.source();
    }
    why
}
