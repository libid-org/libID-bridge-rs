//! A configured origin in its canonical form: what every origin this bridge
//! admits, publishes or dials is checked into, once, at startup.

use std::fmt;

use serde::Serialize;
use url::Url;

use crate::error::{
    Error,
    Result,
};

/// A canonical origin: `https`, or `http` on exactly `localhost` or
/// `127.0.0.1`; a host and nothing after it; lowercase host, no default port;
/// made only of the bytes an origin is made of. Its two constructors are the
/// only way to get one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Origin(String);

impl Origin {
    /// `spelling` folded to its canonical form: `Url::origin` lowercases the
    /// host and drops a default port. A refusal names `field`.
    pub fn parse(field: &str, spelling: &str) -> Result<Origin> {
        let url = Url::parse(spelling).map_err(|e| Error::Config {
            detail: format!("{field} {spelling}: {e}"),
        })?;
        let refuse = |why: &str| Error::Config {
            detail: format!(
                "{field} {spelling} {why}; it must be a bare origin, \
                 as in https://id.example.com"
            ),
        };
        if !matches!(url.scheme(), "http" | "https") {
            return Err(refuse("is not http or https"));
        }
        if url.host().is_none() {
            return Err(refuse("names no host"));
        }
        if !matches!(url.path(), "" | "/") {
            return Err(refuse("carries a path"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(refuse("carries a query or fragment"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(refuse("carries credentials"));
        }
        if url.scheme() == "http" && !is_plaintext_loopback(&url) {
            return Err(refuse(
                "is plaintext http on a host that is not localhost or 127.0.0.1",
            ));
        }
        // `;`, quotes and other bytes a Content-Security-Policy reads as syntax
        // are refused: the CCDP origin is spliced into `script-src` and
        // `frame-src`.
        let origin = url.origin().ascii_serialization();
        if !origin
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:[]/".contains(&b))
        {
            return Err(refuse(
                "carries a byte an origin is not made of, which a \
                 Content-Security-Policy would read as syntax",
            ));
        }
        Ok(Origin(origin))
    }

    /// `spelling` as written: refused unless it is already canonical, with
    /// the canonical spelling named rather than folded to.
    pub fn listed(field: &str, spelling: &str) -> Result<Origin> {
        let origin = Origin::parse(field, spelling)?;
        if origin.as_str() != spelling {
            return Err(Error::Config {
                detail: format!(
                    "{field} {spelling} is not canonical; write it as {origin}"
                ),
            });
        }
        Ok(origin)
    }

    /// Whether the host is an IPv6 literal. A canonical origin brackets one
    /// and carries a bracket nowhere else.
    pub fn is_ipv6_literal(&self) -> bool {
        self.0.contains('[')
    }

    /// The canonical spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `url` is plaintext `http` on exactly `localhost` or `127.0.0.1`:
/// the one case a canonical origin is not HTTPS.
fn is_plaintext_loopback(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
}
