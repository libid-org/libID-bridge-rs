//! A configured origin in its canonical form: what every origin this bridge
//! admits, publishes or dials is checked into, once, at startup.
//!
//! An application allowlist is written in the wider vocabulary of
//! [`Admitted`]: an exact origin, or an origin pattern admitting the direct
//! subdomains of one host. Everything else — the Distribution this bridge
//! dials, the origin its policy names — is an [`Origin`] and nothing else.

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

    /// Whether a Content-Security-Policy source expression can name this
    /// origin's host. Its grammar admits letters, digits, `-` and the `.`
    /// between labels, so an IPv6 literal and an underscore are both outside
    /// it, and a browser discards a source it cannot parse.
    pub fn names_a_policy_host(&self) -> bool {
        let after_scheme = self
            .0
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&self.0);
        let host = after_scheme
            .split_once(':')
            .map(|(host, _)| host)
            .unwrap_or(after_scheme);
        !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
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

/// An origin pattern: `https://*.` followed by a suffix host, admitting the
/// direct subdomains of that host and not the host itself.
/// `https://*.handles.link` admits `https://app.handles.link`, and neither
/// `https://handles.link` nor `https://a.b.handles.link`.
///
/// No public suffix list is consulted. A pattern places the whole
/// direct-subdomain namespace of its suffix inside the trust boundary, and
/// the operator writing one asserts control of that namespace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Pattern(String);

impl Pattern {
    /// What an origin pattern begins with. A member beginning with it is one,
    /// and is refused where it is not a well-formed one.
    pub const PREFIX: &'static str = "https://*.";

    /// `spelling` as written, well formed: the scheme is `https`, and the
    /// suffix is the host of a canonical origin — which [`Origin::listed`]
    /// decides, so that one validator answers for both member kinds —
    /// carrying at least one `.`, no second `*`, no port, no trailing `.`
    /// and no empty label. A refusal names `field`.
    pub fn listed(field: &str, spelling: &str) -> Result<Pattern> {
        let refuse = |why: &str| Error::Config {
            detail: format!(
                "{field} {spelling} {why}; an origin pattern is https://*. \
                 followed by the host whose direct subdomains it admits, \
                 as in https://*.handles.link"
            ),
        };
        let Some(suffix) = spelling.strip_prefix(Pattern::PREFIX) else {
            return Err(refuse("is not an origin pattern"));
        };
        if !suffix.contains('.') {
            return Err(refuse("names a suffix of one label"));
        }
        if suffix.contains('*') {
            return Err(refuse("names a suffix carrying a second *"));
        }
        if Origin::listed(field, &format!("https://{suffix}")).is_err() {
            return Err(refuse("names a suffix that is not a canonical host"));
        }
        // A URL parser keeps a port, an empty label and a trailing `.`, and
        // reports the result canonical, so the three are read off the
        // spelling. Each leaves a suffix no browser-stamped host ends in, and
        // so a pattern that admits nothing at all.
        if suffix.contains(':') {
            return Err(refuse("names a suffix carrying a port"));
        }
        if suffix.starts_with('.') || suffix.contains("..") {
            return Err(refuse("names a suffix carrying an empty label"));
        }
        if suffix.ends_with('.') {
            return Err(refuse("names a suffix carrying a trailing dot"));
        }
        Ok(Pattern(spelling.to_owned()))
    }

    /// Whether this pattern admits `origin`, which [`Admitted::admits`] has
    /// already found canonical.
    ///
    /// It does when `origin` is spelled `https://` and then a host carrying
    /// no `:` and no `/`, which ends in `.` and this pattern's suffix, with
    /// one nonempty label carrying no `.` ahead of that. Both ends are
    /// anchored.
    ///
    /// Nothing is normalised here. Both sides are canonical already — a
    /// browser stamps an origin lowercase and in punycode, and a suffix in
    /// any other form is refused at construction — so the comparison is of
    /// bytes.
    fn admits(&self, origin: &str) -> bool {
        let Some(host) = origin.strip_prefix("https://") else {
            return false;
        };
        if host.contains(':') || host.contains('/') {
            return false;
        }
        let Some(label) = host
            .strip_suffix(self.suffix())
            .and_then(|head| head.strip_suffix('.'))
        else {
            return false;
        };
        !label.is_empty() && !label.contains('.')
    }

    /// The spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The host whose direct subdomains this pattern admits.
    fn suffix(&self) -> &str {
        &self.0[Pattern::PREFIX.len()..]
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One member of an application allowlist, published as the spelling it was
/// written in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Admitted {
    /// A canonical origin, admitting itself and nothing else.
    Exact(Origin),
    /// An origin pattern, admitting the direct subdomains of its suffix.
    Pattern(Pattern),
}

impl Admitted {
    /// `spelling` as written. A member beginning with [`Pattern::PREFIX`] is
    /// an origin pattern and is refused where it is not a well-formed one,
    /// rather than read as an origin; a member carrying a `*` anywhere else
    /// is refused too; every other member is an exact canonical origin. A
    /// refusal names `field`.
    pub fn listed(field: &str, spelling: &str) -> Result<Admitted> {
        if spelling.starts_with(Pattern::PREFIX) {
            return Pattern::listed(field, spelling).map(Admitted::Pattern);
        }
        // No browser stamps an origin whose host carries a `*`, so a member
        // carrying one outside the pattern prefix is a mistyped pattern and
        // matches nothing. Reading it as an exact origin keeps the typo until
        // a ceremony hangs waiting for a peer that never matches.
        if spelling.contains('*') {
            return Err(Error::Config {
                detail: format!(
                    "{field} {spelling} carries a * and is not an origin \
                     pattern, which is https://*. followed by the host whose \
                     direct subdomains it admits, as in https://*.handles.link"
                ),
            });
        }
        Origin::listed(field, spelling).map(Admitted::Exact)
    }

    /// Whether this member admits `origin`, as a browser stamped it.
    ///
    /// Canonicality is decided ahead of membership of either kind. A member
    /// spelling is not an origin a browser stamps, so a peer offering one as
    /// its own origin is turned away by that precondition rather than matched
    /// by the literal comparison and bound.
    pub fn admits(&self, origin: &str) -> bool {
        // The precondition an exact member is held to, applied to what the
        // browser stamped; only whether it holds is read.
        if Origin::listed("Origin", origin).is_err() {
            return false;
        }
        match self {
            Admitted::Exact(exact) => exact.as_str() == origin,
            Admitted::Pattern(pattern) => pattern.admits(origin),
        }
    }

    /// The spelling.
    pub fn as_str(&self) -> &str {
        match self {
            Admitted::Exact(exact) => exact.as_str(),
            Admitted::Pattern(pattern) => pattern.as_str(),
        }
    }
}

impl fmt::Display for Admitted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether `url` is plaintext `http` on exactly `localhost` or `127.0.0.1`:
/// the one case a canonical origin is not HTTPS.
fn is_plaintext_loopback(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
}
