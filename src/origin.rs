//! A configured origin in its canonical form: what every origin this bridge
//! admits, publishes or dials is checked into, once, at startup.
//!
//! An application allowlist is written in the wider vocabulary of
//! [`Admitted`]: an exact origin, or an origin pattern admitting the
//! subdomains of one host suffix. Everything else — the Distribution this
//! bridge dials, the origin its policy names — is an [`Origin`] and nothing
//! else.
//!
//! What a request arrived under is an [`Observed`], read from the `Origin`
//! header once and carrying the proof that it is canonical. Membership takes
//! one of those and nothing else.

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

/// An origin pattern: `*.` and then the host suffix whose subdomains it
/// admits, at every depth. `*.handles.link` admits
/// `https://app.handles.link` and `https://a.b.handles.link`, and not
/// `https://handles.link`.
///
/// Its matching is the browser's byte for byte, and its grammar is the
/// browser's narrowed in the one place [`Pattern::listed`] names
/// (`ts/packages/popup/src/message.ts`, `SUBDOMAIN_PATTERN` and
/// `isAllowedOrigin`). A member the bridge publishes and the browser reads
/// differently yields a ceremony that never becomes ready rather than an
/// error, so the two sides do not get to drift.
///
/// No public suffix list is consulted. A pattern places the whole subdomain
/// namespace of its suffix, at every depth, inside the trust boundary, and
/// the operator writing one asserts control of that namespace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Pattern(String);

impl Pattern {
    /// What an origin pattern begins with. A member beginning with it is one,
    /// and is refused where it is not a well-formed one.
    pub const PREFIX: &'static str = "*.";

    /// The fewest labels a configured suffix carries.
    const LEAST_LABELS: usize = 2;

    /// `spelling` as written, well formed: [`Pattern::PREFIX`] and then one
    /// or more DNS labels, each lowercase alphanumeric with hyphens only
    /// inside it, the last of them beginning with a letter. So no scheme, no
    /// port, no path, no uppercase, no underscore, no trailing dot, no empty
    /// label, no second `*`.
    ///
    /// The suffix carries at least [`Pattern::LEAST_LABELS`] labels, which
    /// the browser does not ask for. It is the one place this bridge is the
    /// narrower of the two: a whole top-level domain is not an allowlist, and
    /// a narrower bridge admits a subset of what the browser admits, so the
    /// two cannot disagree over an origin either one lets through.
    ///
    /// A refusal names `field` and the first thing actually wrong with the
    /// spelling.
    pub fn listed(field: &str, spelling: &str) -> Result<Pattern> {
        let refuse = |why: &str| Error::Config {
            detail: format!(
                "{field} {spelling} {why}; an origin pattern is *. followed \
                 by the host suffix whose subdomains it admits, as in \
                 *.handles.link"
            ),
        };
        let Some(suffix) = spelling.strip_prefix(Pattern::PREFIX) else {
            return Err(refuse("is not an origin pattern"));
        };
        // Splitting the empty suffix yields one empty label, which the walk
        // refuses, so an empty suffix needs no case of its own.
        let mut labels = suffix.split('.').peekable();
        let mut count = 0usize;
        while let Some(label) = labels.next() {
            count += 1;
            if let Some(fault) = label_fault(label, labels.peek().is_none()) {
                return Err(refuse(fault));
            }
        }
        if count < Pattern::LEAST_LABELS {
            return Err(refuse(
                "names a suffix of one label, and a whole top-level domain is \
                 not an allowlist",
            ));
        }
        Ok(Pattern(spelling.to_owned()))
    }

    /// Whether this pattern admits `origin`, the spelling of an
    /// [`Observed`] and so already canonical.
    ///
    /// It does when `origin` is spelled `https://` and then anything ending
    /// in this pattern's suffix together with the dot ahead of it. That dot
    /// anchors the suffix to a label boundary; the depth above it is
    /// unbounded; and the comparison runs over everything past the scheme,
    /// so a port falls inside it and ends the match.
    ///
    /// Nothing is normalised here. Both sides are canonical already — a
    /// browser stamps an origin lowercase and in punycode, and a suffix in
    /// any other form is refused at construction — so the comparison is of
    /// bytes.
    fn admits(&self, origin: &str) -> bool {
        origin
            .strip_prefix("https://")
            .is_some_and(|host| host.ends_with(self.anchored_suffix()))
    }

    /// The spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The suffix together with the dot that anchors it to a label boundary:
    /// what an admitted host ends in.
    fn anchored_suffix(&self) -> &str {
        &self.0["*".len()..]
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An origin as a browser stamped it: the value of one `Origin` header,
/// found canonical.
///
/// It is the only thing membership is tested against, so the canonicality
/// precondition cannot be skipped and is decided once for a request rather
/// than once for each member tested against it. A member's own spelling is
/// not canonical, so it cannot be offered as an observed origin, reach the
/// literal comparison against an exact member and become a bound origin.
#[derive(Clone, Copy, Debug)]
pub struct Observed<'a>(&'a str);

impl<'a> Observed<'a> {
    /// `spelling` where it is already in the form a browser stamps, which is
    /// the form [`Origin::listed`] holds an exact member to; `None`
    /// otherwise, and only whether it holds is read.
    pub fn stamped(spelling: &'a str) -> Option<Observed<'a>> {
        Origin::listed("Origin", spelling)
            .is_ok()
            .then_some(Observed(spelling))
    }

    /// The spelling.
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

/// One member of an application allowlist, published as the spelling it was
/// written in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Admitted {
    /// A canonical origin, admitting itself and nothing else.
    Exact(Origin),
    /// An origin pattern, admitting the subdomains of its suffix.
    Pattern(Pattern),
}

impl Admitted {
    /// `spelling` as written. A member beginning with [`Pattern::PREFIX`] is
    /// an origin pattern and is refused where it is not a well-formed one,
    /// rather than read as an origin; a member carrying a `*` anywhere else
    /// is refused too; every other member is an exact canonical origin. A
    /// refusal names `field`.
    ///
    /// A bare `*` is a member the browser reads as every origin. It is
    /// refused here: an allowlist this bridge publishes names what it
    /// serves. Refusing it narrows admission, so the browser is never asked
    /// to admit something the bridge would not.
    pub fn listed(field: &str, spelling: &str) -> Result<Admitted> {
        if spelling == "*" {
            return Err(Error::Config {
                detail: format!(
                    "{field} * admits every origin, and an allowlist this \
                     bridge publishes names the origins and the suffixes it \
                     serves"
                ),
            });
        }
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
                     pattern, which is *. followed by the host suffix whose \
                     subdomains it admits, as in *.handles.link"
                ),
            });
        }
        Origin::listed(field, spelling).map(Admitted::Exact)
    }

    /// Whether this member admits `observed`.
    ///
    /// Canonicality is decided ahead of membership of either kind, and
    /// [`Observed`] is where it is decided: a member spelling is not an
    /// origin a browser stamps, so a peer offering one as its own origin
    /// never reaches the literal comparison and is never bound.
    pub fn admits(&self, observed: Observed<'_>) -> bool {
        match self {
            Admitted::Exact(exact) => exact.as_str() == observed.as_str(),
            Admitted::Pattern(pattern) => pattern.admits(observed.as_str()),
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

/// Why `label` is not a label of a pattern suffix, or `None` where it is
/// one: nonempty, lowercase alphanumeric with hyphens only inside it, and,
/// where it is the `last` label, beginning with a letter.
///
/// That letter is what leaves an address outside the grammar. The last label
/// of an IPv4 address in any of its forms is digits, and an IPv6 literal
/// carries bytes no label carries at all.
fn label_fault(label: &str, last: bool) -> Option<&'static str> {
    let bytes = label.as_bytes();
    let (Some(first), Some(end)) = (bytes.first(), bytes.last()) else {
        return Some("names a suffix carrying an empty label");
    };
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Some("names a suffix carrying a label outside the lowercase DNS alphabet");
    }
    if *first == b'-' || *end == b'-' {
        return Some("names a suffix carrying a label that begins or ends with a hyphen");
    }
    if last && !first.is_ascii_lowercase() {
        return Some(
            "ends in a label that does not begin with a letter, so it names an \
             address rather than a host",
        );
    }
    None
}

/// Whether `url` is plaintext `http` on exactly `localhost` or `127.0.0.1`:
/// the one case a canonical origin is not HTTPS.
fn is_plaintext_loopback(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1"))
}
