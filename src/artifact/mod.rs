//! The callback document this bridge serves: the CCDP Distribution's artifact
//! with one unversioned list in place of its one marker, under a
//! Content-Security-Policy composed here from this deployment's own sources
//! and the script hashes the artifact arrived with.
//!
//! The document is not parsed. The marker is substituted for, the hashes are
//! carried, and the policy admits those hashes and no other script source, so
//! what the Distribution ships is what the Distribution is answerable for.

pub mod policy;
pub mod upstream;

use axum::http::HeaderValue;
use bytes::Bytes;

use policy::ArtifactError;

use crate::origin::Origin;

/// What the deployment contributes to the document and its policy.
pub struct DeploymentInputs<'a> {
    /// The CCDP Distribution this bridge selects: in the inserted list, and
    /// the one origin the policy admits a frame from.
    pub ccdp_origin: &'a Origin,
    /// The effective admission set, which the Callback authenticates an
    /// application against. It contains the CCDP origin.
    pub allowed_origins: &'a [Origin],
}

/// The finished document: the exact bytes, and the policy they are served
/// under.
pub struct CallbackDocument {
    /// The document, composed once.
    pub body: Bytes,
    /// Its `Content-Security-Policy`, naming the script hashes the artifact
    /// arrived with.
    pub csp: HeaderValue,
}

impl CallbackDocument {
    /// Configure one artifact and compose the response it is served as: the
    /// one constructor, where the deployment's data goes in and the policy is
    /// written.
    ///
    /// `hashes` are the script sources the artifact's own policy named, and
    /// become the only script sources the composed policy admits. The marker
    /// occurs once and is replaced by escaped data, so no byte those hashes
    /// cover moves and nothing inserted can be read as markup.
    pub fn compose(
        html: &str,
        hashes: &[String],
        inputs: &DeploymentInputs<'_>,
    ) -> Result<CallbackDocument, ArtifactError> {
        let markers = html.matches(policy::MARKER).count();
        if markers != 1 {
            return Err(ArtifactError::Markers(markers));
        }

        // One unversioned list: `[allowedOrigins, ccdpOrigin]`, written in
        // place of the marker. The encoder emits no `<`, `>` or `&`, so the
        // inserted bytes can neither end the element that holds them nor open
        // one of their own.
        let record = serde_json::json!([inputs.allowed_origins, inputs.ccdp_origin]);
        let body = html.replace(policy::MARKER, &json(&record));

        let csp = policy(hashes, inputs.ccdp_origin.as_str());
        let csp = HeaderValue::from_str(&csp)
            .map_err(|e| ArtifactError::Policy(format!("{csp:?}: {e}")))?;
        Ok(CallbackDocument {
            body: Bytes::from(body),
            csp,
        })
    }
}

/// A composed document and the validator it was retrieved under.
///
/// One value, published as one unit, and that is the point: the ETag advances
/// only where a document does. A `200` whose body this bridge refuses publishes
/// nothing, so the next revalidation cannot send `If-None-Match` for a document
/// that was never served -- which would turn one bad artifact into a permanent
/// `304` for a document nobody has.
pub struct Published {
    /// The document, and the policy it is served under.
    pub document: CallbackDocument,
    /// The `ETag` the document arrived with, sent back as `If-None-Match`.
    pub etag: Option<String>,
}

/// The response policy: this deployment's own sources, and the script hashes
/// the artifact arrived with.
pub fn policy(hashes: &[String], ccdp_origin: &str) -> String {
    [
        "default-src 'none'".to_owned(),
        "object-src 'none'".to_owned(),
        "base-uri 'none'".to_owned(),
        "form-action 'none'".to_owned(),
        "frame-ancestors 'none'".to_owned(),
        // Hashes only; the artifact bundles its dependencies.
        format!("script-src {}", hashes.join(" ")),
        // The artifact's own inline styles.
        "style-src 'unsafe-inline'".to_owned(),
        // Callback may frame the Distribution it came from, and nothing else.
        format!("frame-src {ccdp_origin}"),
        "connect-src 'none'".to_owned(),
    ]
    .join("; ")
}

/// A JSON island, escaped so it cannot end the script element that carries
/// it: `<`, `>`, `&`, the line separators and every non-ASCII character leave
/// as `\uXXXX` escapes, so the inserted data is ASCII.
pub fn json(value: &serde_json::Value) -> String {
    use std::fmt::Write as _;

    let rendered = value.to_string();
    let mut out = String::with_capacity(rendered.len());
    for c in rendered.chars() {
        match c {
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if c.is_ascii() => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out
}
