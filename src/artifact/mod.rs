//! The callback document this bridge serves: the CCDP Distribution's artifact
//! with one unversioned list in place of its one marker, under a
//! Content-Security-Policy composed here from this deployment's own sources
//! and the script hashes the artifact arrived with.
//!
//! The document is not parsed. The marker is substituted for, the hashes are
//! carried, and the policy admits those hashes and no other script source, so
//! what the Distribution ships is what the Distribution is answerable for.

pub(crate) mod policy;
pub(crate) mod upstream;

use axum::http::HeaderValue;
use bytes::Bytes;

use policy::ArtifactError;

use crate::origin::Origin;

#[cfg(test)]
pub(crate) use crate::fixtures::ARTIFACT as FIXTURE;

/// What the deployment contributes to the document and its policy.
pub(crate) struct DeploymentInputs<'a> {
    /// The CCDP Distribution this bridge selects: in the inserted list, and
    /// the one origin the policy admits a frame from.
    pub(crate) ccdp_origin: &'a Origin,
    /// The effective admission set, which the Callback authenticates an
    /// application against. It contains the CCDP origin.
    pub(crate) allowed_origins: &'a [Origin],
}

/// The finished document: the exact bytes, and the policy they are served
/// under.
pub(crate) struct CallbackDocument {
    /// The document, composed once.
    pub(crate) body: Bytes,
    /// Its `Content-Security-Policy`, naming the script hashes the artifact
    /// arrived with.
    pub(crate) csp: HeaderValue,
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
    pub(crate) fn compose(
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
pub(crate) struct Published {
    /// The document, and the policy it is served under.
    pub(crate) document: CallbackDocument,
    /// The `ETag` the document arrived with, sent back as `If-None-Match`.
    pub(crate) etag: Option<String>,
}

/// The response policy: this deployment's own sources, and the script hashes
/// the artifact arrived with.
fn policy(hashes: &[String], ccdp_origin: &str) -> String {
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
fn json(value: &serde_json::Value) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(spelling: &str) -> Origin {
        Origin::parse("T", spelling).unwrap()
    }

    fn origins() -> Vec<Origin> {
        vec![
            origin("https://app.example"),
            origin("https://ccdp.example"),
        ]
    }

    fn compose(html: &str) -> Result<CallbackDocument, ArtifactError> {
        CallbackDocument::compose(
            html,
            &crate::fixtures::artifact_hashes(),
            &DeploymentInputs {
                ccdp_origin: &origin("https://ccdp.example"),
                allowed_origins: &origins(),
            },
        )
    }

    fn text(doc: &CallbackDocument) -> String {
        String::from_utf8(doc.body.to_vec()).unwrap()
    }

    /// The artifact a live Distribution serves composes, and what is served
    /// carries the deployment's data where the marker was.
    #[test]
    fn the_artifact_of_a_live_distribution_composes() {
        let served = text(&compose(FIXTURE).unwrap());
        assert!(!served.contains(policy::MARKER));
        assert!(served.contains(
            r#"[["https://app.example","https://ccdp.example"],"https://ccdp.example"]"#
        ));
    }

    /// Only the marker changes: every other byte of the artifact is served as
    /// it arrived, so no byte a declared hash covers moves.
    #[test]
    fn substitution_touches_only_the_marker() {
        let served = text(&compose(FIXTURE).unwrap());
        let at = FIXTURE.find(policy::MARKER).unwrap();
        assert_eq!(&served[..at], &FIXTURE[..at]);
        let after = at + policy::MARKER.len();
        assert_eq!(
            &served[served.len() - (FIXTURE.len() - after)..],
            &FIXTURE[after..]
        );
    }

    /// A document with no marker, or with more than one, is refused rather
    /// than filled in twice.
    #[test]
    fn a_document_without_exactly_one_marker_is_refused() {
        for (html, count) in [
            ("<html><body>nothing to fill</body></html>", 0),
            (
                "<html>__LIBID_CALLBACK_CONFIG__ __LIBID_CALLBACK_CONFIG__</html>",
                2,
            ),
        ] {
            assert_eq!(
                compose(html).map(|_| ()).unwrap_err(),
                ArtifactError::Markers(count)
            );
        }
    }

    /// The policy names the hashes the artifact arrived with, admits a frame
    /// only from the configured Distribution, and admits no connection.
    #[test]
    fn the_policy_carries_the_hashes_and_this_deployments_sources() {
        let doc = compose(FIXTURE).unwrap();
        let csp = doc.csp.to_str().unwrap();
        assert!(csp.starts_with(
            "default-src 'none'; object-src 'none'; base-uri 'none'; \
             form-action 'none'; frame-ancestors 'none'"
        ));
        for source in crate::fixtures::artifact_hashes() {
            assert!(csp.contains(&source), "{csp}");
        }
        assert!(csp.contains("frame-src https://ccdp.example"));
        assert!(csp.contains("connect-src 'none'"));
        assert!(!csp.contains("'unsafe-eval'"));
        assert!(!csp.contains("'unsafe-inline'; script"), "{csp}");
    }

    /// Inserted data leaves as ASCII with no character a parser reads as
    /// markup, whatever the deployment is called.
    #[test]
    fn inserted_data_cannot_be_read_as_markup() {
        let rendered = json(&serde_json::json!(["</script><script>", "\u{2028}\u{e9}"]));
        assert!(rendered.is_ascii());
        for forbidden in ['<', '>', '&'] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
        assert!(rendered.contains("\\u003c"));
    }
}
