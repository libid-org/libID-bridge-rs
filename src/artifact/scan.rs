//! Reading a Callback artifact well enough to serve it: the one data slot
//! this bridge substitutes into, and the mount point the artifact contract
//! requires. What the browser executes is named by the artifact's own
//! hash-only `script-src`, which this bridge carries into the policy it
//! composes; the data slot is not executable, so substituting into it leaves
//! every hashed byte where it was.

use std::ops::Range;

/// The marker the build leaves for deployment data, and the element that
/// carries it. Both are fixed by the artifact contract.
pub(crate) const MARKER: &str = "__LIBID_CALLBACK_CONFIG__";
const SLOT_OPEN: &str = "<script id=\"libid-callback-config\" type=\"application/json\">";
const SCRIPT_CLOSE: &str = "</script>";

/// The element the Callback renders into, which the artifact carries once.
const MOUNT_POINT: &str = "<main id=\"libid-root\"></main>";

/// The largest artifact this bridge will read.
pub(crate) const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

/// The most script hashes an artifact's policy may name.
const MAX_HASHES: usize = 8;

/// Why an artifact was refused. Every variant is a refusal to serve, never a
/// repair.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ArtifactError {
    #[error("the artifact is {0} bytes, over the {MAX_ARTIFACT_BYTES}-byte bound")]
    TooLarge(usize),
    #[error("the document carries {0} configuration slots, and must carry one")]
    Slots(usize),
    #[error("the configuration slot does not hold exactly the marker")]
    Marker,
    #[error("the document does not carry exactly one empty `<main id=\"libid-root\">`")]
    MountPoint,
    #[error("the artifact's own policy {0}")]
    UpstreamPolicy(String),
    #[error("the composed policy is not a header value: {0}")]
    Policy(String),
}

/// The byte range the deployment data replaces: what the one data slot holds.
///
/// The document carries that slot once and the mount point once. Everything
/// else about the artifact is the Distribution's to get right: this bridge
/// substitutes into one non-executable element and changes nothing else.
pub(crate) fn slot(html: &str) -> Result<Range<usize>, ArtifactError> {
    if html.len() > MAX_ARTIFACT_BYTES {
        return Err(ArtifactError::TooLarge(html.len()));
    }
    read(html)
}

/// The same without the size bound, which the retrieved bytes carry: the
/// composed document is longer by what the slot holds.
pub(crate) fn read(html: &str) -> Result<Range<usize>, ArtifactError> {
    let opens = html.matches(SLOT_OPEN).count();
    if opens != 1 {
        return Err(ArtifactError::Slots(opens));
    }
    let text = html.find(SLOT_OPEN).expect("one slot element") + SLOT_OPEN.len();
    let end = html[text..]
        .find(SCRIPT_CLOSE)
        .map(|k| text + k)
        .ok_or(ArtifactError::Slots(0))?;

    if html.matches(MOUNT_POINT).count() != 1 {
        return Err(ArtifactError::MountPoint);
    }
    Ok(text..end)
}

/// The script hashes an artifact's own policy names.
///
/// The artifact is served with the hashes of the code it carries, and this
/// bridge carries them into the policy it composes rather than recomputing
/// them: a `script-src` naming anything but hashes is refused, so no source
/// this bridge did not write can reach the composed policy.
pub(crate) fn script_hashes(policy: &str) -> Result<Vec<String>, ArtifactError> {
    let refuse = |why: String| Err(ArtifactError::UpstreamPolicy(why));

    let Some(directive) = policy.split(';').find(|d| {
        d.split_whitespace()
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("script-src"))
    }) else {
        return refuse("names no script-src".into());
    };

    let hashes: Vec<String> = directive
        .split_whitespace()
        .skip(1)
        .map(str::to_owned)
        .collect();
    if hashes.is_empty() {
        return refuse("names a script-src with no source".into());
    }
    if hashes.len() > MAX_HASHES {
        return refuse(format!(
            "names {} script sources, and at most {MAX_HASHES} are read",
            hashes.len()
        ));
    }
    if let Some(source) = hashes.iter().find(|s| !is_hash(s)) {
        return refuse(format!("names the script source {source}, and not a hash"));
    }
    Ok(hashes)
}

/// Whether `source` is a CSP hash source expression: `'sha256-…'` and the two
/// longer digests, base64 between the quotes.
fn is_hash(source: &str) -> bool {
    let Some(rest) = ["'sha256-", "'sha384-", "'sha512-"]
        .into_iter()
        .find_map(|prefix| source.strip_prefix(prefix))
    else {
        return false;
    };
    let Some(digest) = rest.strip_suffix('\'') else {
        return false;
    };
    !digest.is_empty()
        && digest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=-_".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A document as the Distribution builds one: the slot, the mount point,
    /// and `body` after them.
    fn doc(body: &str) -> String {
        format!(
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">\
             <title>libID</title><body><main id=\"libid-root\"></main>\
             <script id=\"libid-callback-config\" type=\"application/json\">\
             {MARKER}</script>{body}</body></html>"
        )
    }

    /// The slot is the bytes between the slot element's tags, and nothing
    /// else moves.
    #[test]
    fn the_slot_is_what_the_element_holds() {
        let html = doc("<script type=\"module\">let x = 1;</script>");
        let slot = slot(&html).expect("a document this bridge reads");
        assert_eq!(html[slot].trim(), MARKER);
    }

    /// The fixture the tests serve is one this bridge reads.
    #[test]
    fn the_fixture_is_readable() {
        let html = crate::fixtures::ARTIFACT;
        let slot = slot(html).expect("the fixture artifact");
        assert_eq!(html[slot].trim(), MARKER);
    }

    /// Each of these is refused.
    #[test]
    fn a_document_this_bridge_cannot_serve_is_refused() {
        let slot_element = format!(
            "<script id=\"libid-callback-config\" type=\"application/json\">\
                     {MARKER}</script>"
        );
        for (why, html) in [
            (
                "no slot",
                "<body><main id=\"libid-root\"></main></body>".to_owned(),
            ),
            (
                "two slots",
                doc(&slot_element),
            ),
            (
                "no mount point",
                format!("<body>{slot_element}</body>"),
            ),
            (
                "two mount points",
                doc("<main id=\"libid-root\"></main>"),
            ),
            (
                "a slot element that never closes",
                format!(
                    "<body><main id=\"libid-root\"></main>\
                     <script id=\"libid-callback-config\" type=\"application/json\">{MARKER}"
                ),
            ),
        ] {
            assert!(slot(&html).is_err(), "{why} must be refused");
        }
    }

    /// The bound is the retrieved artifact's; the composed document is longer
    /// by what the slot holds and is read without it.
    #[test]
    fn the_composed_document_is_read_without_the_bound() {
        let filler = "x".repeat(MAX_ARTIFACT_BYTES - doc("").len() - 64);
        let html = doc(&format!("<p>{filler}</p>"));
        assert!(html.len() <= MAX_ARTIFACT_BYTES);
        assert!(slot(&html).is_ok());

        let composed = format!("{html}{}", "y".repeat(128));
        assert!(composed.len() > MAX_ARTIFACT_BYTES);
        assert!(
            read(&composed).is_ok(),
            "the composed document is not bounded a second time"
        );
        assert!(matches!(slot(&composed), Err(ArtifactError::TooLarge(_))));
    }

    /// The hashes are read out of the artifact's own `script-src`, whatever
    /// the rest of its policy says.
    #[test]
    fn the_hashes_are_the_ones_the_artifact_declares() {
        let policy = "default-src 'none'; SCRIPT-SRC 'sha256-abc123+/=' 'sha384-def'; \
                      style-src 'unsafe-inline'";
        assert_eq!(
            script_hashes(policy).expect("a hash-only script-src"),
            ["'sha256-abc123+/='", "'sha384-def'"]
        );
    }

    /// A policy naming anything but hashes is refused, so no source this
    /// bridge did not write reaches the composed policy.
    #[test]
    fn a_policy_that_is_not_hash_only_is_refused() {
        for policy in [
            "default-src 'none'",
            "script-src",
            "script-src 'unsafe-inline'",
            "script-src 'self'",
            "script-src https://cdn.example",
            "script-src 'nonce-abc'",
            "script-src 'strict-dynamic' 'sha256-abc'",
            "script-src 'sha256-'",
            "script-src sha256-abc",
            "script-src 'sha1-abc'",
            "script-src 'sha256-a b'",
            "script-src 'sha256-a' 'sha256-b' 'sha256-c' 'sha256-d' 'sha256-e' \
             'sha256-f' 'sha256-g' 'sha256-h' 'sha256-i'",
        ] {
            assert!(
                matches!(script_hashes(policy), Err(ArtifactError::UpstreamPolicy(_))),
                "{policy} must be refused"
            );
        }
    }
}
