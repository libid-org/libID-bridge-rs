//! The response policy of a callback document: the script hashes its
//! Distribution declared, read out of the policy the artifact arrived under.
//!
//! The hashes are carried into the policy this bridge composes and are never
//! recomputed. What they cover is the Distribution's to state, and the policy
//! this bridge serves admits those hashes and no other script source, so code
//! they do not cover does not run whoever wrote it.

/// The marker the build leaves for deployment data. Fixed by the artifact
/// contract, and the one thing substitution touches.
pub const MARKER: &str = "__LIBID_CALLBACK_CONFIG__";

/// The largest artifact this bridge will read. The retrieval stops at it,
/// which is the one place the bytes arrive.
pub const MAX_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

/// The most script hashes an artifact's policy may name.
pub const MAX_HASHES: usize = 16;

/// Why an artifact was refused. Every variant is a refusal to serve, never a
/// repair.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactError {
    /// The document does not carry the one configuration marker.
    #[error("the document carries {0} configuration markers, and must carry one")]
    Markers(usize),
    /// The artifact's own policy names something this bridge will not serve.
    #[error("the artifact's own policy {0}")]
    UpstreamPolicy(String),
    /// The composed policy is not a header value.
    #[error("the composed policy is not a header value: {0}")]
    Policy(String),
}

/// The script hashes an artifact's own policy names.
///
/// A `script-src` naming anything but hash sources is refused: those sources
/// become the ones this bridge serves its own document under, so a
/// Distribution that named `'unsafe-inline'` would be choosing the policy of
/// an origin that is not its own.
pub fn script_hashes(policy: &str) -> Result<Vec<String>, ArtifactError> {
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

/// Whether `source` is a CSP hash source expression: one of the three digest
/// algorithms, case-insensitively as the grammar spells them, with base64
/// between the quotes.
pub fn is_hash(source: &str) -> bool {
    let Some(rest) = source.strip_prefix('\'') else {
        return false;
    };
    let Some(digest) = rest.strip_suffix('\'') else {
        return false;
    };
    let Some((algorithm, digest)) = digest.split_once('-') else {
        return false;
    };
    if !["sha256", "sha384", "sha512"]
        .iter()
        .any(|a| algorithm.eq_ignore_ascii_case(a))
    {
        return false;
    }
    !digest.is_empty()
        && digest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=-_".contains(&b))
}
