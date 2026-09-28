//! The Distribution's version list: `GET {ccdpOrigin}/ccdp/versions.json`,
//! the platform ceremony versions whose Prover implementation the
//! Distribution bundles. One JSON object, keyed by platform id as the
//! ceremony catalog spells it, each value a nonempty, duplicate-free,
//! ascending array of unsigned 16-bit integers.
//!
//! A key this bridge does not know is ignored, value and all: a Distribution
//! may bundle a platform this bridge predates. Any other violation refuses
//! the whole list, and the list last accepted stays. Key order carries no
//! meaning.

use std::{
    collections::BTreeMap,
    fmt,
};

use serde_json::Value;

use crate::deployment::PlatformId;

/// The largest version list this bridge will read. Three platforms with one
/// version each is under fifty bytes; the bound leaves room for the
/// platforms this bridge does not know.
pub const MAX_VERSIONS_BYTES: usize = 64 * 1024;

/// Why a version list was refused. Every variant refuses the whole list,
/// never one platform of it.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VersionsError {
    /// The body is not JSON.
    #[error("the version list is not JSON: {0}")]
    Json(String),
    /// The top level is not an object.
    #[error("the version list is not a JSON object")]
    NotAnObject,
    /// A platform's value is not an array.
    #[error("the version list's {platform} is not an array")]
    NotAnArray {
        /// Whose value.
        platform: PlatformId,
    },
    /// An element of a platform's array is not an unsigned 16-bit integer.
    #[error(
        "the version list's {platform} holds {found}, and a version is an unsigned \
         16-bit integer"
    )]
    NotAVersion {
        /// Whose array.
        platform: PlatformId,
        /// The element: a number as written, any other value by its kind.
        found: String,
    },
    /// A platform lists no version.
    #[error("the version list's {platform} is empty")]
    Empty {
        /// Whose array.
        platform: PlatformId,
    },
    /// A platform lists a version twice.
    #[error("the version list's {platform} lists version {version} twice")]
    Duplicate {
        /// Whose array.
        platform: PlatformId,
        /// The version listed twice.
        version: u16,
    },
    /// A platform's array is not ascending.
    #[error("the version list's {platform} is not in ascending order")]
    Unordered {
        /// Whose array.
        platform: PlatformId,
    },
}

/// A version list this bridge accepted: for each platform it knows and the
/// list names, the versions the Distribution bundles, ascending. Parsing is
/// the one constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versions(BTreeMap<PlatformId, Vec<u16>>);

impl Versions {
    /// `body` read as the version list, or the first rule it breaks.
    pub fn parse(body: &[u8]) -> Result<Versions, VersionsError> {
        let value: Value = serde_json::from_slice(body)
            .map_err(|e| VersionsError::Json(e.to_string()))?;
        let Value::Object(entries) = value else {
            return Err(VersionsError::NotAnObject);
        };
        let mut listed = BTreeMap::new();
        for (key, value) in &entries {
            // A platform this bridge does not know is ignored, value and all.
            let Some(platform) = PlatformId::named(key) else {
                continue;
            };
            listed.insert(platform, Versions::listed_for(platform, value)?);
        }
        Ok(Versions(listed))
    }

    /// The versions the Distribution bundles for `platform`, ascending, or
    /// `None` where the list does not name it.
    pub fn bundled_for(&self, platform: PlatformId) -> Option<&[u16]> {
        self.0.get(&platform).map(Vec::as_slice)
    }

    /// One platform's array: nonempty, every element an unsigned 16-bit
    /// integer, each greater than the one before it.
    fn listed_for(
        platform: PlatformId,
        value: &Value,
    ) -> Result<Vec<u16>, VersionsError> {
        let Some(items) = value.as_array() else {
            return Err(VersionsError::NotAnArray { platform });
        };
        if items.is_empty() {
            return Err(VersionsError::Empty { platform });
        }
        let mut versions: Vec<u16> = Vec::with_capacity(items.len());
        for item in items {
            let version = item
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| VersionsError::NotAVersion {
                    platform,
                    found: kind_of(item),
                })?;
            if let Some(&last) = versions.last() {
                if version == last {
                    return Err(VersionsError::Duplicate { platform, version });
                }
                if version < last {
                    return Err(VersionsError::Unordered { platform });
                }
            }
            versions.push(version);
        }
        Ok(versions)
    }
}

impl fmt::Display for Versions {
    /// Each platform the list names with its versions, as `github=[1, 2]
    /// x=[1]`; `<none>` for a list naming no platform this bridge knows.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("<none>");
        }
        for (i, (platform, versions)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{platform}={versions:?}")?;
        }
        Ok(())
    }
}

/// `value` as a refusal names it: a number as written, anything else by its
/// kind, so a string the length of the whole body is never echoed.
fn kind_of(value: &Value) -> String {
    match value {
        Value::Number(n) => n.to_string(),
        Value::Null => "null".to_owned(),
        Value::Bool(_) => "a boolean".to_owned(),
        Value::String(_) => "a string".to_owned(),
        Value::Array(_) => "an array".to_owned(),
        Value::Object(_) => "an object".to_owned(),
    }
}
