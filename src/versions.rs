//! The Distribution's version list: `GET {ccdpOrigin}/ccdp/versions.json`,
//! the platform ceremony versions whose Prover implementation the
//! Distribution bundles. One JSON object, keyed by platform id as the
//! ceremony catalog spells it, each value a nonempty ascending array of
//! unsigned 16-bit integers.
//!
//! A key this bridge does not know is ignored: a Distribution may bundle a
//! platform this bridge predates. Every value is held to the grammar, and
//! any violation refuses the whole list, and the list last accepted stays.
//! Key order carries no meaning.

use std::{
    collections::BTreeMap,
    fmt,
};

use serde::{
    de,
    Deserialize,
};

use crate::deployment::PlatformId;

/// The largest version list this bridge will read. Three platforms with one
/// version each is under fifty bytes; the bound leaves room for the
/// platforms this bridge does not know.
pub const MAX_VERSIONS_BYTES: usize = 64 * 1024;

/// A version list this bridge accepted: for each platform it knows and the
/// list names, the versions the Distribution bundles, ascending. Parsing is
/// the one constructor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "BTreeMap<String, Bundled>")]
pub struct Versions(BTreeMap<PlatformId, Bundled>);

impl Versions {
    /// `body` read as the version list, or the first rule it breaks.
    pub fn parse(body: &[u8]) -> serde_json::Result<Versions> {
        serde_json::from_slice(body)
    }

    /// The versions the Distribution bundles for `platform`, ascending, or
    /// `None` where the list does not name it.
    pub fn bundled_for(&self, platform: PlatformId) -> Option<&[u16]> {
        self.0.get(&platform).map(|bundled| bundled.0.as_slice())
    }
}

impl From<BTreeMap<String, Bundled>> for Versions {
    /// The entries whose key spells a platform this bridge knows.
    fn from(listed: BTreeMap<String, Bundled>) -> Versions {
        Versions(
            listed
                .into_iter()
                .filter_map(|(key, bundled)| Some((key.parse().ok()?, bundled)))
                .collect(),
        )
    }
}

impl fmt::Display for Versions {
    /// Each platform the list names with its versions, as `github=[1, 2]
    /// x=[1]`; `<none>` for a list naming no platform this bridge knows.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("<none>");
        }
        for (i, (platform, bundled)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{platform}={:?}", bundled.0)?;
        }
        Ok(())
    }
}

/// One platform's versions as the list writes them: an array of unsigned
/// 16-bit integers, nonempty and ascending, so duplicate-free.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Vec<u16>")]
pub struct Bundled(Vec<u16>);

impl TryFrom<Vec<u16>> for Bundled {
    type Error = de::value::Error;

    fn try_from(versions: Vec<u16>) -> Result<Bundled, Self::Error> {
        if versions.is_empty() {
            return Err(de::Error::custom("the platform lists no version"));
        }
        if let Some(pair) = versions.windows(2).find(|pair| pair[0] >= pair[1]) {
            return Err(de::Error::custom(format_args!(
                "the platform lists version {} after {}, and versions are ascending",
                pair[1], pair[0]
            )));
        }
        Ok(Bundled(versions))
    }
}
