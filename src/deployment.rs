//! The enabled platforms, checked once at startup, and the public ceremony
//! configuration projected from them.

use bytes::Bytes;
use serde::Deserialize;
use serde_json::{
    json,
    Map,
    Value,
};

use crate::error::{
    Error,
    Result,
};

/// The platforms a ceremony can run against. A name outside this catalog is
/// refused while parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformId {
    /// Google.
    Google,
    /// X.
    X,
    /// GitHub, whose token exchange this service performs.
    Github,
}

impl PlatformId {
    /// The wire spelling: the key in the public configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::X => "x",
            Self::Github => "github",
        }
    }
}

/// The one GitHub ceremony version this service's token exchange implements.
const GITHUB_ONLY_VERSION: u16 = 1;

/// One enabled platform, with the fields its ceremony takes. In the
/// configuration file, one `[[platforms]]` table keyed by `id`.
#[derive(Clone, Deserialize)]
#[serde(tag = "id", rename_all = "lowercase", deny_unknown_fields)]
pub enum PlatformProfile {
    /// Google: the public client id and the ceremony versions advertised.
    Google {
        /// The public OAuth client identifier.
        client_id: String,
        /// Platform ceremony versions, nonempty and duplicate-free.
        versions: Vec<u16>,
    },
    /// X: the public client id and the ceremony versions advertised.
    X {
        /// The public OAuth client identifier.
        client_id: String,
        /// Platform ceremony versions, nonempty and duplicate-free.
        versions: Vec<u16>,
    },
    /// GitHub: the public client id, the ceremony versions advertised, and
    /// the client secret the token exchange spends.
    Github {
        /// The public OAuth client identifier.
        client_id: String,
        /// Platform ceremony versions, nonempty and duplicate-free.
        versions: Vec<u16>,
        /// The OAuth App's client secret; `GH_OAUTH_CLIENT_SECRET` overrides it.
        #[serde(default)]
        client_secret: Option<String>,
    },
}

impl PlatformProfile {
    /// Which platform.
    pub fn id(&self) -> PlatformId {
        match self {
            Self::Google { .. } => PlatformId::Google,
            Self::X { .. } => PlatformId::X,
            Self::Github { .. } => PlatformId::Github,
        }
    }

    /// The public OAuth client identifier.
    pub fn client_id(&self) -> &str {
        match self {
            Self::Google { client_id, .. }
            | Self::X { client_id, .. }
            | Self::Github { client_id, .. } => client_id,
        }
    }

    /// The ceremony versions advertised. List order has no meaning.
    pub fn versions(&self) -> &[u16] {
        match self {
            Self::Google { versions, .. }
            | Self::X { versions, .. }
            | Self::Github { versions, .. } => versions,
        }
    }

    /// The client secret the entry carries: GitHub's, when set.
    pub fn client_secret(&self) -> Option<&str> {
        match self {
            Self::Github { client_secret, .. } => client_secret.as_deref(),
            Self::Google { .. } | Self::X { .. } => None,
        }
    }

    /// Whether this deployment enables the confidential GitHub exchange.
    pub fn is_github(&self) -> bool {
        self.id() == PlatformId::Github
    }
}

/// `Debug` redacts the client secret.
impl std::fmt::Debug for PlatformProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut entry = f.debug_struct(self.id().as_str());
        entry
            .field("client_id", &self.client_id())
            .field("versions", &self.versions());
        if self.is_github() {
            entry.field("client_secret", &self.client_secret().map(|_| "<redacted>"));
        }
        entry.finish()
    }
}

/// Check the enabled set: nonempty, each platform once, each with a client id
/// and a nonempty, duplicate-free version list that this service can serve.
pub fn platforms(profiles: Vec<PlatformProfile>) -> Result<Vec<PlatformProfile>> {
    let refuse = |detail: String| Error::Config {
        detail: format!("platforms: {detail}"),
    };

    if profiles.is_empty() {
        return Err(refuse(
            "no platform is enabled; add a [[platforms]] table to the configuration file"
                .into(),
        ));
    }

    for p in &profiles {
        let id = p.id().as_str();
        if profiles
            .iter()
            .filter(|q| q.id() == p.id())
            .nth(1)
            .is_some()
        {
            return Err(refuse(format!("{id} appears more than once")));
        }
        if p.client_id().is_empty() {
            return Err(refuse(format!("{id} carries no client_id")));
        }
        if p.versions().is_empty() {
            return Err(refuse(format!("{id} advertises no version")));
        }
        for v in p.versions() {
            if p.versions().iter().filter(|w| *w == v).nth(1).is_some() {
                return Err(refuse(format!(
                    "{id} advertises version {v} more than once"
                )));
            }
            if p.is_github() && *v != GITHUB_ONLY_VERSION {
                return Err(refuse(format!(
                    "github advertises version {v}, and this bridge's token \
                     exchange implements {GITHUB_ONLY_VERSION} only"
                )));
            }
        }
    }
    Ok(profiles)
}

/// The public ceremony configuration: what one deployment publishes.
pub struct CeremonyConfig<'a> {
    /// The CCDP Distribution this deployment selects.
    pub ccdp_origin: &'a str,
    /// The enabled platforms, checked.
    pub platforms: &'a [PlatformProfile],
}

impl CeremonyConfig<'_> {
    fn record(&self) -> Value {
        let mut by_id = Map::new();
        for p in self.platforms {
            by_id.insert(
                p.id().as_str().to_owned(),
                json!({
                    "clientId": p.client_id(),
                    "ceremonyVersions": p.versions(),
                }),
            );
        }
        json!({
            "ccdpOrigin": self.ccdp_origin,
            "platforms": Value::Object(by_id),
        })
    }

    /// That record as the bytes it is served in, serialized once at startup.
    pub fn serialized(&self) -> Bytes {
        Bytes::from(
            serde_json::to_vec(&self.record())
                .expect("a Value of string keys serializes into memory"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = r#"[{"id":"github","client_id":"Iv1.0","versions":[1]}]"#;

    /// Parse records as the configuration file would, then check them.
    fn checked(json: &str) -> Result<Vec<PlatformProfile>> {
        let records: Vec<PlatformProfile> =
            serde_json::from_str(json).map_err(|e| Error::Config {
                detail: e.to_string(),
            })?;
        platforms(records)
    }

    #[test]
    fn a_well_formed_set_parses() {
        let p = checked(ONE).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p[0].is_github());
        assert_eq!(p[0].versions(), [1]);
        assert_eq!(p[0].client_secret(), None);
    }

    /// The github entry carries its secret; `Debug` does not print it.
    #[test]
    fn the_github_entry_carries_its_secret_and_debug_redacts_it() {
        let p = checked(
            r#"[{"id":"github","client_id":"Iv1.0","versions":[1],"client_secret":"ghs_in_the_entry"}]"#,
        )
        .unwrap();
        assert_eq!(p[0].client_secret(), Some("ghs_in_the_entry"));
        let printed = format!("{:?}", p[0]);
        assert!(!printed.contains("ghs_"), "{printed}");
        assert!(printed.contains("<redacted>"), "{printed}");
    }

    /// Each of these is refused at startup.
    #[test]
    fn a_set_this_service_cannot_serve_stops_the_process() {
        for (why, json) in [
            ("empty", "[]"),
            (
                "unknown platform",
                r#"[{"id":"twitter","client_id":"a","versions":[1]}]"#,
            ),
            (
                "duplicate platform",
                r#"[{"id":"x","client_id":"a","versions":[1]},{"id":"x","client_id":"b","versions":[1]}]"#,
            ),
            (
                "no versions",
                r#"[{"id":"x","client_id":"a","versions":[]}]"#,
            ),
            (
                "duplicate version",
                r#"[{"id":"x","client_id":"a","versions":[1,1]}]"#,
            ),
            (
                "github on a version its token service does not implement",
                r#"[{"id":"github","client_id":"a","versions":[2]}]"#,
            ),
            (
                "additional member",
                r#"[{"id":"x","client_id":"a","label":"X","versions":[1]}]"#,
            ),
            (
                "a secret on a platform that has none",
                r#"[{"id":"x","client_id":"a","versions":[1],"client_secret":"s"}]"#,
            ),
        ] {
            assert!(checked(json).is_err(), "{why} must be refused");
        }
    }
}
