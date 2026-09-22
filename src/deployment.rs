//! What a deployment is, checked once at startup: the Distribution it
//! selects, the origins it admits, the platforms it enables, and the public
//! ceremony configuration projected from them. Nothing here is retrieved or
//! bound.

use std::sync::Arc;

use bytes::Bytes;
use serde::Deserialize;
use serde_json::{
    json,
    Map,
    Value,
};

use crate::{
    config::Settings,
    error::{
        Error,
        Result,
    },
    origin::Origin,
};

/// The checked inputs of one deployment.
pub struct Deployment {
    /// The CCDP Distribution this deployment selects.
    pub ccdp_origin: Origin,
    /// The effective admission set `allowedAppOrigins ∪ {ccdpOrigin}`: the one
    /// rule the configuration route applies, and what the callback document
    /// is told.
    pub allowed_origins: Arc<[Origin]>,
    /// The enabled platforms.
    pub platforms: Vec<PlatformProfile>,
}

impl Deployment {
    /// Every rule a deployment must satisfy before it serves a request,
    /// applied to the resolved configuration; the first rule broken is the
    /// error.
    pub fn checked(settings: &Settings) -> Result<Deployment> {
        let ccdp_origin = ccdp_origin(&settings.ccdp_origin)?;
        // The resolved CCDP origin joins the admitted set once; an overridden
        // `CCDP_ORIGIN` does not keep `https://lib.id` admitted unless it is
        // listed.
        let allowed_origins: Arc<[Origin]> = {
            let mut set = allowed_app_origins(&settings.allowed_app_origins)?;
            if !set.contains(&ccdp_origin) {
                set.push(ccdp_origin.clone());
            }
            set.into()
        };
        let platforms = platforms(settings.platforms.clone())?;
        Ok(Deployment {
            ccdp_origin,
            allowed_origins,
            platforms,
        })
    }

    /// The public ceremony configuration, as the bytes every admitted caller
    /// receives.
    pub fn ceremony_config(&self) -> Bytes {
        CeremonyConfig {
            ccdp_origin: &self.ccdp_origin,
            platforms: &self.platforms,
        }
        .serialized()
    }
}

/// The platforms a ceremony can run against. A name outside this catalog is
/// refused while parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformId {
    /// Keyed `google`.
    Google,
    /// Keyed `x`.
    X,
    /// Keyed `github`.
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

/// One enabled platform, with the fields its ceremony takes. In the
/// configuration file, one `[[platforms]]` table keyed by `id`.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "id", rename_all = "lowercase", deny_unknown_fields)]
pub enum PlatformProfile {
    /// A public client.
    Google {
        /// The public OAuth client identifier.
        client_id: String,
        /// Platform ceremony versions, nonempty and duplicate-free.
        versions: Vec<u16>,
    },
    /// A public client.
    X {
        /// The public OAuth client identifier.
        client_id: String,
        /// Platform ceremony versions, nonempty and duplicate-free.
        versions: Vec<u16>,
    },
    /// A confidential client whose credential is public: the browser's
    /// token request sends it as `client_secret`.
    Github {
        /// The public OAuth client identifier.
        client_id: String,
        /// Platform ceremony versions, nonempty and duplicate-free.
        versions: Vec<u16>,
        /// The OAuth App's client secret, published as
        /// `clientCredential`: public application configuration,
        /// nonempty printable ASCII without whitespace.
        client_credential: String,
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

    /// The public client credential the entry carries: GitHub's.
    pub fn client_credential(&self) -> Option<&str> {
        match self {
            Self::Github {
                client_credential, ..
            } => Some(client_credential),
            Self::Google { .. } | Self::X { .. } => None,
        }
    }
}

/// Check the enabled set: nonempty, each platform once, each with a client id,
/// a nonempty, duplicate-free version list and, where its ceremony takes one,
/// a client credential of nonempty printable ASCII without whitespace.
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
        // A client id the platform could never issue is a typo the
        // deployment publishes and every ceremony then fails on.
        if !printable_without_whitespace(p.client_id()) {
            return Err(refuse(format!(
                "{id}'s client_id is not printable ASCII without whitespace"
            )));
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
        }
        if let Some(credential) = p.client_credential() {
            if credential.is_empty() {
                return Err(refuse(format!("{id} carries an empty client_credential")));
            }
            if !printable_without_whitespace(credential) {
                return Err(refuse(format!(
                    "{id}'s client_credential is not printable ASCII \
                     without whitespace"
                )));
            }
        }
    }
    Ok(profiles)
}

/// Whether every byte of `value` is printable ASCII carrying no whitespace,
/// which is what a public client identifier and a public client credential
/// are made of.
fn printable_without_whitespace(value: &str) -> bool {
    value.bytes().all(|b| (0x21..=0x7E).contains(&b))
}

/// The CCDP Distribution this deployment selects, in canonical form. A host a
/// policy cannot name is refused: the callback document's policy names this
/// origin as a `frame-src` source, and a browser discards a source whose
/// grammar it cannot parse, leaving the document framing nothing. An IPv6
/// literal and an underscore are both outside that grammar. The admitted
/// application origins reach the document as escaped data rather than as
/// policy, so they are not held to this.
fn ccdp_origin(spelling: &str) -> Result<Origin> {
    let origin = Origin::parse("CCDP_ORIGIN", spelling)?;
    if !origin.names_a_policy_host() {
        return Err(Error::Config {
            detail: format!(
                "CCDP_ORIGIN {spelling} names a host a Content-Security-Policy \
                 cannot carry as a source, which admits letters, digits, `-` \
                 and `.`; name the Distribution by a host made of those"
            ),
        });
    }
    Ok(origin)
}

/// The application origins admitted to read the configuration, each as
/// written: one that is not already canonical is refused rather than folded,
/// and a blank one is a member the operator did not mean to write.
fn allowed_app_origins(list: &[String]) -> Result<Vec<Origin>> {
    let mut out = Vec::new();
    // The index is the member's own, so a refusal names the entry the
    // operator wrote.
    for (i, spelling) in list.iter().enumerate() {
        let field = format!("ALLOWED_APP_ORIGINS[{i}]");
        if spelling.is_empty() {
            return Err(Error::Config {
                detail: format!("{field} is blank"),
            });
        }
        let origin = Origin::listed(&field, spelling)?;
        // A duplicate is refused, not folded.
        if out.contains(&origin) {
            return Err(Error::Config {
                detail: format!("ALLOWED_APP_ORIGINS names {origin} more than once"),
            });
        }
        out.push(origin);
    }
    if out.is_empty() {
        return Err(Error::Config {
            detail: "ALLOWED_APP_ORIGINS is empty, so no application could \
                     read the ceremony configuration"
                .into(),
        });
    }
    Ok(out)
}

/// The public ceremony configuration: what one deployment publishes.
pub struct CeremonyConfig<'a> {
    /// The CCDP Distribution this deployment selects.
    pub ccdp_origin: &'a crate::origin::Origin,
    /// The enabled platforms, checked.
    pub platforms: &'a [PlatformProfile],
}

impl CeremonyConfig<'_> {
    fn record(&self) -> Value {
        let mut by_id = Map::new();
        for p in self.platforms {
            let mut entry = json!({
                "clientId": p.client_id(),
                "ceremonyVersions": p.versions(),
            });
            if let Some(credential) = p.client_credential() {
                entry["clientCredential"] = Value::from(credential);
            }
            by_id.insert(p.id().as_str().to_owned(), entry);
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
