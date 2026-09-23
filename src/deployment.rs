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
    origin::{
        Admitted,
        Origin,
    },
};

/// The checked inputs of one deployment.
pub struct Deployment {
    /// The CCDP Distribution this deployment selects.
    pub ccdp_origin: Origin,
    /// The effective admission set `allowedAppOrigins ∪ {ccdpOrigin}`: the one
    /// rule the configuration route applies, and what the callback document
    /// is told. The CCDP origin is a member of it literally.
    pub allowed_origins: Arc<[Admitted]>,
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
        // listed. Membership is the literal spelling: the Callback asserts
        // the list carries this origin itself, so an origin pattern covering
        // it is a different member and does not stand in for it.
        let allowed_origins: Arc<[Admitted]> = {
            let mut set = allowed_app_origins(&settings.allowed_app_origins)?;
            if !set.iter().any(|m| m.as_str() == ccdp_origin.as_str()) {
                set.push(Admitted::Exact(ccdp_origin.clone()));
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformId {
    /// Keyed `google`.
    Google,
    /// Keyed `x`.
    X,
    /// Keyed `github`.
    Github,
}

impl PlatformId {
    /// Whether this platform's ceremony sends a client credential in its
    /// token request. GitHub's does, and requires one whether or not the
    /// client is public; no other does.
    pub fn sends_a_credential(self) -> bool {
        matches!(self, PlatformId::Github)
    }

    /// The wire spelling: the key in the public configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::X => "x",
            Self::Github => "github",
        }
    }
}

/// One enabled platform, as one `[[platforms]]` table.
///
/// Every platform carries the same three things. Whether it also carries a
/// credential is not a different shape, it is a rule, and [`platforms`]
/// applies it: GitHub's ceremony sends one as `client_secret` and no other
/// ceremony sends one at all.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformProfile {
    /// Which platform.
    pub id: PlatformId,
    /// The public OAuth client identifier.
    pub client_id: String,
    /// Platform ceremony versions, nonempty and duplicate-free. List order
    /// has no meaning.
    pub versions: Vec<u16>,
    /// The OAuth App's client secret, published as `clientCredential`:
    /// public application configuration, nonempty printable ASCII without
    /// whitespace.
    #[serde(default)]
    pub client_credential: Option<String>,
}

/// Check the enabled set: nonempty, each platform once, each with a client id,
/// a nonempty, duplicate-free version list, and a client credential on
/// exactly the platforms whose ceremony sends one, of nonempty printable
/// ASCII without whitespace.
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
        let id = p.id.as_str();
        if profiles.iter().filter(|q| q.id == p.id).nth(1).is_some() {
            return Err(refuse(format!("{id} appears more than once")));
        }
        if p.client_id.is_empty() {
            return Err(refuse(format!("{id} carries no client_id")));
        }
        // A client id the platform could never issue is a typo the
        // deployment publishes and every ceremony then fails on.
        if !printable_without_whitespace(&p.client_id) {
            return Err(refuse(format!(
                "{id}'s client_id is not printable ASCII without whitespace"
            )));
        }
        if p.versions.is_empty() {
            return Err(refuse(format!("{id} advertises no version")));
        }
        for v in &p.versions {
            if p.versions.iter().filter(|w| w == &v).nth(1).is_some() {
                return Err(refuse(format!(
                    "{id} advertises version {v} more than once"
                )));
            }
        }
        // A credential belongs to exactly the ceremonies that send one.
        match (p.id.sends_a_credential(), p.client_credential.as_deref()) {
            (false, Some(_)) => {
                return Err(refuse(format!(
                    "{id} carries a client_credential, and its ceremony sends none"
                )))
            }
            (true, None) => {
                return Err(refuse(format!("{id} carries no client_credential")))
            }
            (_, None) => {}
            (_, Some(credential)) => {
                if credential.is_empty() {
                    return Err(refuse(format!(
                        "{id} carries an empty client_credential"
                    )));
                }
                if !printable_without_whitespace(credential) {
                    return Err(refuse(format!(
                        "{id}'s client_credential is not printable ASCII \
                     without whitespace"
                    )));
                }
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

/// The application allowlist admitted to read the configuration, each member
/// as written: an exact origin that is not already canonical is refused
/// rather than folded, a pattern that is not well formed is refused rather
/// than read as an origin, and a blank member is one the operator did not
/// mean to write.
fn allowed_app_origins(list: &[String]) -> Result<Vec<Admitted>> {
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
        let member = Admitted::listed(&field, spelling)?;
        // A duplicate is refused, not folded. Duplication is of the spelling,
        // so a pattern and an origin it covers are two members.
        if out.contains(&member) {
            return Err(Error::Config {
                detail: format!("ALLOWED_APP_ORIGINS names {member} more than once"),
            });
        }
        out.push(member);
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
                "clientId": p.client_id,
                "ceremonyVersions": p.versions,
            });
            if let Some(credential) = p.client_credential.as_deref() {
                entry["clientCredential"] = Value::from(credential);
            }
            by_id.insert(p.id.as_str().to_owned(), entry);
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
