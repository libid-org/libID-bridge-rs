//! What a deployment is, checked once at startup: the Distribution it
//! selects, the origins it admits, the platforms it enables with the OAuth
//! client each runs, and the public ceremony configuration composed from
//! them. Nothing here is retrieved or bound.

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

/// The longest `client_id` a platform entry carries, in bytes. The Application
/// forwards it unchanged into CCDP's `ProveIdentity`, whose wire limits refuse
/// a longer one, so every ceremony would fail on it.
pub const MAX_CLIENT_ID_BYTES: usize = 512;

/// The longest `client_credential` a platform entry carries, in bytes, under
/// the same `ProveIdentity` wire limits.
pub const MAX_CLIENT_CREDENTIAL_BYTES: usize = 512;

/// The checked inputs of one deployment.
pub struct Deployment {
    /// The CCDP Distribution this deployment selects.
    pub ccdp_origin: Origin,
    /// The effective admission set `allowedAppOrigins ∪ {ccdpOrigin}`: the one
    /// rule the configuration route applies, and what the callback document
    /// is told. The CCDP origin is a member of it literally.
    pub allowed_origins: Arc<[Admitted]>,
    /// The enabled platforms, each with the client its ceremony runs.
    pub platforms: Vec<PlatformProfile>,
}

impl Deployment {
    /// Every rule a deployment must satisfy before it serves a request,
    /// applied to the resolved configuration; the first rule broken is the
    /// error.
    pub fn checked(settings: &Settings) -> Result<Deployment> {
        // Held to its spelling, as an exact allowlist member is, so the file
        // states the origin published and inserted byte for byte.
        let ccdp_origin = Origin::listed("CCDP_ORIGIN", &settings.ccdp_origin)?;
        // The resolved CCDP origin joins the admitted set once; an overridden
        // `CCDP_ORIGIN` does not keep `https://lib.id` admitted unless it is
        // listed. Membership is the literal spelling: the Callback asserts
        // the list carries this origin itself, so a member covering it — an
        // origin pattern, or `*` — is a different member and does not stand
        // in for it.
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
    /// receives: composed and serialized once, at startup.
    pub fn ceremony_config(&self) -> Bytes {
        CeremonyConfig {
            ccdp_origin: &self.ccdp_origin,
            platforms: &self.platforms,
        }
        .serialized()
    }
}

/// The platforms a ceremony can run against, each spelled in lowercase
/// wherever it is written: the file and the public configuration. A name
/// outside this catalog is refused while parsing a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, strum::Display)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
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
}

/// One enabled platform, as one `[[platforms]]` table: the platform and the
/// one OAuth client every version of its ceremony runs. Its entry in the
/// public record is that client, as `clientId` and, where there is one,
/// `clientCredential`.
///
/// ```toml
/// [[platforms]]
/// id = "github"
/// client_id = "Iv1.0123456789abcdef"
/// client_credential = "..."
/// ```
///
/// Whether a platform carries a credential is not a different shape, it is a
/// rule, and [`PlatformProfile::checked`] applies it: GitHub's ceremony sends
/// one as `client_secret` and no other ceremony sends one at all.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformProfile {
    /// Which platform: the key its entry is published under.
    pub id: PlatformId,
    /// The public OAuth client identifier: nonempty printable ASCII without
    /// whitespace, at most [`MAX_CLIENT_ID_BYTES`].
    pub client_id: String,
    /// The OAuth App's client secret, on exactly the platforms whose ceremony
    /// sends one: public application configuration, nonempty printable ASCII
    /// without whitespace, at most [`MAX_CLIENT_CREDENTIAL_BYTES`].
    #[serde(default)]
    pub client_credential: Option<String>,
}

impl PlatformProfile {
    /// This table checked: a client id of nonempty printable ASCII without
    /// whitespace within [`MAX_CLIENT_ID_BYTES`], and a credential of the same
    /// within [`MAX_CLIENT_CREDENTIAL_BYTES`] exactly where the platform's
    /// ceremony sends one. A refusal names the key as the file spells it,
    /// never the value.
    pub fn checked(self) -> Result<PlatformProfile> {
        let id = self.id;
        let refuse = |detail: String| Error::Config {
            detail: format!("platforms: {detail}"),
        };
        if self.client_id.is_empty() {
            return Err(refuse(format!("{id} carries an empty client_id")));
        }
        // A client id the platform could never issue is a typo the
        // deployment publishes and every ceremony then fails on.
        if !printable_without_whitespace(&self.client_id) {
            return Err(refuse(format!(
                "{id}'s client_id is not printable ASCII without whitespace"
            )));
        }
        if self.client_id.len() > MAX_CLIENT_ID_BYTES {
            return Err(refuse(format!(
                "{id}'s client_id is longer than {MAX_CLIENT_ID_BYTES} bytes"
            )));
        }
        // A credential belongs to exactly the ceremonies that send one.
        match (id.sends_a_credential(), self.client_credential.as_deref()) {
            (false, Some(_)) => Err(refuse(format!(
                "{id} carries a client_credential, and its ceremony sends none"
            ))),
            (true, None) => Err(refuse(format!(
                "{id} carries no client_credential, and its ceremony sends one"
            ))),
            (_, Some("")) => {
                Err(refuse(format!("{id} carries an empty client_credential")))
            }
            (_, Some(credential)) if !printable_without_whitespace(credential) => {
                Err(refuse(format!(
                    "{id}'s client_credential is not printable ASCII without \
                     whitespace"
                )))
            }
            (_, Some(credential)) if credential.len() > MAX_CLIENT_CREDENTIAL_BYTES => {
                Err(refuse(format!(
                    "{id}'s client_credential is longer than \
                     {MAX_CLIENT_CREDENTIAL_BYTES} bytes"
                )))
            }
            _ => Ok(self),
        }
    }
}

/// Check the enabled set: nonempty, each platform once, and each as
/// [`PlatformProfile::checked`] has it.
pub fn platforms(profiles: Vec<PlatformProfile>) -> Result<Vec<PlatformProfile>> {
    if profiles.is_empty() {
        return Err(Error::Config {
            detail: "platforms: no platform is enabled; add a [[platforms]] table to \
                     the configuration file"
                .into(),
        });
    }
    for p in &profiles {
        if profiles.iter().filter(|q| q.id == p.id).nth(1).is_some() {
            return Err(Error::Config {
                detail: format!("platforms: {} appears more than once", p.id),
            });
        }
    }
    profiles.into_iter().map(PlatformProfile::checked).collect()
}

/// Whether every byte of `value` is printable ASCII carrying no whitespace,
/// which is what a public client identifier and a public client credential
/// are made of.
fn printable_without_whitespace(value: &str) -> bool {
    value.bytes().all(|b| (0x21..=0x7E).contains(&b))
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
    pub ccdp_origin: &'a Origin,
    /// The enabled platforms, checked.
    pub platforms: &'a [PlatformProfile],
}

impl CeremonyConfig<'_> {
    /// The record: `ccdpOrigin`, and under `platforms` each enabled
    /// platform's entry by its id, in the order `serde_json::Map` keeps its
    /// keys. An entry is the platform's `clientId` and, where its ceremony
    /// sends one, `clientCredential`.
    fn record(&self) -> Value {
        let mut by_id = Map::new();
        for p in self.platforms {
            let mut entry = json!({ "clientId": p.client_id });
            if let Some(credential) = p.client_credential.as_deref() {
                entry["clientCredential"] = Value::from(credential);
            }
            by_id.insert(p.id.to_string(), entry);
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
