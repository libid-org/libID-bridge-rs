//! What a deployment is, checked once at startup: the Distribution it
//! selects, the origins it admits, the platforms it enables with the OAuth
//! clients their ceremony versions run, and the public ceremony configuration
//! composed from them. Nothing here is retrieved or bound.

use std::{
    collections::BTreeMap,
    sync::Arc,
};

use bytes::Bytes;
use serde::{
    Deserialize,
    Serialize,
};
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
    /// The enabled platforms, each with the clients its versions run.
    pub platforms: Vec<Platform>,
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

/// One OAuth client: the public client identifier and, on the platforms
/// whose ceremony sends one, the OAuth App's client secret. The file writes
/// a platform's defaults as `default_client_id` and
/// `default_client_credential` on the platform's own table, and the client
/// of one version as a `[platforms.version_override.N]` table carrying
/// `client_id` and `client_credential`. The public record carries it as
/// `clientId` and, where there is one, `clientCredential`.
///
/// Whether a client carries a credential is not a different shape, it is a
/// rule, and [`Client::checked`] applies it: GitHub's ceremony sends one as
/// `client_secret` and no other ceremony sends one at all.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all(serialize = "camelCase"))]
pub struct Client {
    /// The public OAuth client identifier: nonempty printable ASCII without
    /// whitespace.
    pub client_id: String,
    /// The client credential, on exactly the platforms whose ceremony sends
    /// one: nonempty printable ASCII without whitespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_credential: Option<String>,
}

impl Client {
    /// This client checked as `platform`'s: a client id of nonempty printable
    /// ASCII without whitespace, and a credential of the same exactly where
    /// the platform's ceremony sends one. A refusal names the key as the
    /// file spells it, which is `under` and then `client_id` or
    /// `client_credential`: `default_` on the platform's own table,
    /// `version_override.N.` under it.
    pub fn checked(self, platform: PlatformId, under: &str) -> Result<Client> {
        let refuse = |detail: String| Error::Config {
            detail: format!("platforms: {platform}{detail}"),
        };
        if self.client_id.is_empty() {
            return Err(refuse(format!(" carries an empty {under}client_id")));
        }
        // A client id the platform could never issue is a typo the
        // deployment publishes and every ceremony then fails on.
        if !printable_without_whitespace(&self.client_id) {
            return Err(refuse(format!(
                "'s {under}client_id is not printable ASCII without whitespace"
            )));
        }
        // A credential belongs to exactly the ceremonies that send one.
        match (
            platform.sends_a_credential(),
            self.client_credential.as_deref(),
        ) {
            (false, Some(_)) => Err(refuse(format!(
                " carries a {under}client_credential, and its ceremony sends none"
            ))),
            (true, None) => Err(refuse(format!(
                " carries no {under}client_credential, and its ceremony sends one"
            ))),
            (_, Some("")) => Err(refuse(format!(
                " carries an empty {under}client_credential"
            ))),
            (_, Some(credential)) if !printable_without_whitespace(credential) => {
                Err(refuse(format!(
                    "'s {under}client_credential is not printable ASCII without \
                     whitespace"
                )))
            }
            _ => Ok(self),
        }
    }
}

/// One enabled platform, as one `[[platforms]]` table: the platform, the
/// client its versions run unless one is written for them, and the clients
/// written for particular versions.
///
/// ```toml
/// [[platforms]]
/// id = "github"
/// default_client_id = "Iv1.0123456789abcdef"
/// default_client_credential = "..."
///
/// [platforms.version_override.2]
/// client_id = "Iv1.fedcba9876543210"
/// client_credential = "..."
/// ```
///
/// Which versions exist is not written here: the Distribution publishes the
/// versions it bundles, and the application reads that list and runs each
/// with the client this table assigns it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformProfile {
    /// Which platform.
    pub id: PlatformId,
    /// The public OAuth client identifier every version runs unless
    /// `version_override` names one for it.
    pub default_client_id: String,
    /// The client credential those versions send, on exactly the platforms
    /// whose ceremony sends one.
    #[serde(default)]
    pub default_client_credential: Option<String>,
    /// The client of particular versions, keyed by the decimal spelling of
    /// the version, bare or quoted. A TOML key is a string whatever it
    /// spells; [`Platform::checked`] reads each as a version.
    #[serde(default)]
    pub version_override: BTreeMap<String, Client>,
}

/// One enabled platform, checked: the client its versions run by default,
/// and the versions with a client of their own. Serialized, it is the
/// platform's entry in the public record: the default client's `clientId`
/// and `clientCredential` and, where any override is written,
/// `versionOverrides` keyed by the decimal spelling of the version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Platform {
    /// Which platform: the key its entry is published under.
    #[serde(skip_serializing)]
    pub id: PlatformId,
    /// The client every version runs unless `overrides` names it.
    #[serde(flatten)]
    pub default: Client,
    /// The clients written for particular versions, by version. Every one
    /// written is published: whether a version exists is the Distribution's
    /// to say and the application's to check.
    #[serde(
        rename = "versionOverrides",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub overrides: BTreeMap<u16, Client>,
}

impl Platform {
    /// `profile` checked: its defaults as a client, every `version_override`
    /// key as a version, and every override as a client. The first rule
    /// broken is the error.
    pub fn checked(profile: PlatformProfile) -> Result<Platform> {
        let id = profile.id;
        let default = Client {
            client_id: profile.default_client_id,
            client_credential: profile.default_client_credential,
        }
        .checked(id, "default_")?;
        let mut overrides = BTreeMap::new();
        for (key, client) in profile.version_override {
            let Some(version) = Platform::version_key(&key) else {
                return Err(Error::Config {
                    detail: format!(
                        "platforms: {id}'s version_override key {key:?} is not a \
                         version; a key is the decimal spelling of an unsigned \
                         16-bit integer, bare or quoted, with no sign, leading \
                         zero or whitespace"
                    ),
                });
            };
            let client = client.checked(id, &format!("version_override.{key}."))?;
            overrides.insert(version, client);
        }
        Ok(Platform {
            id,
            default,
            overrides,
        })
    }

    /// `key` as a version: the canonical decimal spelling of an unsigned
    /// 16-bit integer, digits alone with no leading zero, or `None`. `parse`
    /// alone would take a sign and leading zeros, and two spellings of one
    /// version would be two keys TOML cannot tell apart.
    fn version_key(key: &str) -> Option<u16> {
        let canonical = !key.is_empty()
            && key.bytes().all(|b| b.is_ascii_digit())
            && (key == "0" || !key.starts_with('0'));
        canonical.then(|| key.parse().ok()).flatten()
    }
}

/// Check the enabled set: nonempty, each platform once, and each as
/// [`Platform::checked`] has it.
pub fn platforms(profiles: Vec<PlatformProfile>) -> Result<Vec<Platform>> {
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
    profiles.into_iter().map(Platform::checked).collect()
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
    pub ccdp_origin: &'a Origin,
    /// The enabled platforms, checked.
    pub platforms: &'a [Platform],
}

impl CeremonyConfig<'_> {
    /// The record: `ccdpOrigin`, and under `platforms` each enabled
    /// platform's entry by its id, in the order `serde_json::Map` keeps its
    /// keys.
    fn record(&self) -> Value {
        let by_id: Map<String, Value> = self
            .platforms
            .iter()
            .map(|p| (p.id.to_string(), json!(p)))
            .collect();
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
