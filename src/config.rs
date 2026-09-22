//! Configuration: where the process listens, and the file the deployment is
//! written in.
//!
//! The bind address is not ceremony configuration, and a container image sets
//! it in the environment, so it is a flag and a variable. Everything else is a
//! key of the file. The enabled platforms can be written nowhere else and a
//! bridge with no platform could serve no ceremony, so the file is required
//! whatever else is set, and there is no second way to spell what it holds.

use clap::{
    CommandFactory,
    FromArgMatches,
    Parser,
};
use serde::Deserialize;

use crate::{
    deployment::PlatformProfile,
    error::{
        Error,
        Result,
    },
};

/// The canonical libID Distribution, which a file naming none selects.
const DEFAULT_CCDP_ORIGIN: &str = "https://lib.id";

/// The deployment's settings.
#[derive(Parser, Debug)]
#[command(name = "libid-server-rs", version, about)]
pub struct Config {
    /// Path to the TOML configuration file the deployment is written in.
    #[arg(long, env = "LIBID_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// Host to bind. Use 0.0.0.0 in containers.
    #[arg(long, env = "HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind.
    #[arg(long, env = "PORT", default_value = "8722")]
    pub port: u16,

    /// The application origins admitted to read the public ceremony
    /// configuration, from the file's `allowed_app_origins`. Nonempty, each
    /// in canonical form and read as written.
    #[arg(skip)]
    pub allowed_app_origins: Vec<String>,

    /// The CCDP Distribution this bridge selects, from the file's
    /// `ccdp_origin`: the canonical origin serving the Callback artifact and
    /// everything the browser runs after it. A file naming none selects the
    /// canonical libID Distribution.
    #[arg(skip)]
    pub ccdp_origin: String,

    /// The enabled platforms, from the file's `[[platforms]]` tables: each
    /// names a platform, its public client id, the ceremony versions it
    /// advertises and, for `github`, the public client credential.
    #[arg(skip)]
    pub platforms: Vec<PlatformProfile>,
}

/// The configuration file.
///
/// An unknown key is refused. The bind address and port are not keys: a
/// container image sets them in the environment, so a file naming them would
/// be read and not applied.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    /// [`Config::allowed_app_origins`].
    allowed_app_origins: Option<Vec<String>>,
    /// [`Config::ccdp_origin`].
    ccdp_origin: Option<String>,
    /// [`Config::platforms`]:
    ///
    /// ```toml
    /// [[platforms]]
    /// id = "github"
    /// client_id = "Iv1.0123456789abcdef"
    /// versions = [1]
    /// client_credential = "..."
    /// ```
    platforms: Option<Vec<PlatformProfile>>,
}

impl Config {
    /// Resolve the configuration from the process's arguments, environment
    /// and configuration file.
    pub fn resolve() -> Result<Config> {
        Config::resolve_from(std::env::args_os())
    }

    /// The same, from an explicit argv.
    pub fn resolve_from<I, T>(argv: I) -> Result<Config>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Config::merged(Config::command(), argv)
    }

    /// The same, parsing with `command`: which environment variables reach a
    /// flag is that command's to say.
    pub fn merged<I, T>(command: clap::Command, argv: I) -> Result<Config>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let matches = command.get_matches_from(argv);
        let mut cfg = Config::from_arg_matches(&matches).map_err(|e| Error::Config {
            detail: e.to_string(),
        })?;
        let Some(path) = cfg.config.clone() else {
            return Err(Error::Config {
                detail: "no configuration file; name one with --config or \
                         LIBID_CONFIG. The deployment is written in it."
                    .into(),
            });
        };

        let refuse = |detail: String| Error::Config {
            detail: format!("{}: {detail}", path.display()),
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|e| refuse(format!("cannot be read: {e}")))?;
        let file: FileConfig =
            toml::from_str(&text).map_err(|e| refuse(e.message().to_owned()))?;

        cfg.allowed_app_origins = file.allowed_app_origins.unwrap_or_default();
        cfg.ccdp_origin = file
            .ccdp_origin
            .unwrap_or_else(|| DEFAULT_CCDP_ORIGIN.to_owned());
        cfg.platforms = file.platforms.unwrap_or_default();
        Ok(cfg)
    }
}
