//! Configuration: a TOML file, environment variables and command-line flags.

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

/// The deployment's settings.
///
/// Every flag has an environment variable of the same name. Precedence is
/// command line, then environment, then the configuration file, then the
/// default.
#[derive(Parser, Debug)]
#[command(name = "libid-server-rs", version, about)]
pub struct Config {
    /// Path to a TOML configuration file. Every setting below can be written
    /// in it under its own name in lower case.
    #[arg(long, env = "LIBID_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// Host to bind. Use 0.0.0.0 in containers. Flag or environment only:
    /// where the process listens is not ceremony configuration.
    #[arg(long, env = "HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind. Flag or environment only.
    #[arg(long, env = "PORT", default_value = "8722")]
    pub port: u16,

    /// Comma-separated application origins admitted to read the public
    /// ceremony configuration. Nonempty, each in canonical form.
    #[arg(long, env = "ALLOWED_APP_ORIGINS", value_delimiter = ',')]
    pub allowed_app_origins: Vec<String>,

    /// The CCDP Distribution this bridge selects: the canonical origin serving
    /// the Callback artifact and everything the browser runs after it.
    /// Published in the configuration and inserted into the callback document.
    #[arg(long, env = "CCDP_ORIGIN", default_value = "https://lib.id")]
    pub ccdp_origin: String,

    /// The enabled platforms, from the configuration file's `[[platforms]]`
    /// tables: each names a platform, its public client id, the ceremony
    /// versions it advertises and, for `github`, the public client
    /// credential.
    #[arg(skip)]
    pub platforms: Vec<PlatformProfile>,
}

/// The configuration file.
///
/// Every key is optional and corresponds to the [`Config`] field of the same
/// name; an unknown key is refused. `allowed_app_origins` is a list, and the
/// platforms are `[[platforms]]` tables. The bind address and port are not
/// keys: a container image sets them in the environment, which beats a file,
/// so a file naming them would be read and not applied.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    /// [`Config::allowed_app_origins`].
    pub allowed_app_origins: Option<Vec<String>>,
    /// [`Config::ccdp_origin`].
    pub ccdp_origin: Option<String>,
    /// [`Config::platforms`]:
    ///
    /// ```toml
    /// [[platforms]]
    /// id = "github"
    /// client_id = "Iv1.0123456789abcdef"
    /// versions = [1]
    /// client_credential = "..."
    /// ```
    pub platforms: Option<Vec<PlatformProfile>>,
}

/// Whether clap supplied `id` from its default rather than from the command
/// line or the environment.
fn defaulted(matches: &clap::ArgMatches, id: &str) -> bool {
    !matches!(
        matches.value_source(id),
        Some(clap::parser::ValueSource::CommandLine)
            | Some(clap::parser::ValueSource::EnvVariable)
    )
}

impl Config {
    /// Resolve the configuration from the process's arguments, environment
    /// and configuration file.
    pub fn resolve() -> Result<Config> {
        Config::resolve_from(std::env::args_os())
    }

    /// The same, from an explicit argv. A value from the file is used where
    /// neither a flag nor an environment variable set the field.
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
        // The enabled platforms are read from the file and nowhere else, so a
        // run that names none could serve no ceremony.
        let Some(path) = cfg.config.clone() else {
            return Err(Error::Config {
                detail: "no configuration file; name one with --config or \
                         LIBID_CONFIG. The enabled platforms are read from it."
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

        if defaulted(&matches, "ccdp_origin") {
            cfg.ccdp_origin = file.ccdp_origin.unwrap_or(cfg.ccdp_origin);
        }
        if defaulted(&matches, "allowed_app_origins") {
            cfg.allowed_app_origins =
                file.allowed_app_origins.unwrap_or(cfg.allowed_app_origins);
        }
        cfg.platforms = file.platforms.unwrap_or_default();
        Ok(cfg)
    }
}
