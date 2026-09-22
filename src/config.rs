//! What the command line says, and what the file says. Two things, because
//! they are read from two places by two libraries and nothing belongs to
//! both.
//!
//! The command line says where the process listens and which file to read.
//! Where the process listens is not ceremony configuration and a container
//! image sets it in the environment, so it has no place in the file. The file
//! says everything else. The enabled platforms can be written nowhere else
//! and a bridge with no platform could serve no ceremony, so the file is
//! required whatever else is set, and there is no second way to spell what it
//! holds.

use clap::Parser;
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

/// What the command line says.
#[derive(Parser, Debug)]
#[command(name = "libid-server-rs", version, about)]
pub struct Cli {
    /// Path to the TOML file the deployment is written in.
    #[arg(long, env = "LIBID_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// Host to bind. Use 0.0.0.0 in containers.
    #[arg(long, env = "HOST", default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind.
    #[arg(long, env = "PORT", default_value = "8722")]
    pub port: u16,
}

impl Cli {
    /// What this process was invoked with.
    pub fn resolve() -> Result<Cli> {
        Cli::resolve_from(std::env::args_os())
    }

    /// The same, from an explicit argv.
    pub fn resolve_from<I, T>(argv: I) -> Result<Cli>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Cli::parsed_by(<Cli as clap::CommandFactory>::command(), argv)
    }

    /// The same, parsing with `command`: which environment variables reach a
    /// flag is that command's to say.
    pub fn parsed_by<I, T>(command: clap::Command, argv: I) -> Result<Cli>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Cli as clap::FromArgMatches>::from_arg_matches(&command.get_matches_from(argv))
            .map_err(|e| Error::Config {
                detail: e.to_string(),
            })
    }

    /// The deployment this invocation names, read from its file.
    pub fn settings(&self) -> Result<Settings> {
        let Some(path) = self.config.as_ref() else {
            return Err(Error::Config {
                detail: "no configuration file; name one with --config or \
                         LIBID_CONFIG. The deployment is written in it."
                    .into(),
            });
        };
        Settings::read(path)
    }
}

/// What the file says.
///
/// An unknown key is refused. The bind address and port are not keys: a
/// container image sets them in the environment, so a file naming them would
/// be read and not applied.
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The application origins admitted to read the public ceremony
    /// configuration. Nonempty, each in canonical form and read as written.
    #[serde(default)]
    pub allowed_app_origins: Vec<String>,

    /// The CCDP Distribution this bridge selects: the canonical origin
    /// serving the Callback artifact and everything the browser runs after
    /// it. A file naming none selects the canonical libID Distribution.
    #[serde(default = "default_ccdp_origin")]
    pub ccdp_origin: String,

    /// The enabled platforms, as `[[platforms]]` tables: each names a
    /// platform, its public client id, the ceremony versions it advertises
    /// and, for `github`, the public client credential.
    ///
    /// ```toml
    /// [[platforms]]
    /// id = "github"
    /// client_id = "Iv1.0123456789abcdef"
    /// versions = [1]
    /// client_credential = "..."
    /// ```
    #[serde(default)]
    pub platforms: Vec<PlatformProfile>,
}

impl Settings {
    /// The deployment written in the file at `path`.
    pub fn read(path: &std::path::Path) -> Result<Settings> {
        let refuse = |detail: String| Error::Config {
            detail: format!("{}: {detail}", path.display()),
        };
        let text = std::fs::read_to_string(path)
            .map_err(|e| refuse(format!("cannot be read: {e}")))?;
        toml::from_str(&text).map_err(|e| refuse(e.message().to_owned()))
    }
}

/// The canonical Distribution, for a file that names none.
fn default_ccdp_origin() -> String {
    DEFAULT_CCDP_ORIGIN.to_owned()
}
