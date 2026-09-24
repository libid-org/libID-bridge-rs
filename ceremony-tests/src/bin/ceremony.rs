//! The suite's own tasks, run by a person from `ceremony-tests/`: exporting a
//! saved session for the X and Google rungs, converting a browser's cookie
//! export into the X one, and listing which settings are set. Values are
//! never printed, except the saved session an export prints where it is given
//! no file to write.

use std::path::{
    Path,
    PathBuf,
};

use ceremony_tests::{
    browser::{
        cookies,
        google,
        x,
    },
    settings::{
        self,
        Missing,
        Need,
        VARIABLES,
    },
};
use clap::{
    Parser,
    Subcommand,
};

#[derive(Parser)]
#[command(name = "ceremony", about = "The live ceremony suite's own tasks")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Export the session a person signed in to in the platform's Chrome
    /// profile. The first export, and one whose session the platform no
    /// longer honours, opens a Chrome for a person to sign in.
    Export {
        #[command(subcommand)]
        platform: Platform,
    },
    /// Turn a browser's cookie export into a saved-session setting.
    Convert {
        #[command(subcommand)]
        platform: Conversion,
    },
    /// List each setting as set, missing or unset; never its value.
    Settings {
        /// One section alone.
        #[arg(value_parser = clap::builder::PossibleValuesParser::new(sections()))]
        section: Option<String>,
    },
}

#[derive(Subcommand)]
enum Platform {
    /// X's session, from `X_PROFILE`, as `X_TEST_ALICE_COOKIES`.
    X {
        #[command(flatten)]
        out: Out,
    },
    /// Google's session, from `GOOGLE_PROFILE`, as `GOOGLE_TEST_ALICE_COOKIES`.
    Google {
        #[command(flatten)]
        out: Out,
    },
}

#[derive(clap::Args)]
struct Out {
    /// Write the session as JSON to this file, which its owner alone may
    /// read, whole or not at all; without it the base64 setting is printed.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Conversion {
    /// A list of `x.com` cookies, or Playwright's `storageState`, printed as
    /// `X_TEST_ALICE_COOKIES`.
    X {
        /// The browser's export; keep it under a gitignored `.env*` name.
        export: PathBuf,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    match Cli::parse().task {
        Task::Export {
            platform: Platform::X { out },
        } => {
            let profile = settings::tooling().x_profile.clone();
            let cookies = x::Export { profile }.fresh_cookies().await;
            cookies::deliver(&cookies, out.out.as_deref(), "X_TEST_ALICE_COOKIES");
        }
        Task::Export {
            platform: Platform::Google { out },
        } => {
            let (app, account) = settings::read(|get| {
                settings::both(settings::google_app(get), settings::google_account(get))
            })
            .unwrap_or_else(|missing| exit(missing));
            let profile = settings::tooling().google_profile.clone();
            google::export_fresh_session(&app, &account, profile, out.out.as_deref())
                .await;
        }
        Task::Convert {
            platform: Conversion::X { export },
        } => convert_x(&export),
        Task::Settings { section } => {
            for &(name, in_section, need) in VARIABLES {
                if section.as_deref().is_none_or(|s| s == in_section) {
                    let shown = if need == Need::Required {
                        "required"
                    } else {
                        "optional"
                    };
                    let status = status(name, need);
                    println!("{name:<32} {in_section:<16} {shown:<10} {status}");
                }
            }
        }
    }
}

/// The sections, in the order the table lists them.
fn sections() -> Vec<&'static str> {
    let mut sections: Vec<&'static str> = VARIABLES.iter().map(|v| v.1).collect();
    sections.dedup();
    sections
}

/// The absent variables named, and a failed exit.
fn exit(missing: Missing) -> ! {
    eprintln!("{missing}");
    std::process::exit(2)
}

fn convert_x(export: &Path) {
    let json = std::fs::read_to_string(export).unwrap_or_else(|e| {
        eprintln!("{}: {e}", export.display());
        std::process::exit(2)
    });
    println!("X_TEST_ALICE_COOKIES={}", x::secret_from_export(&json));
}

/// Whether `name` is set: `set`, or else `missing` where its section
/// requires it and nothing stands in for it, or `unset`.
fn status(name: &'static str, need: Need) -> String {
    if settings::is_set(name) {
        return "set".into();
    }
    let stand_in = VARIABLES
        .iter()
        .find(|other| other.2 == Need::InsteadOf(name) && settings::is_set(other.0));
    match (need, stand_in) {
        (Need::Required, Some(other)) => format!("unset, {} stands in", other.0),
        (Need::Required, None) => "missing".into(),
        _ => "unset".into(),
    }
}
