//! The settings the suite reads: every variable, its section and whether
//! the section needs it, in [`VARIABLES`]; one typed value per section, read
//! by a function over a lookup so a test can supply its own.
//!
//! A section fails once, naming every required variable that is absent, and
//! [`both`] joins two sections' failures. The real lookup is the environment,
//! with the settings file read into it once per process; an exported value
//! wins over the file, and an empty value is an absent one.

use std::{
    fmt,
    path::PathBuf,
};

/// Where a section reads its variables: the value of a name, if it has one.
pub type Lookup<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// The settings file, when it is not the `.env.test` found from the working
/// directory upward.
pub const ENV_FILE: &str = "CEREMONY_ENV_FILE";

/// Whether a section needs a variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Need {
    /// The section fails without it.
    Required,
    /// The section reads it when it is set.
    Optional,
    /// It stands in for the required variable named, which wins where both
    /// are set.
    InsteadOf(&'static str),
}

/// Every variable the suite reads: its name, its section, and its need. The
/// crate's README says what each means.
pub const VARIABLES: &[(&str, &str, Need)] = {
    use Need::*;
    &[
        ("GH_OAUTH_CLIENT_ID", "github-app", Required),
        ("GH_OAUTH_CLIENT_SECRET", "github-app", Required),
        ("LIBID_TEST_PUBLIC_ORIGIN", "github-app", Required),
        ("GH_TEST_ALICE_USERNAME", "github-account", Required),
        ("GH_TEST_ALICE_PASSWORD", "github-account", Required),
        ("GH_TEST_ALICE_TOTP_SECRET", "github-account", Required),
        ("X_OAUTH_CLIENT_ID", "x-app", Required),
        ("LIBID_TEST_X_REDIRECT_URI", "x-app", Required),
        ("X_TEST_ALICE_USERNAME", "x-account", Required),
        ("X_TEST_ALICE_EMAIL", "x-account", Optional),
        ("X_TEST_ALICE_PASSWORD", "x-account", Optional),
        ("X_TEST_ALICE_COOKIES", "x-session", Required),
        (
            "X_TEST_ALICE_COOKIES_FILE",
            "x-session",
            InsteadOf("X_TEST_ALICE_COOKIES"),
        ),
        ("GOOGLE_OAUTH_CLIENT_ID", "google-app", Required),
        ("LIBID_TEST_GOOGLE_REDIRECT_URI", "google-app", Required),
        ("GOOGLE_TEST_ALICE_EMAIL", "google-account", Required),
        ("GOOGLE_TEST_ALICE_PASSWORD", "google-account", Optional),
        ("GOOGLE_TEST_ALICE_COOKIES", "google-session", Required),
        (
            "GOOGLE_TEST_ALICE_COOKIES_FILE",
            "google-session",
            InsteadOf("GOOGLE_TEST_ALICE_COOKIES"),
        ),
        (ENV_FILE, "tooling", Optional),
        ("CHROME", "tooling", Optional),
        ("BROWSER_HEAD", "tooling", Optional),
        ("BROWSER_TRACE", "tooling", Optional),
        ("X_CHALLENGE_TRACE", "tooling", Optional),
        ("PROFILE_SIGN_IN", "tooling", Optional),
        ("X_PROFILE", "tooling", Optional),
        ("GOOGLE_PROFILE", "tooling", Optional),
    ]
};

/// The required variables a read found absent, by section; `A (or B)` where
/// `B` stands in for `A`.
#[derive(Debug, PartialEq, Eq)]
pub struct Missing(pub Vec<(&'static str, Vec<String>)>);

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the live ceremony suite is missing settings: ")?;
        for (i, (section, names)) in self.0.iter().enumerate() {
            let sep = if i == 0 { "" } else { "; " };
            write!(f, "{sep}{section} needs {}", names.join(", "))?;
        }
        write!(f, ". Put them in a gitignored .env.test, or export them.")
    }
}

/// Both sections, or every variable either found absent.
pub fn both<A, B>(
    a: Result<A, Missing>,
    b: Result<B, Missing>,
) -> Result<(A, B), Missing> {
    match (a, b) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        (a, b) => Err(Missing(
            [a.err(), b.err()]
                .into_iter()
                .flatten()
                .flat_map(|m| m.0)
                .collect(),
        )),
    }
}

/// The variables of one section, noting each required one that is absent.
struct Reader<'a> {
    get: &'a Lookup<'a>,
    section: &'static str,
    missing: Vec<String>,
}

impl<'a> Reader<'a> {
    fn new(get: &'a Lookup<'a>, section: &'static str) -> Self {
        Reader {
            get,
            section,
            missing: Vec::new(),
        }
    }

    fn optional(&self, name: &str) -> Option<String> {
        (self.get)(name).filter(|value| !value.is_empty())
    }

    /// The value of `name`; empty where it is absent, which [`Reader::done`]
    /// then reports, so no absent value reaches a section.
    fn required(&mut self, name: &str) -> String {
        self.optional(name).unwrap_or_else(|| {
            self.missing.push(name.to_owned());
            String::new()
        })
    }

    fn done<T>(self, section: T) -> Result<T, Missing> {
        if self.missing.is_empty() {
            Ok(section)
        } else {
            Err(Missing(vec![(self.section, self.missing)]))
        }
    }
}

/// A saved session: `encoded`, the base64 an export prints, or else `file`,
/// the JSON it writes.
fn saved_session(
    get: &Lookup,
    section: &'static str,
    encoded: &'static str,
    file: &'static str,
) -> Result<SavedSession, Missing> {
    let r = Reader::new(get, section);
    match (r.optional(encoded), r.optional(file)) {
        (Some(value), _) => Ok(SavedSession::Encoded {
            var: encoded,
            value,
        }),
        (None, Some(path)) => Ok(SavedSession::File {
            var: file,
            path: path.into(),
        }),
        (None, None) => Err(Missing(vec![(
            section,
            vec![format!("{encoded} (or {file})")],
        )])),
    }
}

/// A section read from the environment.
pub fn read<T>(section: impl Fn(&Lookup) -> Result<T, Missing>) -> Result<T, Missing> {
    section(&environment)
}

/// A section read from the environment; a missing variable is a panic naming
/// every one absent.
pub fn load<T>(section: impl Fn(&Lookup) -> Result<T, Missing>) -> T {
    read(section).unwrap_or_else(|missing| panic!("{missing}"))
}

/// Whether `name` has a value in the environment.
pub fn is_set(name: &str) -> bool {
    environment(name).is_some_and(|value| !value.is_empty())
}

/// The variable `name`, from the environment or from the settings file; an
/// exported value wins over the file.
fn environment(name: &str) -> Option<String> {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| match std::env::var(ENV_FILE) {
        Ok(path) => {
            dotenvy::from_path(path).ok();
        }
        Err(_) => {
            dotenvy::from_filename(".env.test").ok();
        }
    });
    std::env::var(name).ok()
}

/// The GitHub OAuth App the deployment under test is configured with.
pub struct GitHubApp {
    pub client_id: String,
    pub client_secret: String,
    pub public_origin: String,
}

pub fn github_app(get: &Lookup) -> Result<GitHubApp, Missing> {
    let mut r = Reader::new(get, "github-app");
    let app = GitHubApp {
        client_id: r.required("GH_OAUTH_CLIENT_ID"),
        client_secret: r.required("GH_OAUTH_CLIENT_SECRET"),
        public_origin: r.required("LIBID_TEST_PUBLIC_ORIGIN"),
    };
    r.done(app)
}

/// The GitHub test account, and the base32 key of its authenticator app.
pub struct GitHubAccount {
    pub username: String,
    pub password: String,
    pub totp_secret: String,
}

pub fn github_account(get: &Lookup) -> Result<GitHubAccount, Missing> {
    let mut r = Reader::new(get, "github-account");
    let account = GitHubAccount {
        username: r.required("GH_TEST_ALICE_USERNAME"),
        password: r.required("GH_TEST_ALICE_PASSWORD"),
        totp_secret: r.required("GH_TEST_ALICE_TOTP_SECRET"),
    };
    r.done(account)
}

/// The X app, a public PKCE client.
pub struct XApp {
    pub client_id: String,
    pub redirect_uri: String,
}

pub fn x_app(get: &Lookup) -> Result<XApp, Missing> {
    let mut r = Reader::new(get, "x-app");
    let app = XApp {
        client_id: r.required("X_OAUTH_CLIENT_ID"),
        redirect_uri: r.required("LIBID_TEST_X_REDIRECT_URI"),
    };
    r.done(app)
}

/// The X test account.
pub struct XAccount {
    pub username: String,
    pub email: Option<String>,
    pub password: Option<String>,
}

pub fn x_account(get: &Lookup) -> Result<XAccount, Missing> {
    let mut r = Reader::new(get, "x-account");
    let account = XAccount {
        username: r.required("X_TEST_ALICE_USERNAME"),
        email: r.optional("X_TEST_ALICE_EMAIL"),
        password: r.optional("X_TEST_ALICE_PASSWORD"),
    };
    r.done(account)
}

/// The X test account's saved session.
pub struct XSession(pub SavedSession);

pub fn x_session(get: &Lookup) -> Result<XSession, Missing> {
    saved_session(
        get,
        "x-session",
        "X_TEST_ALICE_COOKIES",
        "X_TEST_ALICE_COOKIES_FILE",
    )
    .map(XSession)
}

/// The Google OAuth client.
pub struct GoogleApp {
    pub client_id: String,
    pub redirect_uri: String,
}

pub fn google_app(get: &Lookup) -> Result<GoogleApp, Missing> {
    let mut r = Reader::new(get, "google-app");
    let app = GoogleApp {
        client_id: r.required("GOOGLE_OAUTH_CLIENT_ID"),
        redirect_uri: r.required("LIBID_TEST_GOOGLE_REDIRECT_URI"),
    };
    r.done(app)
}

/// The Google test account.
pub struct GoogleAccount {
    pub email: String,
    pub password: Option<String>,
}

pub fn google_account(get: &Lookup) -> Result<GoogleAccount, Missing> {
    let mut r = Reader::new(get, "google-account");
    let account = GoogleAccount {
        email: r.required("GOOGLE_TEST_ALICE_EMAIL"),
        password: r.optional("GOOGLE_TEST_ALICE_PASSWORD"),
    };
    r.done(account)
}

/// The Google test account's saved session.
pub struct GoogleSession(pub SavedSession);

pub fn google_session(get: &Lookup) -> Result<GoogleSession, Missing> {
    saved_session(
        get,
        "google-session",
        "GOOGLE_TEST_ALICE_COOKIES",
        "GOOGLE_TEST_ALICE_COOKIES_FILE",
    )
    .map(GoogleSession)
}

/// A saved session as a setting carries it, named by the variable it came
/// from; `browser::cookies::saved` decodes it.
#[derive(Debug, PartialEq, Eq)]
pub enum SavedSession {
    /// Base64 of the JSON cookie list.
    Encoded { var: &'static str, value: String },
    /// A path to the JSON cookie list.
    File { var: &'static str, path: PathBuf },
}

/// How the browser runs, what it leaves behind to diagnose a run, and the
/// profiles the exports read; nothing here is required.
pub struct Tooling {
    pub chrome: Option<PathBuf>,
    pub headed: bool,
    pub trace: Option<PathBuf>,
    pub challenge_trace: Option<PathBuf>,
    pub profile_sign_in: bool,
    pub x_profile: PathBuf,
    pub google_profile: PathBuf,
}

fn tooling_from(get: &Lookup) -> Tooling {
    let r = Reader::new(get, "tooling");
    let path = |name| r.optional(name).map(PathBuf::from);
    Tooling {
        chrome: path("CHROME"),
        headed: path("BROWSER_HEAD").is_some(),
        trace: path("BROWSER_TRACE"),
        challenge_trace: path("X_CHALLENGE_TRACE"),
        profile_sign_in: path("PROFILE_SIGN_IN").is_some(),
        x_profile: path("X_PROFILE").unwrap_or_else(|| ".env.x-profile".into()),
        google_profile: path("GOOGLE_PROFILE")
            .unwrap_or_else(|| ".env.google-profile".into()),
    }
}

/// The tooling settings of this process, read from the environment once.
pub fn tooling() -> &'static Tooling {
    static TOOLING: std::sync::LazyLock<Tooling> =
        std::sync::LazyLock::new(|| tooling_from(&environment));
    &TOOLING
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::BTreeSet,
        path::Path,
    };

    use super::*;

    /// A lookup over `pairs`.
    fn map<'a>(pairs: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<String> + 'a {
        |name| pairs.iter().find(|p| p.0 == name).map(|p| p.1.to_owned())
    }

    /// The names a failed read reports absent, joined.
    fn absent<T>(read: Result<T, Missing>) -> String {
        let Err(Missing(sections)) = read else {
            panic!("the read fails")
        };
        let names: Vec<String> = sections.into_iter().flat_map(|s| s.1).collect();
        names.join(", ")
    }

    /// Every name `read` asks an empty lookup for, under `section`: required
    /// where the read reports it absent, standing in where it follows `(or`,
    /// optional otherwise.
    fn asked<T>(
        section: &'static str,
        read: impl Fn(&Lookup) -> Result<T, Missing>,
    ) -> Vec<(String, &'static str, Need)> {
        let names = RefCell::new(Vec::new());
        let outcome = read(&|name: &str| {
            names.borrow_mut().push(name.to_owned());
            None
        });
        if let Err(Missing(sections)) = &outcome {
            assert!(sections.iter().all(|s| s.0 == section));
        }
        let reported = outcome.err().map(|m| m.to_string()).unwrap_or_default();
        let need = |name: &str| {
            let stand_in = VARIABLES
                .iter()
                .find(|v| reported.contains(&format!("{} (or {name})", v.0)));
            match stand_in {
                Some(of) => Need::InsteadOf(of.0),
                None if reported.contains(&format!(" {name}")) => Need::Required,
                None => Need::Optional,
            }
        };
        let names = names.into_inner();
        names
            .iter()
            .map(|n| (n.clone(), section, need(n)))
            .collect()
    }

    #[test]
    fn the_sections_read_exactly_what_the_table_lists() {
        let mut read: BTreeSet<_> = [
            asked("github-app", github_app),
            asked("github-account", github_account),
            asked("x-app", x_app),
            asked("x-account", x_account),
            asked("x-session", x_session),
            asked("google-app", google_app),
            asked("google-account", google_account),
            asked("google-session", google_session),
            asked("tooling", |get| Ok::<_, Missing>(tooling_from(get))),
        ]
        .concat()
        .into_iter()
        .collect();
        // The real lookup reads the settings file before any other name.
        read.insert((ENV_FILE.to_owned(), "tooling", Need::Optional));
        let table: BTreeSet<_> = VARIABLES
            .iter()
            .map(|&(n, s, need)| (n.to_owned(), s, need))
            .collect();
        assert_eq!(table.len(), VARIABLES.len(), "each variable is listed once");
        assert_eq!(read, table);
    }

    #[test]
    fn a_read_names_every_absent_variable_of_both_sections_at_once() {
        let absent = both(github_app(&map(&[])), github_account(&map(&[])));
        assert!(absent.err().expect("absent").to_string().contains(
            "github-app needs GH_OAUTH_CLIENT_ID, GH_OAUTH_CLIENT_SECRET, \
             LIBID_TEST_PUBLIC_ORIGIN; github-account needs GH_TEST_ALICE_USERNAME, \
             GH_TEST_ALICE_PASSWORD, GH_TEST_ALICE_TOTP_SECRET."
        ));
    }

    #[test]
    fn the_owners_requirements_hold() {
        let empty_id = [
            ("X_OAUTH_CLIENT_ID", ""),
            ("LIBID_TEST_X_REDIRECT_URI", "u"),
        ];
        assert_eq!(absent(x_app(&map(&empty_id))), "X_OAUTH_CLIENT_ID");
        let no_totp = [
            ("GH_TEST_ALICE_USERNAME", "a"),
            ("GH_TEST_ALICE_PASSWORD", "p"),
        ];
        assert_eq!(
            absent(github_account(&map(&no_totp))),
            "GH_TEST_ALICE_TOTP_SECRET"
        );
        let x = x_account(&map(&[("X_TEST_ALICE_USERNAME", "a")])).expect("reads");
        assert_eq!((x.email, x.password), (None, None));
        assert_eq!(
            absent(x_session(&map(&[]))),
            "X_TEST_ALICE_COOKIES (or X_TEST_ALICE_COOKIES_FILE)"
        );
        let file = [("X_TEST_ALICE_COOKIES_FILE", "f.json")];
        let read = x_session(&map(&file)).expect("reads").0;
        assert!(
            matches!(read, SavedSession::File { path, .. } if path == Path::new("f.json"))
        );
        let both = [file[0], ("X_TEST_ALICE_COOKIES", "e30=")];
        let read = x_session(&map(&both)).expect("reads").0;
        assert!(matches!(read, SavedSession::Encoded { value, .. } if value == "e30="));
    }

    #[test]
    fn tooling_defaults_where_nothing_is_set() {
        let tooling = tooling_from(&map(&[]));
        assert!(!tooling.headed && !tooling.profile_sign_in && tooling.trace.is_none());
        assert_eq!(tooling.x_profile, PathBuf::from(".env.x-profile"));
        assert_eq!(tooling.google_profile, PathBuf::from(".env.google-profile"));
        let tooling = tooling_from(&map(&[("BROWSER_HEAD", "1"), ("X_PROFILE", "/x")]));
        assert!(tooling.headed);
        assert_eq!(tooling.x_profile, PathBuf::from("/x"));
    }
}
