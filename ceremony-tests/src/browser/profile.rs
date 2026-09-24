//! A Chrome profile a person signed in to, kept between sessions: the
//! cookies it holds, and the one sign-in a platform lets a person complete
//! only in a Chrome with nothing attached to it.

use std::path::{
    Path,
    PathBuf,
};

use chromiumoxide::{
    cdp::browser_protocol::{
        network::Cookie,
        storage::GetCookiesParams,
    },
    detection::{
        default_executable,
        DetectionOptions,
    },
};

use super::{
    Platform,
    Session,
    POLL,
};
use crate::env::optional;

/// Set to open the sign-in window even when the profile holds a session the
/// platform honours: a renewal on demand.
pub const SIGN_IN: &str = "PROFILE_SIGN_IN";

/// How long a probe waits for the platform to show the session signed in.
pub const PROBE: std::time::Duration = std::time::Duration::from_secs(20);

/// The profile directory `var` names, or `default`, relative to the directory
/// the tests run from.
pub fn named(var: &str, default: &str) -> PathBuf {
    optional(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

/// The cookies Chrome holds in `session`, whichever page is open, for the
/// hosts `keep` admits (given without a leading dot).
pub async fn held(session: &Session, keep: impl Fn(&str) -> bool) -> Vec<Cookie> {
    session
        .page
        .execute(GetCookiesParams::default())
        .await
        .map(|r| r.cookies.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|c| keep(c.domain.trim_start_matches('.')))
        .collect()
}

/// The session in the platform's profile: its cookies for the hosts `keep`
/// admits, read under CDP once `signed_in` has found the platform honouring
/// the session in that same Chrome. A profile the platform does not honour,
/// and a profile with [`SIGN_IN`] set, gets a session from a person, in a
/// Chrome launched with nothing attached to it, and is read again once the
/// window closes.
pub async fn session(
    platform: &impl Platform,
    name: &str,
    url: &str,
    keep: impl Fn(&str) -> bool,
    signed_in: impl AsyncFn(&Session) -> bool,
) -> Vec<Cookie> {
    let profile = platform.profile().expect("an export names its profile");
    let read = || async {
        let session = Session::open(platform).await;
        let honoured = signed_in(&session).await;
        let cookies = held(&session, &keep).await;
        let _ = session.close().await;
        (honoured, cookies)
    };
    let renew = optional(SIGN_IN).is_some();
    let (mut honoured, mut cookies) = if renew {
        (false, Vec::new())
    } else {
        read().await
    };
    if !honoured {
        if !renew {
            eprintln!("{name} does not honour the session the profile holds.");
        }
        sign_in_without_automation(&profile, name, url);
        (honoured, cookies) = read().await;
    }
    assert!(
        honoured,
        "the profile carries no {name} sign-in {name} honours; sign in when the window opens, then close it"
    );
    cookies
}

/// Whether `session`, sent to `url`, comes to rest on `host` within
/// [`PROBE`], rather than on the sign-in page a platform redirects a lapsed
/// session to. A platform may also show a signed-out visitor a page on
/// `host`; [`carries`] tells the two apart.
pub async fn lands_on(session: &Session, url: &str, host: &str) -> bool {
    session.navigate(url).await;
    let started = std::time::Instant::now();
    while started.elapsed() < PROBE {
        let at = session.location().await;
        if url::Url::parse(&at)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .as_deref()
            == Some(host)
        {
            return true;
        }
        tokio::time::sleep(POLL).await;
    }
    false
}

/// Whether the page open in `session` carries `needle` in its markup within
/// [`PROBE`], ignoring case: an account's own address, which a platform's
/// account page names and its signed-out page cannot.
pub async fn carries(session: &Session, needle: &str) -> bool {
    let js = format!(
        "document.documentElement.innerHTML.toLowerCase().includes({})",
        serde_json::to_string(&needle.to_ascii_lowercase()).expect("a JSON string")
    );
    let started = std::time::Instant::now();
    while started.elapsed() < PROBE {
        if session.evaluate(&js).await == "true" {
            return true;
        }
        tokio::time::sleep(POLL).await;
    }
    false
}

/// A visible Chrome on `url`, with `profile` and nothing else: no debugging
/// port, no automation flag, so the sign-in a person completes in it is one
/// the platform accepts. Returns when the person closes the window.
fn sign_in_without_automation(profile: &Path, name: &str, url: &str) {
    // A lock a killed Chrome left would refuse this one.
    for stale in ["SingletonLock", "SingletonSocket", "SingletonCookie"] {
        let _ = std::fs::remove_file(profile.join(stale));
    }
    let chrome = default_executable(DetectionOptions::default())
        .expect("Chrome; install one, or name it in CHROME");
    eprintln!("Sign in to the {name} test account in the window that opens, then close the window.");
    let status = std::process::Command::new(chrome)
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        // The stores the CDP Chrome reads this profile with.
        .arg("--password-store=basic")
        .arg("--use-mock-keychain")
        .arg(url)
        .status()
        .expect("Chrome starts");
    assert!(status.success(), "Chrome exited with {status}");
}
