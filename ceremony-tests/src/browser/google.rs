//! Google browser authorization only: saved session to a direct ID-token fragment.
//! Optional one-attempt sign-in; no access token, token exchange, or notary.

use super::{
    budget,
    cookies::{
        self,
        Stored,
    },
    headed,
    person,
    profile,
    Platform,
    Session,
    POLL,
};
use crate::env::{
    optional,
    required,
};
use chromiumoxide::{
    browser::BrowserConfigBuilder,
    cdp::browser_protocol::network::{
        Cookie as Held,
        EventRequestWillBeSent,
    },
    Page,
};
use futures_util::StreamExt;
use std::{
    path::PathBuf,
    time::{
        Duration,
        Instant,
    },
};

pub struct Authorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub email: String,
    password: Option<String>,
    cookies: Vec<Stored>,
    /// The profile a person signed in to, for an export; the rung keeps none.
    profile: Option<PathBuf>,
}

impl Authorization {
    pub fn from_env(state: String, nonce: String) -> Self {
        let cookies = cookies::from_env("GOOGLE_TEST_ALICE", google_host).expect(
            "GOOGLE_TEST_ALICE_COOKIES (base64 JSON) or GOOGLE_TEST_ALICE_COOKIES_FILE",
        );
        assert!(
            cookies.iter().any(|c| c.name == "SID"
                || c.name == "__Secure-1PSID"
                || c.name == "__Secure-3PSID"),
            "the Google cookie export carries no session cookie"
        );
        Self {
            client_id: required("GOOGLE_OAUTH_CLIENT_ID"),
            redirect_uri: required("LIBID_TEST_GOOGLE_REDIRECT_URI"),
            state,
            nonce,
            email: required("GOOGLE_TEST_ALICE_EMAIL"),
            password: optional("GOOGLE_TEST_ALICE_PASSWORD"),
            cookies,
            profile: None,
        }
    }

    /// The client settings alone, for a session a person is about to create.
    pub fn for_export(state: String, nonce: String) -> Self {
        Self {
            client_id: required("GOOGLE_OAUTH_CLIENT_ID"),
            redirect_uri: required("LIBID_TEST_GOOGLE_REDIRECT_URI"),
            state,
            nonce,
            email: required("GOOGLE_TEST_ALICE_EMAIL"),
            password: None,
            cookies: Vec::new(),
            profile: Some(profile::named("GOOGLE_PROFILE", ".env.google-profile")),
        }
    }

    /// The session of the export profile: every Google cookie Chrome holds
    /// there, the `accounts.google.com` ones included. A profile with no
    /// session gets one from a person, in a Chrome launched with nothing
    /// attached to it -- Google refuses a sign-in in any browser under
    /// automation, but only the sign-in; a session made elsewhere is read
    /// here without objection, and read again on every later export until
    /// it lapses.
    async fn fresh_cookies(&self) -> Vec<Stored> {
        // Google honours a session only where its account page opens on it
        // for this account; a lapsed one is sent to the sign-in page, or
        // shown the signed-out page on the same host, which names no account.
        let honoured = async |session: &Session| {
            signed_in(&profile::held(session, google_host).await)
                && profile::lands_on(
                    session,
                    "https://myaccount.google.com/",
                    "myaccount.google.com",
                )
                .await
                && profile::carries(session, &self.email).await
        };
        profile::session(self, "Google", &self.url(), google_host, honoured)
            .await
            .into_iter()
            .map(Stored::held)
            .collect()
    }

    pub fn url(&self) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "id_token")
            .append_pair("response_mode", "fragment")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", "openid email")
            .append_pair("state", &self.state)
            .append_pair("nonce", &self.nonce)
            .finish();
        format!("https://accounts.google.com/o/oauth2/v2/auth?{query}")
    }
}

impl Platform for Authorization {
    fn profile(&self) -> Option<PathBuf> {
        self.profile.clone()
    }

    /// Google refuses a browser it can tell is automated before it looks at
    /// the session, so this one presents itself as a person's.
    fn configure(&self, config: BrowserConfigBuilder) -> BrowserConfigBuilder {
        person::configure(config)
    }

    async fn prepare(&self, page: &Page) {
        person::prepare(page).await
    }

    fn state(&self) -> &str {
        &self.state
    }

    async fn authorize(&self, session: &mut Session) -> String {
        cookies::restore(session, self.cookies.iter().map(Stored::param)).await;
        let held = google_cookies(session).await;
        eprintln!(
            "Google session restored: Chrome holds {} cookies: {}",
            held.len(),
            held.iter()
                .map(|c| format!("{}@{}", c.name, c.domain))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let refused: Vec<_> = self
            .cookies
            .iter()
            .filter(|set| !held.iter().any(|c| c.same_slot(set)))
            .map(|c| format!("{}@{}{}", c.name, c.domain, c.path))
            .collect();
        assert!(
            refused.is_empty(),
            "Chrome holds every cookie the export set; it refused {}",
            refused.join(" ")
        );
        // A fragment is absent from HTTP, but CDP supplies it separately.
        let mut redirect = watch_fragment(session, &self.redirect_uri).await;
        session.navigate(&self.url()).await;
        let started = Instant::now();
        let mut last_click = Instant::now() - Duration::from_secs(3);
        let mut email_submitted = false;
        let mut password_submitted = false;
        while started.elapsed() < budget() {
            if let Some(url) = redirect.seen() {
                // Drop the bearer-bearing location before any diagnostics.
                session.navigate("about:blank").await;
                return url;
            }
            let location = url::Url::parse(&session.location().await).ok();
            if location.as_ref().and_then(|u| u.host_str()) == Some("accounts.google.com")
            {
                let text = session.body_text().await.to_ascii_lowercase();
                assert!(
                    headed() || !text.contains("this browser or app may not be secure"),
                    "Google refused this browser; interactive authorization is required; controls: {}",
                    controls(session).await
                );
                assert!(
                    headed()
                        || (!text.contains("verify it's you")
                            && !text.contains("verify you’re human")),
                    "Google requires interactive account verification; controls: {}",
                    controls(session).await
                );
                let login_visible = session.evaluate(
                    "[...document.querySelectorAll('input[type=password],input[type=email],input[name=identifier]')].some(e => e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden') ? 'visible' : 'absent'",
                ).await;
                if login_visible == "visible" {
                    if headed() {
                        tokio::time::sleep(POLL).await;
                        continue;
                    }
                    let password = self.password.as_deref().expect(
                        "Google requested a fresh login; renew the saved session interactively or set GOOGLE_TEST_ALICE_PASSWORD",
                    );
                    let step = session.evaluate(
                        "[...document.querySelectorAll('input[type=password]')].some(e => e.getClientRects().length) ? 'password' : 'email'",
                    ).await;
                    if step == "email" && !email_submitted {
                        session.fill("input[name=identifier]", &self.email).await;
                        if let Ok(button) =
                            session.page.find_element("#identifierNext").await
                        {
                            email_submitted = button.click().await.is_ok();
                        }
                    } else if step == "password" && !password_submitted {
                        session.fill("input[type=password]", password).await;
                        if let Ok(button) =
                            session.page.find_element("#passwordNext").await
                        {
                            password_submitted = button.click().await.is_ok();
                        }
                    }
                    tokio::time::sleep(POLL).await;
                    continue;
                }
                assert!(
                    !text.contains("redirect_uri_mismatch"),
                    "Google rejected the redirect URI; register LIBID_TEST_GOOGLE_REDIRECT_URI exactly in the OAuth client"
                );
                for marker in [
                    "access blocked",
                    "has not completed the google verification process",
                    "invalid_client",
                    "unauthorized_client",
                    "unsupported_response_type",
                ] {
                    assert!(
                        !text.contains(marker),
                        "Google authorization configuration error: {marker}"
                    );
                }
                if last_click.elapsed() >= Duration::from_secs(3) {
                    let email = serde_json::to_string(&self.email).expect("email JSON");
                    let mark = format!(
                        r#"(() => {{
                        document.querySelectorAll('[data-libid-google]').forEach(e => e.removeAttribute('data-libid-google'));
                        const usable = e => !e.disabled && e.getAttribute('aria-disabled') !== 'true' && e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden';
                        const account = [...document.querySelectorAll('[data-identifier]')].find(e => usable(e) && e.getAttribute('data-identifier').toLowerCase() === {email}.toLowerCase());
                        const consent = [...document.querySelectorAll('button,[role=button],input[type=submit]')].find(e => usable(e) && /^(continue|allow)$/i.test((e.innerText || e.value || '').trim()));
                        const e = account || consent;
                        if (!e || e.disabled || e.getAttribute('aria-disabled') === 'true' || !e.getClientRects().length) return 'absent';
                        e.setAttribute('data-libid-google','1'); return 'ready';
                    }})()"#
                    );
                    if session.evaluate(&mark).await == "ready" {
                        if let Ok(button) =
                            session.page.find_element("[data-libid-google='1']").await
                        {
                            if button.click().await.is_ok() {
                                last_click = Instant::now();
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(POLL).await;
        }
        panic!(
            "Google authorization timed out; controls: {}",
            controls(session).await
        );
    }
}

/// Which of Google's controls the page shows, so a failure names its layer:
/// `login` is a session problem, `accountChooser` or `consent` a driving one.
async fn controls(session: &Session) -> String {
    session
        .evaluate(
            r#"JSON.stringify({
                accountChooser: !!document.querySelector('[data-identifier]'),
                consent: [...document.querySelectorAll('button,[role=button],input[type=submit]')].some(e => /^(continue|allow)$/i.test((e.innerText || e.value || '').trim()) && e.getClientRects().length),
                login: [...document.querySelectorAll('input[type=password],input[type=email],input[name=identifier]')].some(e => e.getClientRects().length),
                uncheckedConsent: [...document.querySelectorAll('input[type=checkbox],[role=checkbox]')].some(e => e.getClientRects().length && !(e.checked || e.getAttribute('aria-checked') === 'true')),
            })"#,
        )
        .await
}

/// Whether the cookies carry a sign-in `accounts.google.com` honours.
fn signed_in(cookies: &[Held]) -> bool {
    cookies.iter().any(|c| {
        c.domain.ends_with("accounts.google.com")
            && (c.name == "LSID" || c.name == "__Host-1PLSID")
    })
}

/// Every Google cookie Chrome holds, whichever page is open.
async fn google_cookies(session: &Session) -> Vec<Stored> {
    profile::held(session, google_host)
        .await
        .into_iter()
        .map(Stored::held)
        .collect()
}

/// A Google host, given without its leading dot.
fn google_host(host: &str) -> bool {
    host == "google.com" || host.ends_with(".google.com")
}

/// Exact redirect matching, unlike prefix matching, rejects sibling paths.
pub async fn watch_fragment(session: &Session, uri: &str) -> super::Redirect {
    let expected = url::Url::parse(uri).expect("registered redirect URI");
    assert!(
        expected.query().is_none() && expected.fragment().is_none(),
        "redirect URI must have no query or fragment"
    );
    let mut events = session
        .page
        .event_listener::<EventRequestWillBeSent>()
        .await
        .expect("redirect events");
    let (tx, found) = tokio::sync::oneshot::channel();
    let watching = tokio::spawn(async move {
        while let Some(event) = events.next().await {
            if url::Url::parse(&event.request.url).ok().as_ref() == Some(&expected) {
                let fragment = event.request.url_fragment.as_deref().unwrap_or_default();
                let _ = tx.send(format!("{}{fragment}", event.request.url));
                return;
            }
        }
    });
    super::Redirect { found, watching }
}

/// Export the session of `GOOGLE_PROFILE` (`.env.google-profile`): a profile
/// with no sign-in opens a Chrome for a person to sign in once; after that the
/// export needs nobody. Written as JSON to `GOOGLE_COOKIE_EXPORT_OUT` when that
/// names a path, so the value never crosses a terminal, or printed as the
/// `GOOGLE_TEST_ALICE_COOKIES` value otherwise.
pub async fn export_fresh_session() {
    let authorization = Authorization::for_export("export".into(), "export".into());
    let cookies = authorization.fresh_cookies().await;
    cookies::deliver(
        &cookies,
        "GOOGLE_COOKIE_EXPORT_OUT",
        "GOOGLE_TEST_ALICE_COOKIES",
    );
}

/// Chrome reports the fragment of a redirect it lands on, through the request
/// event, against a local fixture: no account, no external network.
pub async fn chrome_preserves_the_redirect_fragment() {
    use axum::{
        response::Redirect,
        routing::get,
        Router,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let target = format!("{origin}/auth/callback#state=s&id_token=fixture");
    let landing = target.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/start",
                    get(move || async move { Redirect::temporary(&landing) }),
                )
                .route("/auth/callback", get(|| async { "callback" })),
        )
        .await
        .unwrap();
    });
    let a = Authorization {
        client_id: String::new(),
        redirect_uri: format!("{origin}/auth/callback"),
        state: "s".into(),
        nonce: String::new(),
        email: String::new(),
        password: None,
        cookies: vec![],
        profile: None,
    };
    let session = Session::open(&a).await;
    let mut redirect = watch_fragment(&session, &a.redirect_uri).await;
    session.navigate(&format!("{origin}/start")).await;
    let observed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(url) = redirect.seen() {
                break url;
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("Chrome reports the fragment");
    let _ = session.close().await;
    server.abort();
    assert_eq!(observed, target);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_requests_only_direct_identity_evidence() {
        let a = Authorization {
            client_id: "client".into(),
            redirect_uri: "http://localhost/auth/callback".into(),
            state: "state".into(),
            nonce: "nonce".into(),
            email: "a@example.com".into(),
            password: None,
            cookies: vec![],
            profile: None,
        };
        assert_eq!(a.url(), "https://accounts.google.com/o/oauth2/v2/auth?response_type=id_token&response_mode=fragment&client_id=client&redirect_uri=http%3A%2F%2Flocalhost%2Fauth%2Fcallback&scope=openid+email&state=state&nonce=nonce");
    }
}
