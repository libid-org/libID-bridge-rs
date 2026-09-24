//! X's authorization, driven from a blank page to the redirect: a session
//! restored from saved cookies or signed in through X's own pages, then the
//! consent page. Chrome presents itself as a person's desktop Chrome.

use std::{
    ops::Range,
    time::{
        Duration,
        Instant,
    },
};

use chromiumoxide::{
    cdp::browser_protocol::input::{
        DispatchKeyEventParams,
        DispatchKeyEventType,
    },
    layout::Point,
    page::ScreenshotParams,
    Page,
};
use rand::Rng;

use super::{
    budget,
    cookies::{
        self,
        Stored,
    },
    headed,
    profile,
    within,
    Platform,
    Session,
    POLL,
};
use crate::env::{
    optional,
    required,
};

/// A cookie list exported from a browser, as the `X_TEST_ALICE_COOKIES`
/// value: base64 of the shape [`Account::from_env`] reads.
///
/// The input is what a browser or its extensions hand out -- a bare list, or
/// an object carrying one under `cookies` -- with the field names either
/// spelling uses. Only `x.com` is kept, and a list without the session cookie
/// is refused: it would restore nothing.
pub fn secret_from_export(export: &str) -> String {
    let cookies = cookies::parse(export.as_bytes(), x_host)
        .unwrap_or_else(|e| panic!("the export is a cookie list: {e}"));
    assert!(
        signed_in(&cookies),
        "the export carries no auth_token cookie for x.com, so it restores no session"
    );
    cookies::encoded(&cookies)
}

/// An X host, given without its leading dot.
fn x_host(host: &str) -> bool {
    host == "x.com" || host.ends_with(".x.com")
}

/// Whether the cookies carry a session X honours.
fn signed_in(cookies: &[Stored]) -> bool {
    cookies.iter().any(|c| c.name == "auth_token")
}

/// The two hosts a session's cookies are set for.
const HOSTS: [&str; 2] = ["x.com", "twitter.com"];

/// The text a signed-in X page shows.
const SIGNED_IN: [&str; 3] = ["Home", "Explore", "Notifications"];

/// The text X shows for a sign-in it refused.
const REFUSED: [&str; 4] = [
    "Could not log you in",
    "Something went wrong",
    "incorrect",
    "temporarily limited your login",
];

/// The username field, on X's landing page and in its sign-in dialog.
const USERNAME: &str =
    "input[name='username_or_email'], input[autocomplete='username'], input[name='username']";
const PASSWORD: &str = "input[name='password']";
/// The field X asks the e-mail address into on a sign-in it examines.
const CHALLENGE: &str = "input[data-testid='ocfEnterTextTextInput']";

/// The X test account: its credentials, the e-mail address X may ask for,
/// and the session cookies it was last exported with.
pub struct Account {
    username: String,
    password: String,
    email: Option<String>,
    cookies: Vec<Stored>,
}

impl Account {
    /// The account `prefix` names: `{prefix}_USERNAME` and `{prefix}_PASSWORD`
    /// are required; `{prefix}_EMAIL` and the saved session, `{prefix}_COOKIES`
    /// (base64 of the list an export prints) or `{prefix}_COOKIES_FILE` (the
    /// JSON it writes), are optional.
    pub fn from_env(prefix: &str) -> Account {
        Account {
            cookies: cookies::from_env(prefix, x_host).unwrap_or_default(),
            ..Account::for_export(prefix)
        }
    }

    /// The account's credentials alone, for an export that creates the
    /// session; the saved one stays unread.
    pub fn for_export(prefix: &str) -> Account {
        Account {
            username: required(&format!("{prefix}_USERNAME")),
            password: required(&format!("{prefix}_PASSWORD")),
            email: optional(&format!("{prefix}_EMAIL")),
            cookies: Vec::new(),
        }
    }

    /// The account's handle.
    pub fn username(&self) -> &str {
        &self.username
    }
}

/// X's authorization request, as the client builds it, and the account
/// that grants it.
pub struct Authorization<'a> {
    pub account: &'a Account,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub code_challenge: &'a str,
    /// The profile a person signed in to, for an export; the rung keeps none.
    pub profile: Option<std::path::PathBuf>,
}

impl Authorization<'_> {
    /// The URL to open.
    pub fn url(&self) -> String {
        url::Url::parse_with_params(
            "https://x.com/i/oauth2/authorize",
            [
                ("response_type", "code"),
                ("client_id", self.client_id),
                ("redirect_uri", self.redirect_uri),
                ("scope", "tweet.read users.read"),
                ("state", self.state),
                ("code_challenge", self.code_challenge),
                ("code_challenge_method", "S256"),
            ],
        )
        .expect("the authorization endpoint is a URL")
        .into()
    }

    /// The session of the export profile: every x.com cookie Chrome holds
    /// there. A profile with no session gets one from a person, in a Chrome
    /// launched with nothing attached to it, on X's own sign-in page; every
    /// later export reads the profile with nobody present, until the session
    /// lapses.
    pub async fn fresh_cookies(&self) -> Vec<Stored> {
        // X honours a session only where its home timeline opens on it; a
        // lapsed one lands on the sign-in page.
        let honoured = async |session: &Session| {
            profile::held(session, x_host)
                .await
                .iter()
                .any(|c| c.name == "auth_token")
                && {
                    session.navigate("https://x.com/home").await;
                    Self::signed_in_within(session, profile::PROBE).await
                }
        };
        profile::session(self, "X", "https://x.com/i/flow/login", x_host, honoured)
            .await
            .into_iter()
            .map(Stored::held)
            .collect()
    }

    /// Whether the page shows a signed-in X.
    async fn signed_in(session: &Session) -> bool {
        let text = session.body_text().await;
        SIGNED_IN.iter().all(|mark| text.contains(mark))
    }

    /// Wait up to `patience` for a signed-in X page.
    async fn signed_in_within(session: &Session, patience: Duration) -> bool {
        within(patience, POLL, async || Self::signed_in(session).await).await
    }

    /// Install the saved session on the blank page, each cookie on both
    /// hosts; authorization itself checks the session.
    async fn restored(&self, session: &Session) -> bool {
        if self.account.cookies.is_empty() {
            return false;
        }
        let on_both_hosts = HOSTS.iter().flat_map(|host| {
            self.account.cookies.iter().map(|c| {
                Stored {
                    domain: c.domain.replace("x.com", host),
                    ..c.clone()
                }
                .param()
            })
        });
        cookies::restore(session, on_both_hosts).await;
        true
    }

    /// Sign in through X's own pages: a web search for X, its result in the
    /// tab X opens, the page's own sign-in link, the username, the password,
    /// the e-mail address if X asks, and Cloudflare's check if it runs.
    async fn sign_in(&self, session: &mut Session) {
        let mut jitter = <Jitter as rand::SeedableRng>::from_os_rng();
        let known = session.tabs().await;
        let _ = tokio::time::timeout(
            Duration::from_secs(15),
            session
                .page
                .goto("https://www.bing.com/search?q=twitter+login"),
        )
        .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        if session.evaluate(BING_CONSENT).await == "accepted" {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let clicked = session.evaluate(BING_RESULT).await;
        assert_ne!(clicked, "not_found", "the search lists x.com");

        if let Some(opened) = session.tab_opened(&known, Duration::from_secs(8)).await {
            session.adopt(opened, self).await;
        }
        within(
            Duration::from_secs(15),
            Duration::from_secs(1),
            async || session.evaluate("document.readyState").await == "complete",
        )
        .await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        session.evaluate(X_CONSENT).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        session.trace("x-landing").await;
        if session.location().await.contains("/home") {
            return;
        }

        if !present(session, USERNAME, Duration::from_secs(2)).await {
            session.evaluate(SIGN_IN_LINK).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
            session.trace("after-sign-in-link").await;
            if session.location().await.contains("/home") {
                return;
            }
        }

        if present(session, USERNAME, Duration::from_secs(10)).await {
            for _ in 0..3 {
                let (x, y) = (
                    200.0 + jitter.random::<f64>() * 600.0,
                    150.0 + jitter.random::<f64>() * 400.0,
                );
                move_mouse(&session.page, x, y, &mut jitter).await;
                pause(&mut jitter, 200..600).await;
            }
            session
                .evaluate("window.scrollBy(0, 50 + Math.random() * 100)")
                .await;
            pause(&mut jitter, 300..700).await;
            session.evaluate("window.scrollBy(0, -50)").await;
            pause(&mut jitter, 200..500).await;
            move_to(session, USERNAME, &mut jitter).await;
            pause(&mut jitter, 200..500).await;
            type_like_a_person(session, USERNAME, &self.account.username, &mut jitter)
                .await;
            pause(&mut jitter, 500..1000).await;
            session.trace("username-typed").await;
            if session.evaluate(NEXT_BUTTON).await == "not_found" {
                press(&session.page, "Tab").await;
                tokio::time::sleep(Duration::from_millis(300)).await;
                press(&session.page, "Enter").await;
            }
            tokio::time::sleep(Duration::from_secs(8)).await;
        }
        session.trace("after-username").await;
        self.refusal_check(session).await;

        if present(session, CHALLENGE, Duration::from_secs(3)).await {
            match self.account.email.as_deref() {
                Some(email) => {
                    type_like_a_person(session, CHALLENGE, email, &mut jitter).await;
                    pause(&mut jitter, 300..600).await;
                    press(&session.page, "Enter").await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    session.trace("after-challenge").await;
                }
                None => assert!(
                    headed(),
                    "X asked for the account's e-mail address: set X_TEST_ALICE_EMAIL"
                ),
            }
        }
        if Self::signed_in(session).await {
            return;
        }

        // In a visible Chrome a person may be completing a step X added.
        let patience = if headed() {
            budget()
        } else {
            Duration::from_secs(10)
        };
        assert!(
            present(session, PASSWORD, patience).await,
            "X shows the password field. {}",
            session.diagnosis().await
        );
        move_to(session, PASSWORD, &mut jitter).await;
        pause(&mut jitter, 200..400).await;
        type_like_a_person(session, PASSWORD, &self.account.password, &mut jitter).await;
        pause(&mut jitter, 400..800).await;
        session.trace("password-typed").await;
        click_by_text(session, &["Log in", "Continue"]).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        session.trace("after-log-in").await;
        self.refusal_check(session).await;

        within(
            Duration::from_secs(30),
            Duration::from_secs(2),
            async || !session.location().await.contains("/account/access"),
        )
        .await;
        let patience = if headed() {
            budget()
        } else {
            Duration::from_secs(20)
        };
        let signed_in = Self::signed_in_within(session, patience).await;
        session.trace("signed-in").await;
        assert!(
            signed_in,
            "X shows the signed-in page after the password. {}",
            session.diagnosis().await
        );
    }

    /// A refusal on the page stops the run, with the page's text; in a
    /// visible Chrome it is printed, and the person at the keyboard goes on.
    async fn refusal_check(&self, session: &Session) {
        let text = session.body_text().await;
        if !REFUSED.iter().any(|mark| text.contains(mark)) {
            return;
        }
        let refusal = format!(
            "X refused the sign-in. On: {}\nPage: {}",
            session.location().await,
            text.chars().take(400).collect::<String>()
        );
        assert!(headed(), "{refusal}");
        eprintln!("{refusal}");
    }
}

impl Platform for Authorization<'_> {
    fn profile(&self) -> Option<std::path::PathBuf> {
        self.profile.clone()
    }

    fn presented_as_person(&self) -> bool {
        true
    }

    fn state(&self) -> &str {
        self.state
    }

    /// Restore cookies and navigate directly to OAuth, without visiting home.
    /// Observe security challenges separately from an explicit login request.
    async fn authorize(&self, session: &mut Session) -> String {
        let started = Instant::now();
        if !self.restored(session).await {
            // X examines a fresh sign-in, and a run nobody is watching has no
            // answer for what it asks. The saved session is the way in.
            assert!(
                headed(),
                "no saved X session supplied: set X_TEST_ALICE_COOKIES or \
                 X_TEST_ALICE_COOKIES_FILE from an export, `cargo test \
                 --test ceremony -- --ignored --nocapture a_fresh_x_session` \
                 in ceremony-tests/"
            );
            self.sign_in(session).await;
        }
        let mut redirect = session.watch_redirect(self.redirect_uri).await;
        session.navigate(&self.url()).await;
        let mut consented: Option<Instant> = None;
        let mut signed_in_again = false;
        let mut last_path = String::new();
        let mut challenged: Option<Instant> = None;

        while started.elapsed() < budget() {
            if let Some(url) = redirect.seen() {
                if consented.is_none() {
                    eprintln!(
                        "X redirected without asking for consent: the app is \
                         already authorized for this account"
                    );
                }
                return url;
            }
            let url = session.location().await;
            if url.starts_with(self.redirect_uri) {
                return url;
            }
            let path = url::Url::parse(&url)
                .map(|u| u.path().to_owned())
                .unwrap_or_default();
            if path != last_path {
                session.trace("authorize").await;
                last_path = path.clone();
            }

            let text = session.body_text().await;
            if security_challenge(&text) {
                if challenged.is_none() {
                    eprintln!("X security verification appeared; allowing 90 seconds to complete");
                }
                let since = challenged.get_or_insert_with(Instant::now);
                if since.elapsed() >= Duration::from_secs(90) {
                    challenge_diagnostics(session).await;
                    panic!("X security verification did not clear within 90 seconds; cookie validity is unknown");
                }
                tokio::time::sleep(POLL).await;
                continue;
            }
            if challenged.take().is_some() {
                eprintln!("X security verification cleared");
            }

            if path.starts_with("/i/oauth2/authorize") {
                if consented.is_none() {
                    eprintln!(
                        "X asked for consent {:?} after the authorization page \
                         was opened",
                        started.elapsed()
                    );
                }
                session.evaluate(X_CONSENT).await;
                if consented.is_none_or(|at| at.elapsed() > Duration::from_secs(10))
                    && session.evaluate(CONSENT_CLICK).await == "ready"
                {
                    if let Ok(button) =
                        session.page.find_element("[data-libid-consent='1']").await
                    {
                        if button.click().await.is_ok() {
                            eprintln!("X consent clicked through browser input");
                            consented = Some(Instant::now());
                        }
                    }
                }
            } else if path.starts_with("/i/flow/login") || path == "/login" {
                assert!(headed(), "X requested login after cookie restoration; renew the saved session interactively");
                assert!(
                    !signed_in_again,
                    "X asked to sign in twice. Page: {}",
                    session.excerpt().await
                );
                self.sign_in(session).await;
                signed_in_again = true;
                consented = None;
                redirect = session.watch_redirect(self.redirect_uri).await;
                session.navigate(&self.url()).await;
            } else if !path.starts_with("/account/access") {
                let text = session.body_text().await;
                assert!(
                    !text.contains("Something went wrong"),
                    "X answered an error on the authorization path"
                );
            }
            tokio::time::sleep(POLL).await;
        }

        panic!(
            "X authorization did not finish within {:?}; last path: {last_path}",
            budget()
        );
    }
}

/// Provider security checks are not evidence that the saved session expired.
fn security_challenge(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "performing security verification",
        "verify you are human",
        "verifies you are not a bot",
        "checking your browser",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

/// Only structural diagnostics enter logs: no URL query, cookies, or page text.
/// An optional screenshot is captured only while the challenge is visible.
async fn challenge_diagnostics(session: &Session) {
    let summary = session.evaluate(r#"JSON.stringify({
        challengeFrame: !!document.querySelector('iframe[src*="challenges.cloudflare.com"]'),
        checkbox: !!document.querySelector('input[type="checkbox"],[role="checkbox"]'),
        passwordField: !!document.querySelector('input[type="password"]'),
        consentControl: !!document.querySelector('[data-libid-consent]'),
        readyState: document.readyState
    })"#).await;
    eprintln!("X challenge diagnostics: {summary}");
    if let Some(dir) = crate::env::optional("X_CHALLENGE_TRACE") {
        let _ = std::fs::create_dir_all(&dir);
        let _ = session
            .page
            .save_screenshot(
                ScreenshotParams::builder().build(),
                std::path::Path::new(&dir).join("x-challenge.png"),
            )
            .await;
    }
}

/// Bing's cookie banner accepted, if it is shown.
const BING_CONSENT: &str = r#"(() => {
    const button = document.querySelector('#bnp_btn_accept')
        || [...document.querySelectorAll('button')].find(b => /accept|agree/i.test(b.textContent));
    if (button) { button.click(); return 'accepted'; }
    return 'no_banner';
})()"#;

/// The first result on x.com or twitter.com clicked, else the first result.
const BING_RESULT: &str = r#"(() => {
    const cites = [...document.querySelectorAll('#b_results .b_algo cite, #b_results .b_algo .b_attribution')];
    for (const cite of cites) {
        if (/twitter\.com|x\.com/i.test(cite.textContent)) {
            const a = cite.closest('.b_algo')?.querySelector('h2 a, h3 a');
            if (a) { a.click(); return 'cite'; }
        }
    }
    const first = document.querySelector('#b_results .b_algo h2 a, #b_results .b_algo h3 a');
    if (first) { first.click(); return 'first:' + first.textContent.trim(); }
    return 'not_found';
})()"#;

/// X's cookie banner accepted, if it is shown.
const X_CONSENT: &str = r#"(() => {
    const span = [...document.querySelectorAll('span')].find(s => s.textContent.includes('Accept all cookies'));
    const button = span && span.closest('button,[role=button],div[role=button]');
    if (button) { button.click(); return 'accepted'; }
    return 'no_banner';
})()"#;

/// The page's own sign-in link clicked.
const SIGN_IN_LINK: &str = r#"(() => {
    const links = [...document.querySelectorAll('a[href="/login"], a[href="/i/flow/login"]')];
    if (links.length) { links[0].click(); return 'link'; }
    const buttons = [...document.querySelectorAll('button, [role="button"], a')];
    const button = buttons.find(b => /^(sign in|log in)$/i.test(b.textContent.trim()));
    if (button) { button.click(); return 'button:' + button.textContent.trim(); }
    return 'not_found';
})()"#;

/// The button that submits the username step clicked: "Next" in the
/// sign-in dialog, "Continue" on the landing page.
const NEXT_BUTTON: &str = r#"(() => {
    const buttons = [...document.querySelectorAll('button, [role="button"]')];
    const next = buttons.find(b => /^(next|continue)$/i.test(b.textContent.trim()));
    if (next) { next.click(); return 'clicked'; }
    return 'not_found';
})()"#;

/// Mark the visible, enabled consent control for a browser input click.
/// X also serves a consent page without `OAuth_Consent_Button`.
const CONSENT_CLICK: &str = r#"(() => {
    document.querySelectorAll('[data-libid-consent]').forEach(e => e.removeAttribute('data-libid-consent'));
    const candidates = [...document.querySelectorAll("[data-testid='OAuth_Consent_Button'],button,[role=button],input[type=submit],a")];
    const button = candidates.find(e =>
        (e.getAttribute('data-testid') === 'OAuth_Consent_Button' ||
         /^(authorize app)$/i.test((e.innerText || e.value || '').trim())) &&
        !e.disabled && e.getAttribute('aria-disabled') !== 'true' &&
        e.getClientRects().length > 0);
    if (button) {
        button.setAttribute('data-libid-consent', '1');
        return 'ready';
    }
    const controls = [...document.querySelectorAll('button,[role=button],input[type=submit],a')]
        .map(e => `${e.tagName}|${e.getAttribute('data-testid') || ''}|${(e.innerText||e.value||'').trim().slice(0,40)}`)
        .filter(d => d.length > 4);
    return 'absent: ' + controls.join(' ;; ').slice(0, 600);
})()"#;

/// Whether `selector` appears on the page within `patience`.
async fn present(session: &Session, selector: &str, patience: Duration) -> bool {
    within(patience, Duration::from_millis(250), async || {
        session.page.find_element(selector).await.is_ok()
    })
    .await
}

/// A trusted click on the first button whose text is one of `texts`: the
/// element is marked from the page, found by the mark, and clicked through
/// CDP input.
async fn click_by_text(session: &Session, texts: &[&str]) {
    let wanted = serde_json::to_string(texts).expect("a list of strings");
    session
        .evaluate(&format!(
            "[...document.querySelectorAll('button,[role=button]')].find(b => {wanted}.includes(b.innerText.trim()))?.setAttribute('data-libid-click', '1')"
        ))
        .await;
    session.click("[data-libid-click='1']").await;
    session
        .evaluate("document.querySelector(\"[data-libid-click='1']\")?.removeAttribute('data-libid-click')")
        .await;
}

/// The mouse moved to `(x, y)` in a few steps.
async fn move_mouse(page: &Page, to_x: f64, to_y: f64, jitter: &mut Jitter) {
    let (mut x, mut y) = (to_x * 0.3, to_y * 0.3);
    for i in 1..=5 {
        let t = f64::from(i) / 5.0;
        x += (to_x - x) * t + (jitter.random::<f64>() - 0.5) * 8.0;
        y += (to_y - y) * t + (jitter.random::<f64>() - 0.5) * 8.0;
        let _ = page.move_mouse(Point { x, y }).await;
        pause(jitter, 25..60).await;
    }
}

/// The mouse moved onto the element `selector` names, or to the middle of
/// the window when the page has no such element.
async fn move_to(session: &Session, selector: &str, jitter: &mut Jitter) {
    let at = match session.page.find_element(selector).await {
        Ok(element) => element.clickable_point().await.ok(),
        Err(_) => Some(Point { x: 720.0, y: 450.0 }),
    };
    if let Some(Point { x, y }) = at {
        move_mouse(&session.page, x, y, jitter).await;
    }
}

/// A pause of a length drawn from `millis`.
async fn pause(jitter: &mut Jitter, millis: Range<u64>) {
    tokio::time::sleep(Duration::from_millis(jitter.random_range(millis))).await;
}

/// `text` typed into the element `selector` names, one key at a time with
/// 60 to 180 milliseconds between keys.
async fn type_like_a_person(
    session: &Session,
    selector: &str,
    text: &str,
    jitter: &mut Jitter,
) {
    if let Ok(element) = session.page.find_element(selector).await {
        let _ = element.click().await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    for ch in text.chars() {
        let key = ch.to_string();
        let events = [
            DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::RawKeyDown)
                .key(key.clone())
                .build(),
            DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::Char)
                .text(key.clone())
                .build(),
            DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::KeyUp)
                .key(key.clone())
                .build(),
        ];
        for event in events {
            let _ = session.page.execute(event.expect("a key event")).await;
        }
        tokio::time::sleep(Duration::from_millis(jitter.random_range(60..180))).await;
    }
}

/// One named key pressed and released.
async fn press(page: &Page, key: &str) {
    let (code, text, key_code) = match key {
        "Enter" => ("Enter", Some("\r"), 13),
        "Tab" => ("Tab", None, 9),
        other => (other, None, 0),
    };
    let mut down = DispatchKeyEventParams::builder()
        .r#type(if text.is_some() {
            DispatchKeyEventType::KeyDown
        } else {
            DispatchKeyEventType::RawKeyDown
        })
        .key(key)
        .code(code)
        .windows_virtual_key_code(key_code)
        .native_virtual_key_code(key_code);
    if let Some(text) = text {
        down = down.text(text);
    }
    let _ = page.execute(down.build().expect("a key event")).await;
    let _ = page
        .execute(
            DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::KeyUp)
                .key(key)
                .code(code)
                .windows_virtual_key_code(key_code)
                .native_virtual_key_code(key_code)
                .build()
                .expect("a key event"),
        )
        .await;
}

/// The source of the small variations in timing and pointer paths.
type Jitter = rand::rngs::StdRng;

#[cfg(test)]
mod challenge_tests {
    use super::security_challenge;

    #[test]
    fn security_checks_are_distinct_from_login_and_consent() {
        assert!(security_challenge("x.com Performing security verification"));
        assert!(security_challenge("Verify you are human"));
        assert!(!security_challenge("Log in to X Password Forgot password?"));
        assert!(!security_challenge(
            "App wants to access your account Cancel Authorize app"
        ));
    }
}
