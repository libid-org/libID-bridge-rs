//! A person's desktop Chrome, as the platforms that fingerprint automation
//! see it: the flags, the user agent and its client hints, and the script
//! every new document runs first. X and Google present themselves this way;
//! GitHub does not need to.

use chromiumoxide::{
    browser::BrowserConfigBuilder,
    cdp::browser_protocol::{
        emulation::{
            SetAutomationOverrideParams,
            SetDeviceMetricsOverrideParams,
            SetUserAgentOverrideParams,
            UserAgentBrandVersion,
            UserAgentMetadata,
        },
        page::AddScriptToEvaluateOnNewDocumentParams,
    },
    Page,
};

/// The Chrome this driver presents itself as.
const USER_AGENT: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

/// Chrome's flags: what chromiumoxide adds by default less `--enable-automation`
/// and `--disable-extensions`, then the presentation.
const FLAGS: &[&str] = &[
    "--disable-background-networking",
    "--enable-features=NetworkService,NetworkServiceInProcess",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-breakpad",
    "--disable-client-side-phishing-detection",
    "--disable-component-extensions-with-background-pages",
    "--disable-default-apps",
    "--disable-features=TranslateUI,PasswordManager",
    "--disable-hang-monitor",
    "--disable-ipc-flooding-protection",
    "--disable-popup-blocking",
    "--disable-prompt-on-repost",
    "--disable-renderer-backgrounding",
    "--disable-save-password-bubble",
    "--disable-sync",
    "--force-color-profile=srgb",
    "--metrics-recording-only",
    "--no-default-browser-check",
    "--no-first-run",
    "--enable-blink-features=IdleDetection",
    "--disable-blink-features=AutomationControlled",
    // The cookie store: the two defaults `disable_default_args` drops. A
    // profile written under one store is unreadable under another, and Chrome
    // says nothing when it drops what it cannot read.
    "--password-store=basic",
    "--use-mock-keychain",
    "--window-size=1440,900",
    "--lang=en-US",
];

/// What every new document runs before the page's own scripts.
const STEALTH: &str = include_str!("stealth.js");

/// Chrome's launch configuration: chromiumoxide's defaults less
/// `--enable-automation` and `--disable-extensions`, then the presentation.
pub fn configure(config: BrowserConfigBuilder) -> BrowserConfigBuilder {
    let mut config = config
        .disable_default_args()
        .viewport(None)
        .arg(format!("--user-agent={USER_AGENT}"));
    for flag in FLAGS {
        config = config.arg(*flag);
    }
    config
}

/// The automation override off, the viewport at the window's size, the user
/// agent and its client hints, and the stealth script on every new document.
/// The metadata here is the one source of the client hints: Chrome reports it
/// through `navigator.userAgentData` and the `sec-ch-ua` headers alike.
pub async fn prepare(page: &Page) {
    let _ = page
        .execute(SetAutomationOverrideParams { enabled: false })
        .await;
    let _ = page
        .execute(SetDeviceMetricsOverrideParams::new(1440, 900, 1., false))
        .await;
    let brand = |brand: &str, version: &str| UserAgentBrandVersion {
        brand: brand.to_owned(),
        version: version.to_owned(),
    };
    let _ = page
        .execute(SetUserAgentOverrideParams {
            user_agent: USER_AGENT.to_owned(),
            accept_language: Some("en-US,en;q=0.9".to_owned()),
            platform: Some("macOS".to_owned()),
            user_agent_metadata: Some(UserAgentMetadata {
                brands: Some(vec![
                    brand("Chromium", "145"),
                    brand("Not:A-Brand", "99"),
                    brand("Google Chrome", "145"),
                ]),
                full_version_list: Some(vec![
                    brand("Chromium", "145.0.0.0"),
                    brand("Not:A-Brand", "99.0.0.0"),
                    brand("Google Chrome", "145.0.0.0"),
                ]),
                platform: "macOS".to_owned(),
                platform_version: "15.3.0".to_owned(),
                // An Intel Mac, as the user agent, `navigator.platform` and
                // the WebGL renderer in stealth.js all say.
                architecture: "x86".to_owned(),
                model: String::new(),
                mobile: false,
                bitness: Some("64".to_owned()),
                wow64: Some(false),
            }),
        })
        .await;
    let _ = page
        .execute(AddScriptToEvaluateOnNewDocumentParams::new(STEALTH))
        .await;
}

/// A Chrome presented as a person's, with nothing to authorize.
struct Presented;

impl super::Platform for Presented {
    fn configure(&self, config: BrowserConfigBuilder) -> BrowserConfigBuilder {
        configure(config)
    }

    async fn prepare(&self, page: &Page) {
        prepare(page).await
    }

    fn state(&self) -> &str {
        ""
    }

    async fn authorize(&self, _session: &mut super::Session) -> String {
        unreachable!("a presentation authorizes nothing")
    }
}

/// Chrome, presented as a person's, tells one story: the `sec-ch-ua` header
/// it sends names the brands `navigator.userAgentData` lists, in the same
/// order, and the architecture its high-entropy hints report is the Intel
/// the platform string and the WebGL renderer claim. Needs a Chrome and a
/// loopback socket, nothing else.
pub async fn chrome_tells_one_story() {
    use axum::{
        http::HeaderMap,
        routing::get,
        Router,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (sent, mut received) = tokio::sync::mpsc::unbounded_channel::<String>();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/",
                get(move |headers: HeaderMap| async move {
                    let header = headers
                        .get("sec-ch-ua")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default();
                    let _ = sent.send(header.to_owned());
                    axum::response::Html("<!doctype html><title>person</title>")
                }),
            ),
        )
        .await
        .unwrap();
    });

    let session = super::Session::open(&Presented).await;
    session.navigate(&format!("{origin}/")).await;
    let header =
        tokio::time::timeout(std::time::Duration::from_secs(10), received.recv())
            .await
            .expect("Chrome requests the page")
            .expect("the page's request headers");
    // The request arrives before the document it answers exists.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while session.evaluate("document.readyState").await != "complete" {
            tokio::time::sleep(super::POLL).await;
        }
    })
    .await
    .expect("the page loads");
    let listed: Vec<serde_json::Value> = serde_json::from_str(
        &session
            .evaluate("JSON.stringify(navigator.userAgentData.brands)")
            .await,
    )
    .expect("navigator.userAgentData lists its brands");
    let brands = listed
        .iter()
        .map(|b| format!("{};v={}", b["brand"], b["version"]))
        .collect::<Vec<_>>()
        .join(", ");
    let architecture = session
        .evaluate(
            "navigator.userAgentData.getHighEntropyValues(['architecture']).then(v => v.architecture)",
        )
        .await;
    let platform = session.evaluate("navigator.platform").await;
    let renderer = session
        .evaluate(
            "document.createElement('canvas').getContext('webgl')?.getParameter(37446) ?? ''",
        )
        .await;
    let _ = session.close().await;
    server.abort();

    assert_eq!(
        header, brands,
        "the header and the page list one set of brands"
    );
    assert!(brands.contains("\"Google Chrome\";v=\"145\""), "{brands}");
    assert_eq!(architecture, "x86");
    assert_eq!(platform, "MacIntel");
    assert!(
        renderer.is_empty() || renderer.contains("Intel"),
        "WebGL names an Intel GPU: {renderer}"
    );
}
