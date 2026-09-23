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
        network::{
            Headers,
            SetExtraHttpHeadersParams,
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
                architecture: "arm".to_owned(),
                model: String::new(),
                mobile: false,
                bitness: Some("64".to_owned()),
                wow64: Some(false),
            }),
        })
        .await;
    let _ = page
            .execute(SetExtraHttpHeadersParams::new(Headers::new(serde_json::json!({
                "sec-ch-ua": "\"Chromium\";v=\"145\", \"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"145\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"macOS\"",
            }))))
            .await;
    let _ = page
        .execute(AddScriptToEvaluateOnNewDocumentParams::new(STEALTH))
        .await;
}
