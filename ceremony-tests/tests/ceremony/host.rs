//! The deployment under test: this repository's binary, built from its own
//! manifest, on a configuration file naming the testnet Distribution and the
//! App's public client id and credential from the settings.

#[path = "../../../tests/common/bridge.rs"]
// The host uses its part of the module.
#[allow(dead_code)]
mod bridge;

use std::{
    path::{
        Path,
        PathBuf,
    },
    process::{
        Command,
        Stdio,
    },
    sync::OnceLock,
};

use bridge::{
    Bridge,
    Reply,
};
use ceremony_tests::{
    env::logging,
    rungs::Published,
    settings::GitHubApp,
};
use libid_bridge_rs::routes::CONFIG_PATH;

/// The Distribution the bridge under test serves the callback document of:
/// libID's testnet one. The rungs read the configuration alone, which the
/// bridge answers whether or not a retrieval has succeeded.
const CCDP_ORIGIN: &str = "https://testnet.ccdp.lib.id";

/// The binary [`bridge`] starts: built once per run from the repository's
/// manifest, into the repository's own target directory, so the bridge under
/// test is always the checkout's.
pub fn binary() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
            let built = Command::new(env!("CARGO"))
                .args([
                    "build",
                    "--locked",
                    "--bin",
                    "libid-bridge-rs",
                    "--message-format=json-render-diagnostics",
                    "--manifest-path",
                ])
                .arg(root.join("Cargo.toml"))
                .arg("--target-dir")
                .arg(root.join("target"))
                .stderr(Stdio::inherit())
                .output()
                .expect("cargo runs");
            assert!(built.status.success(), "the bridge builds");
            String::from_utf8_lossy(&built.stdout)
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find_map(|message| message["executable"].as_str().map(PathBuf::from))
                .expect("cargo names the binary it built")
        })
        .clone()
}

/// The application origin the bridge under test admits, and the one the
/// suite reads the configuration as.
pub const APP_ORIGIN: &str = "https://app.example";

/// The callback URL the OAuth App registers: the public origin, a canonical
/// origin with no path, followed by `/auth/callback`, as the application
/// derives it from the bridge origin.
fn redirect_uri(app: &GitHubApp) -> String {
    let origin = &app.public_origin;
    let parsed = url::Url::parse(origin).expect("LIBID_TEST_PUBLIC_ORIGIN parses");
    assert_eq!(
        &parsed.origin().ascii_serialization(),
        origin,
        "LIBID_TEST_PUBLIC_ORIGIN is a canonical origin"
    );
    format!("{origin}{}", libid_bridge_rs::routes::CALLBACK_PATH)
}

/// A running bridge.
pub struct Host {
    pub bridge: Bridge,
}

impl Host {
    /// The binary on a configuration naming the testnet Distribution and the
    /// App, its client secret in the github table as the credential to
    /// publish.
    pub async fn attesting(app: &GitHubApp) -> Host {
        logging();
        let config = format!(
            "allowed_app_origins = [\"{APP_ORIGIN}\"]\n\
             ccdp_origin = \"{}\"\n\
             [[platforms]]\nid = \"github\"\nclient_id = \"{}\"\nversions = [1]\n\
             client_credential = \"{}\"\n",
            CCDP_ORIGIN, app.client_id, app.client_secret,
        );
        let bridge = tokio::task::spawn_blocking(move || Bridge::started(&config))
            .await
            .expect("the bridge starts");
        Host { bridge }
    }

    /// The github entry of the configuration the bridge publishes, read over
    /// TCP from the admitted application origin, checked to be the client id
    /// and the credential `app` configured, with the App's callback URL.
    pub async fn published(&self, app: &GitHubApp) -> Published {
        let address = self.bridge.address;
        let reply = tokio::task::spawn_blocking(move || {
            Reply::to(address, "GET", CONFIG_PATH, &[("origin", APP_ORIGIN)], "")
        })
        .await
        .expect("the configuration answers");
        assert_eq!(reply.status, 200, "{}", reply.body);
        let record: serde_json::Value =
            serde_json::from_str(&reply.body).expect("a JSON record");
        let github = &record["platforms"]["github"];
        let published = Published {
            client_id: github["clientId"].as_str().expect("a client id").to_owned(),
            credential: github["clientCredential"]
                .as_str()
                .expect("the public credential")
                .to_owned(),
            redirect_uri: redirect_uri(app),
        };
        assert_eq!(published.client_id, app.client_id);
        assert_eq!(published.credential, app.client_secret);
        published
    }
}
