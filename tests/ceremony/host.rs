//! The deployment under test: the binary on a configuration file naming the
//! App's public client id and credential from the environment.

use libid_bridge_rs::routes::CONFIG_PATH;

use ceremony_tests::{
    env::{
        logging,
        required,
    },
    Deployment,
    Published,
};

use super::common::{
    bridge::{
        Bridge,
        Reply,
    },
    Distribution,
};

/// The application origin the bridge under test admits, and the one the
/// suite reads the configuration as.
pub const APP_ORIGIN: &str = "https://app.example";

/// The origin the OAuth App's callback URL is registered under: the bridge
/// origin as the application knows it, a canonical origin with no path.
pub fn public_origin() -> String {
    let origin = required("LIBID_TEST_PUBLIC_ORIGIN");
    let parsed = url::Url::parse(&origin).expect("LIBID_TEST_PUBLIC_ORIGIN parses");
    assert_eq!(
        parsed.origin().ascii_serialization(),
        origin,
        "LIBID_TEST_PUBLIC_ORIGIN is a canonical origin"
    );
    origin
}

/// The callback URL the OAuth App registers: the public origin followed by
/// `/auth/callback`, as the application derives it from the bridge origin.
pub fn redirect_uri() -> String {
    format!(
        "{}{}",
        public_origin(),
        libid_bridge_rs::routes::CALLBACK_PATH
    )
}

/// A running bridge.
pub struct Host {
    pub bridge: Bridge,
}

impl Host {
    /// The binary on a configuration naming the shared Distribution and the
    /// App, its client secret in the github table as the credential to
    /// publish.
    pub async fn attesting() -> Host {
        logging();
        let config = format!(
            "allowed_app_origins = [\"{APP_ORIGIN}\"]\n\
             ccdp_origin = \"{}\"\n\
             [[platforms]]\nid = \"github\"\nclient_id = \"{}\"\nversions = [1]\n\
             client_credential = \"{}\"\n",
            Distribution::shared().origin(),
            required("GH_OAUTH_CLIENT_ID"),
            required("GH_OAUTH_CLIENT_SECRET"),
        );
        let bridge = tokio::task::spawn_blocking(move || Bridge::started(&config))
            .await
            .expect("the bridge starts");
        Host { bridge }
    }

    /// The github entry of the configuration the bridge publishes, read over
    /// TCP from the admitted application origin: the client id and the
    /// credential the configuration named.
    pub async fn published(&self) -> Published {
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
        };
        assert_eq!(published.client_id, required("GH_OAUTH_CLIENT_ID"));
        assert_eq!(published.credential, required("GH_OAUTH_CLIENT_SECRET"));
        published
    }
}

impl Deployment for Host {
    fn redirect_uri(&self) -> String {
        redirect_uri()
    }

    async fn published(&self) -> Published {
        Host::published(self).await
    }
}
