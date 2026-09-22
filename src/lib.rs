//! The OAuth Bridge of a libID ceremony. The contract is `specs/oauth-bridge.md`
//! in the libid repository.
//!
//! It publishes the configuration an application starts from and serves the
//! one callback document the OAuth platforms redirect back to. `/health` is a
//! liveness probe for the container healthcheck and `/metrics` is what this
//! deployment counts.
//!
//! The callback document is the CCDP Distribution's artifact with this
//! deployment's data inserted into its one slot; everything the browser runs
//! after the callback is served by that Distribution. This service performs
//! no token exchange, opens no notary connection, verifies no proof, holds no
//! secret and no key of its own, keeps no ceremony state, and talks to no
//! chain.
//!
//! The Distribution is a separate deployment and this one starts without it.
//! The callback route says it has no document until a retrieval produces one,
//! and keeps serving the last one it has when a later retrieval does not.

#![warn(missing_docs)]

pub(crate) mod artifact;
pub mod config;
pub(crate) mod deployment;
pub mod error;
#[cfg(any(test, feature = "fixtures"))]
#[doc(hidden)]
pub mod fixtures;
pub mod metrics;
pub(crate) mod origin;
pub mod routes;
pub mod state;

use std::sync::Arc;

use error::Result;
use state::AppState;

/// A deployment that has started: the state its routes read, and the
/// refresher that keeps the callback document current.
pub struct Bridge {
    /// What the routes read.
    pub state: Arc<AppState>,
    /// What keeps the callback document current.
    pub(crate) refresher: artifact::upstream::Refresher,
}

impl Bridge {
    /// Check the deployment and build what the routes read. Everything that
    /// must be well-formed for a request to succeed is checked here, at
    /// startup; the error is the first thing that was not.
    ///
    /// No network request is made. The callback artifact is retrieved by the
    /// refresher, so a Distribution that is unreachable delays the callback
    /// document and stops nothing.
    pub fn start(cfg: &config::Config) -> Result<Bridge> {
        let deployment = deployment::Deployment::checked(cfg)?;
        let upstream = artifact::upstream::Upstream::new(&deployment.ccdp_origin);
        let (sender, callback) = tokio::sync::watch::channel(None);
        let (failed, failure) = tokio::sync::watch::channel(None);
        let metrics = Arc::new(metrics::Metrics::new());
        let state = Arc::new(AppState {
            callback,
            allowed_origins: deployment.allowed_origins.clone(),
            ceremony_config: deployment.ceremony_config(),
            failure,
            metrics: metrics.clone(),
        });
        let refresher = artifact::upstream::Refresher::new(
            upstream,
            deployment.allowed_origins,
            sender,
            failed,
            metrics,
        );
        Ok(Bridge { state, refresher })
    }
}

/// Serve `bridge` on `listener` until `shutdown` resolves; in-flight requests
/// finish first. The callback artifact is revalidated for as long as this
/// runs.
pub async fn serve(
    bridge: Bridge,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let app = routes::build_router(bridge.state);
    let refreshing =
        tokio::spawn(bridge.refresher.run(artifact::upstream::Schedule::DEPLOYED));
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await;
    refreshing.abort();
    served
}

#[cfg(test)]
mod tests {
    use super::{
        config::Config,
        fixtures::{
            self,
            Distribution,
        },
        *,
    };

    /// The state of a deployment started on the fixture configuration with
    /// `args`.
    async fn started(args: &[&str]) -> Arc<AppState> {
        Bridge::start(&Config::fixture(args)).unwrap().state
    }

    /// An omitted CCDP origin selects the canonical libID Distribution: the
    /// declared default is `https://lib.id`, and the configured value reaches
    /// the published record.
    #[tokio::test]
    async fn an_omitted_ccdp_origin_selects_the_canonical_distribution() {
        let command = <config::Config as clap::CommandFactory>::command();
        let arg = command
            .get_arguments()
            .find(|a| a.get_id() == "ccdp_origin")
            .expect("the ccdp origin is an argument");
        assert_eq!(arg.get_default_values(), ["https://lib.id"]);

        let state = started(&[]).await;
        let record: serde_json::Value =
            serde_json::from_slice(&state.ceremony_config).unwrap();
        assert_eq!(record["ccdpOrigin"], Distribution::shared().origin());
    }

    /// The effective set is `allowedAppOrigins ∪ {ccdpOrigin}`: the resolved
    /// origin joins once, and an origin already listed is not added twice.
    #[tokio::test]
    async fn the_effective_admission_set_is_the_allowlist_plus_the_ccdp_origin() {
        async fn origins(args: &[&str]) -> Vec<String> {
            let state = started(args).await;
            state
                .allowed_origins
                .iter()
                .map(|origin| origin.as_str().to_owned())
                .collect()
        }
        let ccdp = Distribution::shared().origin().to_owned();

        let joined = origins(&[]).await;
        assert_eq!(joined, ["https://app.example".to_owned(), ccdp.clone()]);
        assert!(!joined.iter().any(|o| o == "https://lib.id"));

        let listed = format!("https://app.example,{ccdp}");
        assert_eq!(
            origins(&["--allowed-app-origins", &listed]).await,
            ["https://app.example".to_owned(), ccdp]
        );
    }

    /// A refusal names the member the operator wrote, by its own index in
    /// the list, whatever blanks the list carries.
    #[tokio::test]
    async fn a_refused_application_origin_carries_its_own_index() {
        let err = Bridge::start(&Config::fixture(&[
            "--allowed-app-origins",
            ",https://app.example,https://APP.example",
        ]))
        .err()
        .expect("the third member is not canonical");
        let text = err.to_string();
        assert!(text.contains("ALLOWED_APP_ORIGINS[2]"), "{text}");
    }

    /// Each of these is refused at startup.
    #[tokio::test]
    async fn a_deployment_that_could_not_serve_a_ceremony_stops_the_process() {
        for (why, args) in [
            ("no admitted origin", vec!["--allowed-app-origins", ""]),
            (
                "a duplicate admitted origin",
                vec![
                    "--allowed-app-origins",
                    "https://app.example,https://app.example",
                ],
            ),
            (
                "a plaintext admitted origin that is not localhost or 127.0.0.1",
                vec!["--allowed-app-origins", "http://app.example"],
            ),
            (
                "a CCDP origin whose host carries a CSP directive separator",
                vec!["--ccdp-origin", "https://a;b.example"],
            ),
            (
                "a CCDP origin written as an IPv6 literal, which its policy \
                 could not name",
                vec!["--ccdp-origin", "https://[::1]:8787"],
            ),
            (
                "an admitted origin whose host carries a CSP keyword quote",
                vec!["--allowed-app-origins", "https://a'b.example"],
            ),
            (
                "an admitted origin carrying a trailing slash",
                vec!["--allowed-app-origins", "https://app.example/"],
            ),
            (
                "an admitted origin spelled with an uppercase host",
                vec!["--allowed-app-origins", "https://APP.example"],
            ),
            (
                "an admitted origin carrying a default port",
                vec!["--allowed-app-origins", "https://app.example:443"],
            ),
            (
                "a github platform whose credential carries whitespace",
                vec![
                    "--platforms",
                    r#"[{"id":"github","client_id":"gh","versions":[1],"client_credential":"c0f fee"}]"#,
                ],
            ),
        ] {
            assert!(
                Bridge::start(&Config::fixture(&args)).is_err(),
                "{why} must stop the process"
            );
        }
    }

    /// The published record keys every enabled platform by name and carries
    /// its client id and versions; the github entry carries its public
    /// client credential, and no other entry carries one.
    #[tokio::test]
    async fn the_published_configuration_keys_every_enabled_platform_by_name() {
        let state = started(&[
            "--platforms",
            r#"[{"id":"google","client_id":"g","versions":[1,2]},{"id":"x","client_id":"xc","versions":[3]},{"id":"github","client_id":"gh","versions":[1],"client_credential":"c0ffee"}]"#,
        ])
        .await;
        let record: serde_json::Value =
            serde_json::from_slice(&state.ceremony_config).unwrap();
        let platforms = record["platforms"].as_object().unwrap();
        let mut names: Vec<&str> = platforms.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["github", "google", "x"]);
        assert_eq!(
            platforms["google"]["ceremonyVersions"],
            serde_json::json!([1, 2])
        );
        assert_eq!(platforms["x"]["clientId"], "xc");
        assert_eq!(platforms["github"]["clientCredential"], "c0ffee");
        assert!(platforms["google"].get("clientCredential").is_none());
        assert!(platforms["x"].get("clientCredential").is_none());
    }

    /// The fixture deployment publishes the fixture credential.
    #[tokio::test]
    async fn the_fixture_deployment_publishes_its_credential() {
        let state = started(&[]).await;
        let record: serde_json::Value =
            serde_json::from_slice(&state.ceremony_config).unwrap();
        assert_eq!(
            record["platforms"]["github"]["clientCredential"],
            fixtures::CLIENT_CREDENTIAL
        );
    }

    /// `build_router` mounts every path.
    #[tokio::test]
    async fn building_the_router_for_a_configured_deployment_does_not_panic() {
        let state = started(&[]).await;
        let _: axum::Router = routes::build_router(state);
    }

    /// The bound listener answers until told to stop, and `serve` returns.
    #[tokio::test]
    async fn serve_answers_until_told_to_stop() {
        use tokio::io::{
            AsyncReadExt,
            AsyncWriteExt,
        };

        let bridge = Bridge::start(&Config::fixture(&[])).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(bridge, listener, async {
            let _ = stopped.await;
        }));

        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        socket
            .write_all(
                b"GET /health HTTP/1.1\r\nhost: bridge\r\nconnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut answer = Vec::new();
        socket.read_to_end(&mut answer).await.unwrap();
        assert!(
            answer.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&answer)
        );

        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
