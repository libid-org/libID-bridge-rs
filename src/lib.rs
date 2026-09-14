//! The OAuth Bridge of a libID ceremony. The contract is `specs/oauth-bridge.md`
//! in the libid repository.
//!
//! It publishes the configuration an application starts from, serves the one
//! callback document the OAuth platforms redirect back to, and performs the
//! one exchange a browser cannot: GitHub's, which needs a client secret.
//! `/health` is a liveness probe for the container healthcheck.
//!
//! The callback document is the CCDP Distribution's artifact with this
//! deployment's data inserted into its one slot; everything the browser runs
//! after the callback is served by that Distribution. This service verifies
//! no proof, holds no key of its own, keeps no ceremony state, and talks to
//! no chain.

#![warn(missing_docs)]

pub(crate) mod artifact;
pub mod config;
pub(crate) mod deployment;
pub mod error;
#[cfg(any(test, feature = "fixtures"))]
#[doc(hidden)]
pub mod fixtures;
pub(crate) mod oauth;
pub(crate) mod origin;
pub mod routes;
pub mod state;

use std::sync::Arc;

use error::{
    Error,
    Result,
};
use origin::Origin;
use secrecy::{
    ExposeSecret,
    SecretString,
};
use state::AppState;
use tokio::sync::Semaphore;

/// Build the shared [`AppState`] from the configuration. Everything that must
/// be well-formed for a request to succeed is checked here, at startup, and
/// the callback artifact is retrieved from the Distribution before this
/// returns; it returns `Err` when it cannot.
pub async fn build_state(cfg: &config::Config) -> Result<Arc<AppState>> {
    let allowed_app_origins = allowed_app_origins(&cfg.allowed_app_origins)?;
    let ccdp_origin = Origin::parse("CCDP_ORIGIN", &cfg.ccdp_origin)?;
    let public_origin = public_origin(&cfg.public_origin)?;
    // The effective set `allowedAppOrigins ∪ {ccdpOrigin}`: the one admission
    // rule of every gated route, and what the callback document is told. The
    // resolved CCDP origin joins once; an overridden `CCDP_ORIGIN` does not
    // keep `https://lib.id` admitted unless it is listed.
    let allowed_origins: Arc<[Origin]> = {
        let mut set = allowed_app_origins.clone();
        if !set.contains(&ccdp_origin) {
            set.push(ccdp_origin.clone());
        }
        set.into()
    };
    let platforms = deployment::platforms(cfg.platforms.clone())?;
    routes::github_token::force_token_endpoint();

    // The exchange is present exactly when a github platform is enabled. Its
    // secret is `GH_OAUTH_CLIENT_SECRET` where set, else the table's; an empty
    // value is unset.
    let set = |secret: &SecretString| !secret.expose_secret().is_empty();
    let overriding = cfg.gh_oauth_client_secret.as_ref().filter(|s| set(s));
    let github = match platforms.iter().find(|p| p.is_github()) {
        Some(profile) => {
            let Some(secret) = overriding
                .or_else(|| profile.client_secret().filter(|s| set(s)))
                .cloned()
            else {
                return Err(Error::Config {
                    detail: "the platforms enable github; set client_secret in its \
                             [[platforms]] table or GH_OAUTH_CLIENT_SECRET"
                        .into(),
                });
            };
            Some(Arc::new(state::GithubExchange {
                credentials: oauth::OAuthCredentials {
                    client_id: profile.client_id().to_owned(),
                    client_secret: secret,
                },
                redirect_uri: format!("{public_origin}{}", routes::CALLBACK_PATH),
                egress: routes::github_token::NotaryEgress::new(cfg.notary_wire_port),
                admitted: allowed_origins.iter().map(Origin::header_value).collect(),
                permits: Semaphore::new(state::MAX_CONCURRENT_EXCHANGES),
            }))
        }
        None if overriding.is_none() => None,
        None => {
            return Err(Error::Config {
                detail: "GH_OAUTH_CLIENT_SECRET is set but no platform enables github"
                    .into(),
            })
        }
    };

    let upstream = artifact::upstream::Upstream::new(&ccdp_origin);
    let published = artifact::Published::retrieved(&upstream, &allowed_origins).await?;
    let (callback_tx, callback) = tokio::sync::watch::channel(Arc::new(published));

    Ok(Arc::new(AppState {
        ceremony_config: deployment::CeremonyConfig {
            ccdp_origin: &ccdp_origin,
            platforms: &platforms,
        }
        .serialized(),
        callback,
        callback_tx,
        upstream,
        public_origin_admitted: allowed_origins.contains(&public_origin),
        allowed_origins,
        github,
    }))
}

/// Serve `state` on `listener` until `shutdown` resolves; in-flight requests
/// finish first. The callback artifact is revalidated for as long as this
/// runs.
pub async fn serve(
    state: Arc<AppState>,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let app = routes::build_router(state.clone());
    let refreshing = tokio::spawn(refresh_callback(state));
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await;
    refreshing.abort();
    served
}

/// Revalidate the callback artifact for as long as the process runs; it
/// returns only when the process ends.
pub async fn refresh_callback(state: Arc<AppState>) {
    artifact::upstream::refresh(state, artifact::upstream::Schedule::DEPLOYED).await
}

/// The application origins admitted to read the configuration, each as
/// written: one that is not already canonical is refused, not folded.
fn allowed_app_origins(list: &[String]) -> Result<Vec<Origin>> {
    let mut out = Vec::new();
    for (i, spelling) in list
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        let field = format!("ALLOWED_APP_ORIGINS[{i}]");
        let origin = Origin::listed(&field, spelling)?;
        // A duplicate is refused, not folded.
        if out.contains(&origin) {
            return Err(Error::Config {
                detail: format!("ALLOWED_APP_ORIGINS names {origin} more than once"),
            });
        }
        out.push(origin);
    }
    if out.is_empty() {
        return Err(Error::Config {
            detail: "ALLOWED_APP_ORIGINS is empty, so no application could \
                     read the ceremony configuration"
                .into(),
        });
    }
    Ok(out)
}

/// The origin this bridge is reached at, in canonical form. Empty is refused:
/// the redirect URI derived from it must equal the OAuth Apps' registration.
fn public_origin(spelling: &str) -> Result<Origin> {
    if spelling.trim().is_empty() {
        return Err(Error::Config {
            detail: "PUBLIC_ORIGIN is empty; set it to the origin this bridge is \
                     reached at, the one the OAuth Apps register /auth/callback under"
                .into(),
        });
    }
    Origin::parse("PUBLIC_ORIGIN", spelling)
}

#[cfg(test)]
mod tests {
    use super::{
        config::Config,
        fixtures::Distribution,
        *,
    };

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

        let state = build_state(&Config::fixture(&[])).await.unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(&state.ceremony_config).unwrap();
        assert_eq!(record["ccdpOrigin"], Distribution::shared().origin());
    }

    /// The redirect URI the exchange sends is the public origin, folded to its
    /// canonical form, followed by `/auth/callback`.
    #[tokio::test]
    async fn the_redirect_uri_is_the_callback_path_under_the_public_origin() {
        let state = build_state(&Config::fixture(&[
            "--public-origin",
            "https://Bridge.example:443",
        ]))
        .await
        .unwrap();
        let github = state.github.as_ref().expect("github is enabled");
        assert_eq!(github.redirect_uri, "https://bridge.example/auth/callback");
    }

    /// A same-origin read of the configuration is admitted exactly when the
    /// public origin is listed as an application origin.
    #[tokio::test]
    async fn a_same_origin_read_is_admitted_only_when_the_public_origin_is_listed() {
        assert!(
            !build_state(&Config::fixture(&[]))
                .await
                .unwrap()
                .public_origin_admitted
        );
        let listed = build_state(&Config::fixture(&[
            "--allowed-app-origins",
            "https://app.example,https://bridge.example",
        ]))
        .await
        .unwrap();
        assert!(listed.public_origin_admitted);
    }

    /// The effective set is `allowedAppOrigins ∪ {ccdpOrigin}`: the resolved
    /// origin joins once, and an origin already listed is not added twice. The
    /// token route holds the same set as header values.
    #[tokio::test]
    async fn the_effective_admission_set_is_the_allowlist_plus_the_ccdp_origin() {
        async fn origins(args: &[&str]) -> Vec<String> {
            let state = build_state(&Config::fixture(args)).await.unwrap();
            let github = state.github.as_ref().expect("github is enabled");
            assert_eq!(
                github.admitted,
                state
                    .allowed_origins
                    .iter()
                    .map(Origin::header_value)
                    .collect::<Vec<_>>(),
                "the token route's set is the effective set"
            );
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

    /// Each of these is refused at startup.
    #[tokio::test]
    async fn a_deployment_that_could_not_serve_a_ceremony_stops_the_process() {
        for (why, args) in [
            ("no public origin", vec!["--public-origin", ""]),
            (
                "a public origin carrying a path",
                vec!["--public-origin", "https://bridge.example/auth"],
            ),
            (
                "a plaintext public origin that is not localhost or 127.0.0.1",
                vec!["--public-origin", "http://bridge.example"],
            ),
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
        ] {
            assert!(
                build_state(&Config::fixture(&args)).await.is_err(),
                "{why} must stop the process"
            );
        }
    }

    /// The published record keys every enabled platform by name and carries
    /// its client id and versions, and no secret.
    #[tokio::test]
    async fn the_published_configuration_keys_every_enabled_platform_by_name() {
        let state = build_state(&Config::fixture(&[
            "--platforms",
            r#"[{"id":"google","client_id":"g","versions":[1,2]},{"id":"x","client_id":"xc","versions":[3]},{"id":"github","client_id":"gh","versions":[1]}]"#,
        ])).await
        .unwrap();
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
        assert!(!String::from_utf8_lossy(&state.ceremony_config).contains("ghs_secret"));
    }

    /// A github platform without a secret, or a secret without a github
    /// platform, refuses to start; neither is a deployment without the route.
    /// The table's secret serves, and `GH_OAUTH_CLIENT_SECRET` overrides it.
    #[tokio::test]
    async fn the_github_secret_and_the_github_platform_require_each_other() {
        let no_secret = vec!["--gh-oauth-client-secret", ""];
        assert!(build_state(&Config::fixture(&no_secret)).await.is_err());

        let in_the_table = vec![
            "--platforms",
            r#"[{"id":"github","client_id":"gh","versions":[1],"client_secret":"ghs_in_the_table"}]"#,
            "--gh-oauth-client-secret",
            "",
        ];
        let state = build_state(&Config::fixture(&in_the_table)).await.unwrap();
        assert_eq!(
            state
                .github
                .as_ref()
                .unwrap()
                .credentials
                .client_secret
                .expose_secret(),
            "ghs_in_the_table"
        );
        let overridden = vec![
            "--platforms",
            r#"[{"id":"github","client_id":"gh","versions":[1],"client_secret":"ghs_in_the_table"}]"#,
        ];
        let state = build_state(&Config::fixture(&overridden)).await.unwrap();
        assert_eq!(
            state
                .github
                .as_ref()
                .unwrap()
                .credentials
                .client_secret
                .expose_secret(),
            "ghs_secret"
        );

        let x_only = vec![
            "--platforms",
            r#"[{"id":"x","client_id":"abc","versions":[1]}]"#,
        ];
        assert!(
            build_state(&Config::fixture(&x_only)).await.is_err(),
            "a secret with no github platform must stop the process"
        );

        let neither = vec![
            "--platforms",
            r#"[{"id":"x","client_id":"abc","versions":[1]}]"#,
            "--gh-oauth-client-secret",
            "",
        ];
        let state = build_state(&Config::fixture(&neither)).await.unwrap();
        assert!(state.github.is_none());
    }

    /// `build_router` mounts every path for a deployment with the token route
    /// and one without.
    #[tokio::test]
    async fn building_the_router_for_a_configured_deployment_does_not_panic() {
        let state = build_state(&Config::fixture(&[])).await.unwrap();
        let _: axum::Router = routes::build_router(state);

        let x_only = build_state(&Config::fixture(&[
            "--platforms",
            r#"[{"id":"x","client_id":"abc","versions":[1]}]"#,
            "--gh-oauth-client-secret",
            "",
        ]))
        .await
        .unwrap();
        let _: axum::Router = routes::build_router(x_only);
    }

    /// The bound listener answers until told to stop, and `serve` returns.
    #[tokio::test]
    async fn serve_answers_until_told_to_stop() {
        use tokio::io::{
            AsyncReadExt,
            AsyncWriteExt,
        };

        let state = build_state(&Config::fixture(&[])).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(state, listener, async {
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
