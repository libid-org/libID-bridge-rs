//! Starting a deployment and serving it.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

mod root {
    use std::sync::Arc;

    use libid_server_rs::{
        state::AppState,
        *,
    };

    use crate::common::{
        self,
        Distribution,
    };

    /// The state of a deployment started on the fixture configuration with
    /// `args`.
    async fn started(args: &[&str]) -> Arc<AppState> {
        Bridge::start(&common::config(args)).unwrap().state
    }

    /// An omitted CCDP origin selects the canonical libID Distribution: the
    /// declared default is `https://lib.id`, and the configured value reaches
    /// the published record.
    #[tokio::test]
    async fn an_omitted_ccdp_origin_selects_the_canonical_distribution() {
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
        let err = Bridge::start(&common::config(&[
            "--allowed-app-origins",
            "https://app.example,https://APP.example",
        ]))
        .err()
        .expect("the second member is not canonical");
        let text = err.to_string();
        assert!(text.contains("ALLOWED_APP_ORIGINS[1]"), "{text}");
    }

    /// A member beginning `https://*.` is judged as an origin pattern, so one
    /// that is not well formed stops the process instead of being read as an
    /// origin, and the refusal names the member by its own index.
    #[tokio::test]
    async fn a_malformed_pattern_is_refused_by_its_own_index() {
        let err = Bridge::start(&common::config(&[
            "--allowed-app-origins",
            "https://app.example,https://*.localhost",
        ]))
        .err()
        .expect("the second member names a suffix of one label");
        let text = err.to_string();
        assert!(text.contains("ALLOWED_APP_ORIGINS[1]"), "{text}");
        assert!(text.contains("https://*.localhost"), "{text}");
    }

    /// A pattern is a member of the effective set as written, beside an
    /// origin it covers: members are duplicates only where their spellings
    /// are.
    #[tokio::test]
    async fn a_pattern_and_an_origin_it_covers_are_two_members() {
        let state = started(&[
            "--allowed-app-origins",
            "https://*.handles.link,https://app.handles.link",
        ])
        .await;
        let members: Vec<&str> =
            state.allowed_origins.iter().map(|m| m.as_str()).collect();
        assert_eq!(
            members[..2],
            ["https://*.handles.link", "https://app.handles.link"]
        );
    }

    /// The CCDP origin joins the effective set by its literal spelling: a
    /// pattern covering it is a different member, and the Callback asserts
    /// the list carries the origin itself.
    #[tokio::test]
    async fn a_pattern_covering_the_ccdp_origin_does_not_stand_in_for_it() {
        let state = started(&[
            "--ccdp-origin",
            "https://dist.handles.link",
            "--allowed-app-origins",
            "https://*.handles.link",
        ])
        .await;
        let members: Vec<&str> =
            state.allowed_origins.iter().map(|m| m.as_str()).collect();
        assert_eq!(
            members,
            ["https://*.handles.link", "https://dist.handles.link"]
        );
    }

    /// A member the operator did not mean to write is refused rather than
    /// skipped.
    #[tokio::test]
    async fn a_blank_member_is_refused() {
        let err = Bridge::start(&common::config(&[
            "--allowed-app-origins",
            ",https://app.example",
        ]))
        .err()
        .expect("the first member is blank");
        assert!(
            err.to_string().contains("ALLOWED_APP_ORIGINS[0] is blank"),
            "{err}"
        );
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
                "a duplicate origin pattern",
                vec![
                    "--allowed-app-origins",
                    "https://*.handles.link,https://*.handles.link",
                ],
            ),
            (
                "an origin pattern whose suffix is one label",
                vec!["--allowed-app-origins", "https://*.localhost"],
            ),
            (
                "an origin pattern whose suffix is not canonical",
                vec!["--allowed-app-origins", "https://*.HANDLES.link"],
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
                "a CCDP origin whose host carries an underscore, which a \
                 policy source expression has no form for",
                vec!["--ccdp-origin", "https://dev_box.example"],
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
                Bridge::start(&common::config(&args)).is_err(),
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
            common::CLIENT_CREDENTIAL
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

        let bridge = Bridge::start(&common::config(&[])).unwrap();
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
