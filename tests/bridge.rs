//! Starting a deployment and serving it.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

mod root {
    use std::sync::Arc;

    use libid_bridge_rs::{
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

    /// The record is composed at startup and the document is retrieved
    /// later: a started deployment holds its record before its refresher
    /// runs, and no document.
    #[tokio::test]
    async fn a_started_deployment_holds_its_record_and_no_document() {
        let state = started(&[]).await;
        assert!(!state.ceremony_config.is_empty());
        assert!(state.callback.borrow().is_none());
        assert!(state.failure.borrow().is_none());
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

    /// A member beginning `*.` is judged as an origin pattern, so one that is
    /// not well formed stops the process instead of being read as an origin,
    /// and the refusal names the member by its own index.
    #[tokio::test]
    async fn a_malformed_pattern_is_refused_by_its_own_index() {
        let err = Bridge::start(&common::config(&[
            "--allowed-app-origins",
            "https://app.example,*.handles_link",
        ]))
        .err()
        .expect("the second member carries an underscore");
        let text = err.to_string();
        assert!(text.contains("ALLOWED_APP_ORIGINS[1]"), "{text}");
        assert!(text.contains("*.handles_link"), "{text}");
    }

    /// How wide an allowlist is belongs to whoever writes it: a suffix of one
    /// label and a bare `*` are members, each joining the effective set as
    /// written and beside an exact member.
    #[tokio::test]
    async fn a_member_as_wide_as_an_operator_writes_is_a_member() {
        for member in ["*.com", "*"] {
            let state = started(&[
                "--allowed-app-origins",
                &format!("https://app.example,{member}"),
            ])
            .await;
            let members: Vec<&str> =
                state.allowed_origins.iter().map(|m| m.as_str()).collect();
            assert_eq!(members[..2], ["https://app.example", member], "{member}");
        }
    }

    /// A pattern is a member of the effective set as written, beside an
    /// origin it covers: members are duplicates only where their spellings
    /// are.
    #[tokio::test]
    async fn a_pattern_and_an_origin_it_covers_are_two_members() {
        let state = started(&[
            "--allowed-app-origins",
            "*.handles.link,https://app.handles.link",
        ])
        .await;
        let members: Vec<&str> =
            state.allowed_origins.iter().map(|m| m.as_str()).collect();
        assert_eq!(members[..2], ["*.handles.link", "https://app.handles.link"]);
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
            "*.handles.link",
        ])
        .await;
        let members: Vec<&str> =
            state.allowed_origins.iter().map(|m| m.as_str()).collect();
        assert_eq!(members, ["*.handles.link", "https://dist.handles.link"]);
    }

    /// A canonical HTTPS CCDP origin starts the bridge whatever its host
    /// carries: an IPv6 literal or an underscore is selected and joins the
    /// effective set as written.
    #[tokio::test]
    async fn a_ccdp_origin_on_any_canonical_host_starts_the_bridge() {
        for ccdp in ["https://[::1]:8787", "https://dev_box.example"] {
            let settings = common::config(&["--ccdp-origin", ccdp]);
            let selected = deployment::Deployment::checked(&settings).unwrap();
            assert_eq!(selected.ccdp_origin.as_str(), ccdp);
            let state = Bridge::start(&settings).unwrap().state;
            let members: Vec<&str> =
                state.allowed_origins.iter().map(|m| m.as_str()).collect();
            assert_eq!(members, ["https://app.example", ccdp]);
        }
    }

    /// The CCDP origin is read as written, as an exact member is: a spelling
    /// that is not canonical stops the process, naming the one to write,
    /// rather than being folded into it.
    #[tokio::test]
    async fn a_noncanonical_ccdp_origin_is_refused_rather_than_folded() {
        for spelling in [
            "https://Dist.example",
            "https://dist.example/",
            "https://dist.example:443",
        ] {
            let err = Bridge::start(&common::config(&["--ccdp-origin", spelling]))
                .err()
                .unwrap_or_else(|| panic!("{spelling} is not canonical"));
            let text = err.to_string();
            assert!(text.contains("CCDP_ORIGIN"), "{text}");
            assert!(text.contains("write it as https://dist.example"), "{text}");
        }
    }

    /// A canonical CCDP origin whose host no HTTP request can carry stops the
    /// process, naming `CCDP_ORIGIN`: the artifact could never be retrieved
    /// from it.
    #[tokio::test]
    async fn a_ccdp_origin_no_request_can_carry_stops_the_process() {
        for spelling in [
            "https://a\"b.example",
            "https://a`b.example",
            "https://a{b.example",
            "https://a}b.example",
        ] {
            assert!(
                origin::Origin::listed("CCDP_ORIGIN", spelling).is_ok(),
                "{spelling} is a canonical origin"
            );
            let err = Bridge::start(&common::config(&["--ccdp-origin", spelling]))
                .err()
                .unwrap_or_else(|| panic!("no request carries {spelling}"));
            let text = err.to_string();
            assert!(
                text.contains("CCDP_ORIGIN") && text.contains("no HTTP request"),
                "{text}"
            );
        }
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
                vec!["--allowed-app-origins", "*.handles.link,*.handles.link"],
            ),
            (
                "an origin pattern whose suffix is not lowercase DNS labels",
                vec!["--allowed-app-origins", "*.HANDLES.link"],
            ),
            (
                "a plaintext admitted origin that is not localhost or 127.0.0.1",
                vec!["--allowed-app-origins", "http://app.example"],
            ),
            (
                "a CCDP origin written as an origin pattern, which names no \
                 Distribution",
                vec!["--ccdp-origin", "*.handles.link"],
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
                    r#"[{"id":"github","client_id":"gh","client_credential":"c0f fee"}]"#,
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
    /// its client id; the github entry carries its public client credential,
    /// and no other entry carries one.
    #[tokio::test]
    async fn the_published_configuration_keys_every_enabled_platform_by_name() {
        let state = started(&[
            "--platforms",
            r#"[{"id":"google","client_id":"g"},{"id":"x","client_id":"xc"},{"id":"github","client_id":"gh","client_credential":"c0ffee"}]"#,
        ])
        .await;
        let record: serde_json::Value =
            serde_json::from_slice(&state.ceremony_config).unwrap();
        let platforms = record["platforms"].as_object().unwrap();
        let mut names: Vec<&str> = platforms.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["github", "google", "x"]);
        assert_eq!(platforms["google"], serde_json::json!({ "clientId": "g" }));
        assert_eq!(platforms["x"], serde_json::json!({ "clientId": "xc" }));
        assert_eq!(
            platforms["github"],
            serde_json::json!({ "clientId": "gh", "clientCredential": "c0ffee" })
        );
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
