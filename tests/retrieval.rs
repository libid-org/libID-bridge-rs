//! Retrieving the callback artifact and the version list, and the refresher
//! that keeps both current.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

mod upstream {
    use std::{
        sync::Arc,
        time::Duration,
    };

    use hyper::{
        header,
        StatusCode,
    };
    use libid_bridge_rs::{
        artifact::{
            upstream::*,
            Published,
        },
        deployment::{
            PlatformId,
            PublishedConfig,
        },
        origin::{
            Admitted,
            Origin,
        },
        versions::MAX_VERSIONS_BYTES,
    };

    use crate::common::{
        self,
        Distribution,
        Reply,
    };

    fn origin(spelling: &str) -> Origin {
        Origin::parse("T", spelling).expect("an origin the tests dial")
    }

    /// A Distribution as a deployment retrieves from it.
    fn upstream(distribution: &Distribution) -> Upstream {
        Upstream::new(&origin(distribution.origin()))
    }

    /// An `https` origin that presents a certificate nothing trusts.
    async fn untrusted_tls_origin() -> String {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a self-signed certificate");
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                    cert.key_pair.serialize_der().into(),
                ),
            )
            .expect("a server configuration");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(socket).await;
                });
            }
        });
        format!("https://localhost:{port}")
    }

    /// Retrieve the artifact, and answer with the refusal.
    async fn refused(upstream: Upstream, unless: &str) -> FetchError {
        match upstream.retrieve_callback(&origins(), None).await {
            Err(refusal) => refusal,
            Ok(_) => panic!("{unless}"),
        }
    }

    /// The origins a deployment admits.
    fn origins() -> Vec<Admitted> {
        vec![Admitted::Exact(origin("https://app.example"))]
    }

    /// A deployment pointed at a fixture Distribution, started the way the
    /// binary starts one and given the one tick its refresher would make
    /// first: both resources retrieved.
    async fn bridge(distribution: &Distribution) -> libid_bridge_rs::Bridge {
        let bridge =
            libid_bridge_rs::Bridge::start(&config(distribution.origin())).unwrap();
        common::retrieve_once(&bridge)
            .await
            .expect("the fixture Distribution answers the artifact and the version list");
        bridge
    }

    /// A healthy Distribution, a deployment pointed at it, and the document
    /// that deployment published.
    async fn deployed() -> (Distribution, libid_bridge_rs::Bridge, Arc<Published>) {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        let before = published(&bridge);
        (distribution, bridge, before)
    }

    /// The document a deployment is serving. It has published one by the
    /// time any of these tests looks.
    fn published(bridge: &libid_bridge_rs::Bridge) -> Arc<Published> {
        bridge
            .state
            .callback
            .current
            .borrow()
            .clone()
            .expect("a document is published")
    }

    /// The record a deployment is serving. It has published one by the time
    /// any of these tests looks.
    fn record(bridge: &libid_bridge_rs::Bridge) -> Arc<PublishedConfig> {
        bridge
            .state
            .ceremony_config
            .current
            .borrow()
            .clone()
            .expect("a record is published")
    }

    /// A deployment pointed at this test's own Distribution.
    fn config(ccdp_origin: &str) -> libid_bridge_rs::config::Settings {
        common::config(&["--ccdp-origin", ccdp_origin])
    }

    fn served(bridge: &libid_bridge_rs::Bridge) -> String {
        String::from_utf8(published(bridge).document.body.to_vec()).unwrap()
    }

    /// A deployment serves the artifact its Distribution built.
    #[tokio::test]
    async fn a_retrieved_artifact_is_what_gets_served() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;

        let published = published(&bridge);
        assert_eq!(published.etag.as_deref(), Some("W/\"the-artifact\""));
        // Composed: the deployment's data is in the document, the marker gone.
        assert!(served(&bridge).contains("https://app.example"));
        assert!(!served(&bridge).contains(libid_bridge_rs::artifact::policy::MARKER));
        // And the policy names the hash of what is being served.
        assert!(published
            .document
            .csp
            .to_str()
            .unwrap()
            .contains("'sha256-"));
    }

    /// A deployment composes its record from the version list its
    /// Distribution serves, and keeps the list and its validator with it.
    #[tokio::test]
    async fn a_retrieved_version_list_is_what_the_record_is_composed_from() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;

        let record = record(&bridge);
        assert_eq!(record.etag.as_deref(), Some("W/\"the-versions\""));
        assert_eq!(
            record.versions.bundled_for(PlatformId::Github),
            Some(&[1][..])
        );
        let json: serde_json::Value = serde_json::from_slice(&record.record).unwrap();
        assert_eq!(
            json["platforms"]["github"]["versions"],
            serde_json::json!([{
                "version": 1,
                "clientId": common::CLIENT_ID,
                "clientCredential": common::CLIENT_CREDENTIAL,
            }])
        );
        assert_eq!(json["ccdpOrigin"], distribution.origin());
    }

    /// A deployment whose Distribution answers nothing it can serve starts
    /// anyway, publishes no document, and records why, naming the URL.
    #[tokio::test]
    async fn a_deployment_that_cannot_retrieve_starts_and_says_why() {
        let distribution = Distribution::serving(Reply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            ..Reply::artifact()
        })
        .await;
        let bridge = libid_bridge_rs::Bridge::start(&config(distribution.origin()))
            .expect("a deployment starts without its Distribution");
        bridge
            .refresher
            .revalidate_callback()
            .await
            .expect_err("a 500 produces no document");

        assert!(bridge.state.callback.current.borrow().is_none());
        let why = bridge
            .state
            .callback
            .failure
            .borrow()
            .clone()
            .expect("a reason");
        assert!(why.contains(distribution.origin()), "{why}");
        assert!(why.contains(ARTIFACT_PATH), "{why}");
        assert_eq!(bridge.state.callback.why_nothing(), why);
    }

    /// A version list this bridge cannot accept publishes no record, and the
    /// reason names the URL; the callback document is unaffected.
    #[tokio::test]
    async fn a_deployment_whose_list_is_refused_starts_and_says_why() {
        let distribution = Distribution::healthy().await;
        distribution.now_serves_versions(Reply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            ..Reply::versions()
        });
        let bridge = libid_bridge_rs::Bridge::start(&config(distribution.origin()))
            .expect("a deployment starts without its Distribution");
        let tick = bridge.refresher.revalidate().await;
        assert_eq!(tick.callback.as_ref().ok(), Some(&true));
        assert!(
            matches!(tick.versions, Err(FetchError::Status(_))),
            "{:?}",
            tick.versions
        );
        assert!(tick.failed());

        assert!(bridge.state.ceremony_config.current.borrow().is_none());
        assert!(bridge.state.callback.current.borrow().is_some());
        let why = bridge
            .state
            .ceremony_config
            .failure
            .borrow()
            .clone()
            .expect("a reason");
        assert!(why.contains(distribution.origin()), "{why}");
        assert!(why.contains(VERSIONS_PATH), "{why}");
        assert!(bridge.state.callback.failure.borrow().is_none());
    }

    /// A Distribution that has nothing new says so, and nothing is republished.
    #[tokio::test]
    async fn an_unchanged_artifact_leaves_the_published_document_alone() {
        // The Distribution answers the revalidation, so it lives to the end.
        let (_distribution, bridge, before) = deployed().await;

        let replaced = bridge.refresher.revalidate_callback().await.unwrap();
        assert!(!replaced, "a 304 replaces nothing");
        // The same value, not an equal one: nothing was composed again.
        assert!(Arc::ptr_eq(&before, &published(&bridge)));
    }

    /// The same of the version list: a `304` leaves the record as it is.
    #[tokio::test]
    async fn an_unchanged_version_list_leaves_the_record_alone() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        let before = record(&bridge);

        let replaced = bridge.refresher.revalidate_versions().await.unwrap();
        assert!(!replaced, "a 304 replaces nothing");
        assert!(Arc::ptr_eq(&before, &record(&bridge)));
    }

    /// A failed refresh retains the last valid result and its validator.
    #[tokio::test]
    async fn an_artifact_that_will_not_scan_retains_the_last_valid_one() {
        let (distribution, bridge, before) = deployed().await;

        distribution.now_serves(Reply {
            etag: Some("W/\"the-replacement\""),
            body: "<!doctype html><body><p>not an artifact".to_owned(),
            ..Reply::artifact()
        });
        let refusal = bridge
            .refresher
            .revalidate_callback()
            .await
            .expect_err("an artifact with no slot is not serveable");
        assert!(matches!(refusal, FetchError::Artifact(_)), "{refusal}");

        assert!(Arc::ptr_eq(&before, &published(&bridge)));
        assert_eq!(
            published(&bridge).etag.as_deref(),
            Some("W/\"the-artifact\"")
        );
    }

    /// A version list this bridge refuses, for any of the grammar's reasons
    /// or for arriving as something else, retains the last accepted record
    /// and its validator, and the refusal is recorded.
    #[tokio::test]
    async fn a_version_list_that_is_refused_retains_the_last_accepted_one() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        let before = record(&bridge);

        for body in [
            "[]",
            "not json",
            r#"{"github":[]}"#,
            r#"{"github":[1,1]}"#,
            r#"{"github":[2,1]}"#,
            r#"{"github":[70000]}"#,
            r#"{"github":"1"}"#,
        ] {
            distribution.now_serves_versions(Reply::listing(body));
            let refusal = bridge
                .refresher
                .revalidate_versions()
                .await
                .expect_err(body);
            assert!(
                matches!(refusal, FetchError::Versions(_)),
                "{body}: {refusal}"
            );
            assert!(Arc::ptr_eq(&before, &record(&bridge)), "{body}");
            let why = bridge
                .state
                .ceremony_config
                .failure
                .borrow()
                .clone()
                .expect("a reason");
            assert!(why.contains(VERSIONS_PATH), "{why}");
        }

        distribution.now_serves_versions(Reply {
            media: "text/html; charset=utf-8",
            ..Reply::listing(common::VERSIONS)
        });
        let refusal = bridge
            .refresher
            .revalidate_versions()
            .await
            .expect_err("a list served as HTML");
        assert!(matches!(refusal, FetchError::Media { .. }), "{refusal}");
        assert!(Arc::ptr_eq(&before, &record(&bridge)));
        assert_eq!(record(&bridge).etag.as_deref(), Some("W/\"the-versions\""));
    }

    /// The publish itself: a Distribution with something new produces a new
    /// document, a new policy and a new validator, all at once.
    #[tokio::test]
    async fn a_new_artifact_replaces_the_published_one_whole() {
        let (distribution, bridge, before) = deployed().await;
        distribution.now_serves(Reply::replacement());

        assert!(bridge.refresher.revalidate_callback().await.unwrap());

        let after = published(&bridge);
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.etag.as_deref(), Some("W/\"the-replacement\""));
        // One value replaced: the policy names the hashes of the document served.
        assert_eq!(
            after.document.csp, before.document.csp,
            "the same bundle hashes the same, whatever validator carried it"
        );
        assert!(String::from_utf8(after.document.body.to_vec())
            .unwrap()
            .contains("https://app.example"));
    }

    /// A new version list replaces the record, the list and the validator as
    /// one value, and the record advertises exactly the new list.
    #[tokio::test]
    async fn a_new_version_list_replaces_the_record_whole() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        let before = record(&bridge);
        distribution.now_serves_versions(Reply {
            etag: Some("W/\"more-versions\""),
            ..Reply::listing(r#"{"github":[1,2]}"#)
        });

        assert!(bridge.refresher.revalidate_versions().await.unwrap());

        let after = record(&bridge);
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.etag.as_deref(), Some("W/\"more-versions\""));
        assert_eq!(
            after.versions.bundled_for(PlatformId::Github),
            Some(&[1, 2][..])
        );
        let json: serde_json::Value = serde_json::from_slice(&after.record).unwrap();
        let listed: Vec<u64> = json["platforms"]["github"]["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["version"].as_u64().unwrap())
            .collect();
        assert_eq!(listed, [1, 2]);
    }

    /// A schedule fast enough to assert on, in real time.
    const BRISK: Schedule = Schedule {
        interval: Duration::from_millis(10),
        floor: Duration::from_millis(10),
    };

    /// A refresh that fails, one that finds nothing new, and one that
    /// replaces: the first two leave the served document as it is, and the
    /// loop reaches the third.
    #[tokio::test]
    async fn the_loop_survives_a_failed_refresh_and_replaces_on_a_later_one() {
        let (distribution, bridge, before) = deployed().await;
        let libid_bridge_rs::Bridge { state, refresher } = bridge;

        // Answered in order, then the standing replacement.
        distribution.answers_next(Reply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            ..Reply::artifact()
        });
        distribution.answers_next(Reply::artifact());
        distribution.now_serves(Reply::replacement());

        let mut published = state.callback.current.clone();
        // The channel starts empty, so the first document is itself a change:
        // mark it seen, and what follows is the replacement.
        published.borrow_and_update();
        let loop_task = tokio::spawn(refresher.run(BRISK));
        // Resolves on the first send, so nothing before it published.
        published.changed().await.expect("the loop publishes");
        // Stopped, though nothing below depends on how promptly it stops.
        loop_task.abort();

        let after = published
            .borrow_and_update()
            .clone()
            .expect("the loop published a document");
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.etag.as_deref(), Some("W/\"the-replacement\""));
        // Both queued answers were given before the replacement was reached.
        assert_eq!(distribution.still_queued(), 0);
        assert!(distribution.requests().len() >= 4);
    }

    /// The loop revalidates the version list on every tick too: a list that
    /// changes while the loop runs replaces the record.
    #[tokio::test]
    async fn the_loop_replaces_the_record_when_the_list_changes() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        let libid_bridge_rs::Bridge { state, refresher } = bridge;
        distribution.now_serves_versions(Reply::listing(r#"{"github":[1,2]}"#));

        let mut published = state.ceremony_config.current.clone();
        published.borrow_and_update();
        let loop_task = tokio::spawn(refresher.run(BRISK));
        published.changed().await.expect("the loop publishes");
        loop_task.abort();

        let after = published
            .borrow_and_update()
            .clone()
            .expect("the loop published a record");
        assert_eq!(
            after.versions.bundled_for(PlatformId::Github),
            Some(&[1, 2][..])
        );
    }

    /// Each resource is published on its own: a failure of one leaves the
    /// other's product where it is, and the tick counts as failed either way.
    #[tokio::test]
    async fn each_resource_is_published_on_its_own() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        let document = published(&bridge);
        let config = record(&bridge);

        // Both current: nothing replaced, nothing failed.
        let tick = bridge.refresher.revalidate().await;
        assert!(matches!(tick.callback, Ok(false)));
        assert!(matches!(tick.versions, Ok(false)));
        assert!(!tick.failed());

        // The artifact fails; the list is fine.
        distribution.answers_next(Reply {
            status: StatusCode::BAD_GATEWAY,
            ..Reply::artifact()
        });
        let tick = bridge.refresher.revalidate().await;
        assert!(matches!(tick.callback, Err(FetchError::Status(_))));
        assert!(matches!(tick.versions, Ok(false)));
        assert!(tick.failed());
        assert!(Arc::ptr_eq(&document, &published(&bridge)));
        assert!(Arc::ptr_eq(&config, &record(&bridge)));
        assert!(bridge.state.callback.failure.borrow().is_some());
        assert!(bridge.state.ceremony_config.failure.borrow().is_none());

        // The list fails; the artifact is fine, and its failure is forgotten.
        distribution.answers_next_versions(Reply::listing("[]"));
        let tick = bridge.refresher.revalidate().await;
        assert!(matches!(tick.callback, Ok(false)));
        assert!(matches!(tick.versions, Err(FetchError::Versions(_))));
        assert!(tick.failed());
        assert!(Arc::ptr_eq(&document, &published(&bridge)));
        assert!(Arc::ptr_eq(&config, &record(&bridge)));
        assert!(bridge.state.callback.failure.borrow().is_none());
        assert!(bridge.state.ceremony_config.failure.borrow().is_some());
    }

    /// A Distribution that sends no validator answers every refresh with the
    /// document itself; the same bytes are not a replacement, so nothing is
    /// published and the served value is the one the first tick published.
    #[tokio::test]
    async fn the_same_document_under_no_validator_is_not_republished() {
        let distribution = Distribution::healthy().await;
        distribution.now_serves(Reply {
            etag: None,
            ..Reply::artifact()
        });
        let bridge = bridge(&distribution).await;
        let before = published(&bridge);
        assert_eq!(before.etag, None, "the Distribution sent no validator");

        for _ in 0..3 {
            assert!(
                !bridge
                    .refresher
                    .revalidate_callback()
                    .await
                    .expect("a refresh that reaches the Distribution"),
                "the same document is not a replacement"
            );
        }
        assert!(Arc::ptr_eq(&before, &published(&bridge)));

        // A document that did change is published, validator or not.
        distribution.now_serves(Reply {
            etag: None,
            // Outside the modules, so the hashes its policy names still hold.
            body: crate::common::ARTIFACT.replace("<title>libID", "<title>libID "),
            ..Reply::artifact()
        });
        assert!(bridge
            .refresher
            .revalidate_callback()
            .await
            .expect("a refresh that reaches the Distribution"));
        assert!(!Arc::ptr_eq(&before, &published(&bridge)));
    }

    /// The same of the version list: under no validator the same list is
    /// not a replacement and no record is composed again; a list that names
    /// the same versions in another spelling is the same list.
    #[tokio::test]
    async fn the_same_list_under_no_validator_is_not_republished() {
        let distribution = Distribution::healthy().await;
        distribution.now_serves_versions(Reply::listing(common::VERSIONS));
        let bridge = bridge(&distribution).await;
        let before = record(&bridge);
        assert_eq!(before.etag, None, "the Distribution sent no validator");

        for body in [
            common::VERSIONS,
            "{ \"x\": [1], \"google\": [1], \"github\": [1] }",
            r#"{"github":[1],"google":[1],"x":[1],"tiktok":[1]}"#,
        ] {
            distribution.now_serves_versions(Reply::listing(body));
            assert!(
                !bridge
                    .refresher
                    .revalidate_versions()
                    .await
                    .expect("a refresh that reaches the Distribution"),
                "{body} is not a replacement"
            );
        }
        assert!(Arc::ptr_eq(&before, &record(&bridge)));

        distribution.now_serves_versions(Reply::listing(
            r#"{"github":[1,2],"google":[1],"x":[1]}"#,
        ));
        assert!(bridge
            .refresher
            .revalidate_versions()
            .await
            .expect("a refresh that reaches the Distribution"));
        assert!(!Arc::ptr_eq(&before, &record(&bridge)));
    }

    /// An artifact served without a hash-only `script-src` is refused: the
    /// hashes of the code it carries are what the composed policy names, and
    /// this bridge computes none of its own.
    #[tokio::test]
    async fn an_artifact_whose_policy_is_not_hash_only_is_refused() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;

        for policy in [
            None,
            Some("default-src 'none'".to_owned()),
            Some("script-src 'unsafe-inline'".to_owned()),
            Some("script-src https://cdn.example".to_owned()),
        ] {
            distribution.now_serves(Reply {
                etag: Some("W/\"the-replacement\""),
                policy,
                ..Reply::artifact()
            });
            let refusal = bridge
                .refresher
                .revalidate_callback()
                .await
                .expect_err("an artifact this bridge cannot write a policy for");
            assert!(
                matches!(
                    refusal,
                    FetchError::Artifact(
                        libid_bridge_rs::artifact::policy::ArtifactError::UpstreamPolicy(
                            _
                        )
                    )
                ),
                "{refusal}"
            );
        }

        // What the deployment published first is still what it serves.
        assert_eq!(
            published(&bridge).etag.as_deref(),
            Some("W/\"the-artifact\"")
        );
    }

    /// A `3xx` is refused, not followed, for either resource.
    #[tokio::test]
    async fn a_redirect_is_refused_rather_than_followed() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        distribution.now_serves(Reply {
            status: StatusCode::FOUND,
            etag: None,
            ..Reply::artifact()
        });
        distribution.now_serves_versions(Reply {
            status: StatusCode::FOUND,
            etag: None,
            ..Reply::versions()
        });

        let refusal = bridge
            .refresher
            .revalidate_callback()
            .await
            .expect_err("a redirect is not an artifact");
        assert!(
            matches!(refusal, FetchError::Redirect(StatusCode::FOUND)),
            "{refusal}"
        );
        // One request, so nothing was followed.
        assert_eq!(distribution.requests().len(), 2);

        let refusal = bridge
            .refresher
            .revalidate_versions()
            .await
            .expect_err("a redirect is not a version list");
        assert!(
            matches!(refusal, FetchError::Redirect(StatusCode::FOUND)),
            "{refusal}"
        );
        assert_eq!(distribution.versions_requests().len(), 2);
    }

    /// A body over the bound is refused, with or without a `content-length`.
    #[tokio::test]
    async fn a_body_over_the_bound_is_refused() {
        let oversize =
            "x".repeat(libid_bridge_rs::artifact::policy::MAX_ARTIFACT_BYTES + 1);
        for chunked in [false, true] {
            let distribution = Distribution::serving(Reply {
                etag: None,
                body: oversize.clone(),
                chunked,
                ..Reply::artifact()
            })
            .await;
            let refusal = refused(
                upstream(&distribution),
                &format!("chunked={chunked}: an oversize body is refused"),
            )
            .await;
            assert!(
                matches!(refusal, FetchError::TooLarge(_)),
                "chunked={chunked}: {refusal}"
            );
        }
    }

    /// The version list has a bound of its own, and a body over it is refused
    /// before it is read as JSON.
    #[tokio::test]
    async fn a_version_list_over_its_bound_is_refused() {
        let oversize = format!("{{\"github\":[1]{}}}", " ".repeat(MAX_VERSIONS_BYTES));
        for chunked in [false, true] {
            let distribution = Distribution::healthy().await;
            distribution.now_serves_versions(Reply {
                chunked,
                ..Reply::listing(&oversize)
            });
            let refusal = upstream(&distribution)
                .retrieve_versions(None)
                .await
                .expect_err("an oversize list is refused");
            assert!(
                matches!(refusal, FetchError::TooLarge(MAX_VERSIONS_BYTES)),
                "chunked={chunked}: {refusal}"
            );
        }
    }

    /// A response that is not `text/html` is refused before scanning.
    #[tokio::test]
    async fn an_answer_that_is_not_html_is_refused() {
        for media in [
            "application/json",
            "text/plain",
            "text/htmlx",
            "text/html-fragment",
            "",
        ] {
            let distribution = Distribution::serving(Reply {
                media,
                etag: None,
                body: "{}".to_owned(),
                ..Reply::artifact()
            })
            .await;
            let refusal =
                refused(upstream(&distribution), "this is not the artifact").await;
            assert!(
                matches!(refusal, FetchError::Media { .. }),
                "{media:?}: {refusal}"
            );
        }
    }

    /// Every spelling of a resource's media type is admitted: the type is
    /// case-insensitive, and parameters begin after optional whitespace and a
    /// `;`. The other resource's type is not it.
    #[test]
    fn every_spelling_of_a_resources_media_type_names_it() {
        for media in [
            "text/html",
            "text/html; charset=utf-8",
            "text/html;charset=utf-8",
            "TEXT/HTML",
            "Text/HTML; charset=UTF-8",
            "  text/html",
            "text/html ",
        ] {
            assert!(CALLBACK.is_served_as(media), "{media:?} names the artifact");
        }
        for media in ["text/htmlx", "text/html-fragment", "application/json", ""] {
            assert!(
                !CALLBACK.is_served_as(media),
                "{media:?} does not name the artifact"
            );
        }
        for media in [
            "application/json",
            "application/json; charset=utf-8",
            "Application/JSON",
        ] {
            assert!(VERSIONS.is_served_as(media), "{media:?} names the list");
        }
        for media in ["application/jsonx", "text/json", "text/html", ""] {
            assert!(
                !VERSIONS.is_served_as(media),
                "{media:?} does not name the list"
            );
        }
    }

    /// The request carries nothing a deployment did not configure, for
    /// either resource, and each is revalidated with its own validator.
    #[tokio::test]
    async fn the_request_carries_nothing_a_deployment_did_not_configure() {
        let distribution = Distribution::healthy().await;
        let bridge = bridge(&distribution).await;
        let tick = bridge.refresher.revalidate().await;
        assert!(!tick.failed());

        for (requests, accept, etag) in [
            (distribution.requests(), "text/html", "W/\"the-artifact\""),
            (
                distribution.versions_requests(),
                "application/json",
                "W/\"the-versions\"",
            ),
        ] {
            let [first, second] = &requests[..] else {
                panic!(
                    "the first retrieval and one revalidation, got {}",
                    requests.len()
                )
            };
            for request in [first, second] {
                for absent in [
                    header::COOKIE,
                    header::AUTHORIZATION,
                    header::REFERER,
                    header::ORIGIN,
                ] {
                    assert!(request.get(&absent).is_none(), "{absent} was sent");
                }
                assert_eq!(
                    request.get(header::ACCEPT_ENCODING).unwrap(),
                    "identity",
                    "the bytes read must be the bytes served"
                );
                assert_eq!(request.get(header::ACCEPT).unwrap(), accept);
            }
            // The first retrieval is unconditional; the second carries the
            // validator the first was published with.
            assert!(first.get(header::IF_NONE_MATCH).is_none());
            assert_eq!(second.get(header::IF_NONE_MATCH).unwrap(), etag);
        }
    }

    /// A Distribution outlives the runtime that started it: the shared one is
    /// started by whichever test reaches it first, and that test's runtime is
    /// dropped when the test returns.
    #[test]
    fn a_distribution_outlives_the_runtime_that_started_it() {
        let runtime = || tokio::runtime::Runtime::new().unwrap();
        let distribution = runtime().block_on(Distribution::healthy());
        let published = runtime()
            .block_on(upstream(&distribution).retrieve_callback(&origins(), None));
        assert!(published.unwrap().is_some());
    }

    /// A peer presenting a certificate the compiled-in anchors do not carry is
    /// refused, and the refusal names the certificate.
    #[tokio::test]
    async fn an_untrusted_certificate_is_refused_as_a_certificate() {
        let untrusted = untrusted_tls_origin().await;
        let refusal = refused(
            Upstream::new(&origin(&untrusted)),
            "an untrusted peer is not a Distribution",
        )
        .await;
        let detail = format!("{refusal}");
        assert!(
            detail.contains("certificate") && detail.contains("UnknownIssuer"),
            "the refusal must name the certificate, and this one says: {detail}"
        );
    }

    /// An encoded body is refused: the request admitted `identity` alone.
    #[tokio::test]
    async fn a_body_that_arrives_encoded_is_refused() {
        let distribution = Distribution::serving(Reply {
            etag: None,
            encoding: Some("br"),
            ..Reply::artifact()
        })
        .await;
        let refusal = refused(
            upstream(&distribution),
            "an encoded body is not the artifact this bridge would hash",
        )
        .await;
        assert!(matches!(refusal, FetchError::Encoded(_)), "{refusal}");

        distribution.now_serves_versions(Reply {
            etag: None,
            encoding: Some("gzip"),
            ..Reply::versions()
        });
        let refusal = upstream(&distribution)
            .retrieve_versions(None)
            .await
            .expect_err("an encoded body is not the list");
        assert!(matches!(refusal, FetchError::Encoded(_)), "{refusal}");
    }

    /// A `304` to a request that carried no validator is refused, and a
    /// deployment cannot start on it.
    #[tokio::test]
    async fn a_304_to_a_request_that_asked_nothing_is_refused() {
        let distribution = Distribution::serving(Reply {
            status: StatusCode::NOT_MODIFIED,
            etag: None,
            ..Reply::artifact()
        })
        .await;
        let refusal = refused(
            upstream(&distribution),
            "an unasked 304 leaves nothing to serve",
        )
        .await;
        assert!(
            matches!(refusal, FetchError::UnaskedNotModified),
            "{refusal}"
        );
        let bridge =
            libid_bridge_rs::Bridge::start(&config(distribution.origin())).unwrap();
        assert!(bridge.refresher.revalidate_callback().await.is_err());
        assert!(bridge.state.callback.current.borrow().is_none());
    }

    /// `Host` carries the port only when it is not the scheme's default.
    /// The client writes it from the URL, so it is read off a request a
    /// Distribution actually received.
    #[tokio::test]
    async fn the_host_header_omits_a_default_port() {
        let distribution = Distribution::healthy().await;
        let _ = bridge(&distribution).await;
        let host = distribution.requests()[0][hyper::header::HOST]
            .to_str()
            .unwrap()
            .to_owned();
        let port = distribution
            .origin()
            .rsplit_once(':')
            .expect("a loopback origin carries its port")
            .1;
        assert_eq!(host, format!("127.0.0.1:{port}"));
        let upstream = Upstream::new(&origin("https://lib.id:443"));
        assert_eq!(
            upstream.url(&CALLBACK),
            format!("https://lib.id{ARTIFACT_PATH}"),
            "a default port is not part of the URL the client dials"
        );
        assert_eq!(
            upstream.url(&VERSIONS),
            format!("https://lib.id{VERSIONS_PATH}")
        );
    }
}
