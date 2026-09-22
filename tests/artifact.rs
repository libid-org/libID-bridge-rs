//! Composing the callback document, and reading the policy an artifact arrived under.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

mod artifact {
    use libid_server_rs::{
        artifact::{
            policy::ArtifactError,
            *,
        },
        origin::Origin,
    };

    use crate::common::ARTIFACT as FIXTURE;

    fn origin(spelling: &str) -> Origin {
        Origin::parse("T", spelling).unwrap()
    }

    fn origins() -> Vec<Origin> {
        vec![
            origin("https://app.example"),
            origin("https://ccdp.example"),
        ]
    }

    fn compose(html: &str) -> Result<CallbackDocument, ArtifactError> {
        CallbackDocument::compose(
            html,
            &crate::common::artifact_hashes(),
            &DeploymentInputs {
                ccdp_origin: &origin("https://ccdp.example"),
                allowed_origins: &origins(),
            },
        )
    }

    fn text(doc: &CallbackDocument) -> String {
        String::from_utf8(doc.body.to_vec()).unwrap()
    }

    /// The artifact a live Distribution serves composes, and what is served
    /// carries the deployment's data where the marker was.
    #[test]
    fn the_artifact_of_a_live_distribution_composes() {
        let served = text(&compose(FIXTURE).unwrap());
        assert!(!served.contains(policy::MARKER));
        assert!(served.contains(
            r#"[["https://app.example","https://ccdp.example"],"https://ccdp.example"]"#
        ));
    }

    /// Only the marker changes: every other byte of the artifact is served as
    /// it arrived, so no byte a declared hash covers moves.
    #[test]
    fn substitution_touches_only_the_marker() {
        let served = text(&compose(FIXTURE).unwrap());
        let at = FIXTURE.find(policy::MARKER).unwrap();
        assert_eq!(&served[..at], &FIXTURE[..at]);
        let after = at + policy::MARKER.len();
        assert_eq!(
            &served[served.len() - (FIXTURE.len() - after)..],
            &FIXTURE[after..]
        );
    }

    /// A document with no marker, or with more than one, is refused rather
    /// than filled in twice.
    #[test]
    fn a_document_without_exactly_one_marker_is_refused() {
        for (html, count) in [
            ("<html><body>nothing to fill</body></html>", 0),
            (
                "<html>__LIBID_CALLBACK_CONFIG__ __LIBID_CALLBACK_CONFIG__</html>",
                2,
            ),
        ] {
            assert_eq!(
                compose(html).map(|_| ()).unwrap_err(),
                ArtifactError::Markers(count)
            );
        }
    }

    /// The policy names the hashes the artifact arrived with, admits a frame
    /// only from the configured Distribution, and admits no connection.
    #[test]
    fn the_policy_carries_the_hashes_and_this_deployments_sources() {
        let doc = compose(FIXTURE).unwrap();
        let csp = doc.csp.to_str().unwrap();
        assert!(csp.starts_with(
            "default-src 'none'; object-src 'none'; base-uri 'none'; \
             form-action 'none'; frame-ancestors 'none'"
        ));
        for source in crate::common::artifact_hashes() {
            assert!(csp.contains(&source), "{csp}");
        }
        assert!(csp.contains("frame-src https://ccdp.example"));
        assert!(csp.contains("connect-src 'none'"));
        assert!(!csp.contains("'unsafe-eval'"));
        assert!(!csp.contains("'unsafe-inline'; script"), "{csp}");
    }

    /// Inserted data leaves as ASCII with no character a parser reads as
    /// markup, whatever the deployment is called.
    #[test]
    fn inserted_data_cannot_be_read_as_markup() {
        let rendered = json(&serde_json::json!(["</script><script>", "\u{2028}\u{e9}"]));
        assert!(rendered.is_ascii());
        for forbidden in ['<', '>', '&'] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
        assert!(rendered.contains("\\u003c"));
    }
}

mod policy {
    use libid_server_rs::artifact::policy::*;

    #[allow(unused_imports)]
    use crate::common;

    /// The hashes of a `script-src` are read in the order the policy names
    /// them, whichever directive order it uses.
    #[test]
    fn the_hashes_of_a_script_src_are_read() {
        let read = script_hashes(
            "default-src 'none'; script-src 'sha256-aaa=' 'sha512-bbb='; style-src 'unsafe-inline'",
        )
        .unwrap();
        assert_eq!(read, ["'sha256-aaa='", "'sha512-bbb='"]);
    }

    /// Every digest the grammar defines is a hash, whatever case it is
    /// written in.
    #[test]
    fn every_digest_algorithm_is_a_hash_in_any_case() {
        for source in [
            "'sha256-aaa='",
            "'sha384-aaa='",
            "'sha512-aaa='",
            "'SHA256-aaa='",
            "'Sha384-aaa='",
        ] {
            assert!(is_hash(source), "{source}");
        }
    }

    /// A source that is not a hash is not one.
    #[test]
    fn a_source_that_is_not_a_hash_is_refused() {
        for source in [
            "'unsafe-inline'",
            "'self'",
            "https://cdn.example",
            "'nonce-abc'",
            "'sha256-'",
            "'sha1-aaa='",
            "sha256-aaa=",
            "'sha256-aa a='",
        ] {
            assert!(!is_hash(source), "{source}");
        }
    }

    /// A policy this bridge cannot serve its document under is refused, and
    /// the refusal names what it found.
    #[test]
    fn a_policy_naming_anything_but_hashes_is_refused() {
        for (policy, expected) in [
            ("default-src 'none'", "names no script-src"),
            ("script-src", "names a script-src with no source"),
            ("script-src 'unsafe-inline'", "and not a hash"),
            ("script-src https://cdn.example", "and not a hash"),
        ] {
            let err = script_hashes(policy).expect_err(policy);
            assert!(err.to_string().contains(expected), "{policy}: {err}");
        }
    }

    /// A policy naming more hashes than are read is refused rather than
    /// truncated.
    #[test]
    fn a_policy_naming_more_hashes_than_are_read_is_refused() {
        let many = (0..=MAX_HASHES)
            .map(|i| format!("'sha256-{i}='"))
            .collect::<Vec<_>>()
            .join(" ");
        let err = script_hashes(&format!("script-src {many}")).unwrap_err();
        assert!(err.to_string().contains("at most"), "{err}");
    }
}
