//! What a deployment must be: its origins, its platforms and where its settings come from.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

mod deployment {
    use libid_server_rs::{
        deployment::*,
        error::{
            Error,
            Result,
        },
    };
    use serde_json::{
        json,
        Value,
    };

    const ONE: &str = r#"[{"id":"github","client_id":"Iv1.0","versions":[1],"client_credential":"c0ffee"}]"#;

    /// Parse records as the configuration file would, then check them.
    fn checked(json: &str) -> Result<Vec<PlatformProfile>> {
        let records: Vec<PlatformProfile> =
            serde_json::from_str(json).map_err(|e| Error::Config {
                detail: e.to_string(),
            })?;
        platforms(records)
    }

    /// One github entry whose `client_credential` is `credential`.
    fn github_with(credential: impl Into<Value>) -> String {
        json!([{
            "id": "github",
            "client_id": "a",
            "versions": [1],
            "client_credential": credential.into(),
        }])
        .to_string()
    }

    #[test]
    fn a_well_formed_set_parses() {
        let p = checked(ONE).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].id, PlatformId::Github);
        assert_eq!(p[0].client_id, "Iv1.0");
        assert_eq!(p[0].versions, [1]);
        assert_eq!(p[0].client_credential.as_deref(), Some("c0ffee"));
    }

    /// The record carries a github entry's credential as
    /// `clientCredential`, and an entry that has none carries no such
    /// key.
    #[test]
    fn the_record_publishes_the_credential_where_there_is_one() {
        let platforms = checked(
            r#"[{"id":"github","client_id":"Iv1.0","versions":[1],"client_credential":"c0ffee"},{"id":"x","client_id":"xc","versions":[2]}]"#,
        )
        .unwrap();
        let ccdp_origin =
            libid_server_rs::origin::Origin::parse("CCDP_ORIGIN", "https://lib.id")
                .unwrap();
        let record: Value = serde_json::from_slice(
            &CeremonyConfig {
                ccdp_origin: &ccdp_origin,
                platforms: &platforms,
            }
            .serialized(),
        )
        .unwrap();

        let github = record["platforms"]["github"].as_object().unwrap();
        let mut keys: Vec<&str> = github.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["ceremonyVersions", "clientCredential", "clientId"]);
        assert_eq!(github["clientCredential"], "c0ffee");

        let x = record["platforms"]["x"].as_object().unwrap();
        let mut keys: Vec<&str> = x.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["ceremonyVersions", "clientId"]);
    }

    /// Each of these is refused at startup.
    #[test]
    fn a_set_this_service_cannot_serve_stops_the_process() {
        let around = |byte: u8| format!("c0f{}fee", char::from(byte));
        for (why, json) in [
            ("empty", "[]".to_owned()),
            (
                "unknown platform",
                r#"[{"id":"twitter","client_id":"a","versions":[1]}]"#.to_owned(),
            ),
            (
                "duplicate platform",
                r#"[{"id":"x","client_id":"a","versions":[1]},{"id":"x","client_id":"b","versions":[1]}]"#.to_owned(),
            ),
            (
                "no versions",
                r#"[{"id":"x","client_id":"a","versions":[]}]"#.to_owned(),
            ),
            (
                "duplicate version",
                r#"[{"id":"x","client_id":"a","versions":[1,1]}]"#.to_owned(),
            ),
            (
                "additional member",
                r#"[{"id":"x","client_id":"a","label":"X","versions":[1]}]"#.to_owned(),
            ),
            (
                "a github entry with no credential",
                r#"[{"id":"github","client_id":"a","versions":[1]}]"#.to_owned(),
            ),
            ("a null credential", github_with(Value::Null)),
            ("a credential that is not a string", github_with(1)),
            ("an empty credential", github_with("")),
            ("a credential carrying a space", github_with(around(b' '))),
            ("a credential carrying a tab", github_with(around(b'\t'))),
            ("a credential carrying a control byte", github_with(around(7))),
            ("a credential carrying DEL", github_with(around(0x7F))),
            ("a credential outside ASCII", github_with(around(0xE9))),
            (
                "a credential on a platform that has none",
                r#"[{"id":"x","client_id":"a","versions":[1],"client_credential":"c0ffee"}]"#.to_owned(),
            ),
        ] {
            assert!(checked(&json).is_err(), "{why} must be refused");
        }
    }

    /// A refusal names the field, never the value.
    #[test]
    fn a_refused_credential_is_named_and_not_quoted() {
        let err =
            checked(&github_with("zzMarkerzz fee")).expect_err("a space is refused");
        let text = err.to_string();
        assert!(text.contains("client_credential"), "{text}");
        assert!(!text.contains("zzMarkerzz"), "{text}");
    }
}

mod origin {
    use libid_server_rs::origin::*;

    /// Whether any of `members` admits `observed`, as the configuration route
    /// reads one `Origin`: the spelling is found canonical once, and one that
    /// is not is admitted by no member.
    fn admits(members: &[Admitted], observed: &str) -> bool {
        Observed::stamped(observed)
            .is_some_and(|observed| members.iter().any(|m| m.admits(observed)))
    }

    /// What a policy source expression can name: letters, digits, `-` and
    /// the `.` between labels, and nothing else.
    #[test]
    fn a_host_a_policy_cannot_name_is_known_for_one() {
        for named in [
            "https://lib.id",
            "https://a-b.example:8443",
            "http://localhost:3000",
        ] {
            assert!(
                Origin::parse("T", named).unwrap().names_a_policy_host(),
                "{named}"
            );
        }
        for unnamed in [
            "https://dev_box.example",
            "https://[::1]:8787",
            "http://127.0.0.1:8787",
        ] {
            let origin = Origin::parse("T", unnamed).unwrap();
            assert_eq!(
                origin.names_a_policy_host(),
                !unnamed.contains('_') && !unnamed.contains('['),
                "{unnamed}"
            );
        }
    }

    /// `parse` folds; `listed` refuses what is not already canonical and names
    /// the spelling to write.
    #[test]
    fn parse_folds_and_listed_refuses_the_unfolded() {
        let folded = Origin::parse("T", "https://Bridge.example:443/").unwrap();
        assert_eq!(folded.as_str(), "https://bridge.example");
        assert_eq!(folded.to_string(), "https://bridge.example");

        let refusal = Origin::listed("T", "https://Bridge.example:443/").unwrap_err();
        assert!(
            refusal
                .to_string()
                .contains("write it as https://bridge.example"),
            "{refusal}"
        );
        assert_eq!(
            Origin::listed("T", "https://bridge.example").unwrap(),
            folded
        );
    }

    /// Plaintext `http` is admitted on exactly `localhost` and `127.0.0.1`,
    /// and refused everywhere else.
    #[test]
    fn plaintext_is_admitted_for_loopback_and_refused_everywhere_else() {
        for spelling in ["http://127.0.0.1:8722", "http://localhost:3000"] {
            assert!(Origin::parse("T", spelling).is_ok(), "{spelling}");
        }
        for spelling in [
            "http://[::1]:8722",
            "http://127.0.0.2:8722",
            "http://10.0.0.1",
            "http://192.168.1.1:8722",
            "http://app.example",
        ] {
            assert!(Origin::parse("T", spelling).is_err(), "{spelling}");
        }
    }

    /// A host the browser side parses is one here too, so the bridge refuses
    /// no origin the browser admits. Only the CCDP origin becomes a policy
    /// source, and `names_a_policy_host` is what holds it to that alphabet.
    #[test]
    fn an_underscore_in_a_host_is_an_origin_like_any_other() {
        for spelling in [
            "https://dev_box.example",
            "https://app_staging.example:8443",
            "https://a;b.example",
            "https://a'b.example",
        ] {
            let origin = Origin::parse("T", spelling)
                .unwrap_or_else(|e| panic!("{spelling}: {e}"));
            assert_eq!(
                origin.names_a_policy_host(),
                !spelling.contains(['_', ';', '\''])
            );
        }
    }

    /// `*` is not a byte an origin is made of, whichever position it takes.
    #[test]
    fn no_origin_spells_a_star() {
        for spelling in [
            "https://*.handles.link",
            "https://*",
            "https://a*b.example",
            "*.handles.link",
            "*",
        ] {
            assert!(Origin::parse("T", spelling).is_err(), "{spelling}");
        }
    }

    /// A well-formed pattern is a member written as it stands, and it
    /// publishes as that spelling.
    #[test]
    fn a_pattern_is_listed_and_published_as_written() {
        let member = Admitted::listed("T", "*.handles.link").unwrap();
        assert!(matches!(member, Admitted::Pattern(_)));
        assert_eq!(member.as_str(), "*.handles.link");
        assert_eq!(member.to_string(), "*.handles.link");
        assert_eq!(
            serde_json::to_string(&member).unwrap(),
            r#""*.handles.link""#
        );
    }

    /// `*` is a member admitting every origin, written as it stands and
    /// published as that spelling.
    #[test]
    fn a_star_admits_every_origin() {
        let member = Admitted::listed("T", "*").unwrap();
        assert!(matches!(member, Admitted::Every));
        assert_eq!(member.as_str(), "*");
        assert_eq!(member.to_string(), "*");
        assert_eq!(serde_json::to_string(&member).unwrap(), r#""*""#);

        let members = [member];
        for observed in [
            "https://anything.example",
            "https://a.b.c.handles.link",
            "https://app.example:8443",
            "http://localhost:3000",
            "http://127.0.0.1:8722",
        ] {
            assert!(admits(&members, observed), "{observed}");
        }
    }

    /// A suffix of one label is a suffix like any other.
    #[test]
    fn a_suffix_of_one_label_is_a_suffix_like_any_other() {
        for (spelling, under, apex) in [
            ("*.com", "https://shop.com", "https://com"),
            ("*.localhost", "https://a.localhost", "https://localhost"),
        ] {
            let members = [Admitted::listed("T", spelling).unwrap()];
            assert!(admits(&members, under), "{under}");
            assert!(!admits(&members, apex), "{apex}");
        }
    }

    /// A member beginning `*.` is an origin pattern, and one that is not
    /// well formed is refused by name rather than read as an origin.
    #[test]
    fn a_malformed_pattern_is_refused_rather_than_read_as_an_origin() {
        for spelling in [
            // A suffix is DNS labels: no scheme, no port, no path, no query,
            // no fragment, no credentials.
            "https://*.handles.link",
            "http://*.handles.link",
            "*.handles.link:8443",
            "*.handles.link/",
            "*.handles.link/path",
            "*.handles.link?q=1",
            "*.handles.link#f",
            "*.user@handles.link",
            // A browser stamps a host lowercase, and no label carries an
            // underscore.
            "*.HANDLES.link",
            "*._a.handles.link",
            // A hyphen lives inside a label, never at either end.
            "*.-a.handles.link",
            "*.a-.handles.link",
            // Every label carries something, and the suffix ends where the
            // spelling does.
            "*.handles.link.",
            "*..handles.link",
            "*..",
            "*.",
            // One `*`, in the one position a pattern spells it.
            "*.*.handles.link",
            "*handles.link",
        ] {
            let refusal = Admitted::listed("FIELD", spelling).unwrap_err();
            assert!(
                refusal.to_string().contains("FIELD"),
                "{spelling}: {refusal}"
            );
        }
    }

    /// An exact member admits its own spelling and nothing else: neither a
    /// subdomain of it nor a near miss of it.
    #[test]
    fn an_exact_member_admits_only_itself() {
        let members = [Admitted::listed("T", "https://app.example").unwrap()];
        assert!(admits(&members, "https://app.example"));
        for other in [
            "https://sub.app.example",
            "https://APP.example",
            "https://app.example/",
            "https://app.example:8443",
        ] {
            assert!(!admits(&members, other), "{other}");
        }
    }

    /// A host the browser side calls canonical is one here too. Only the CCDP
    /// origin becomes a policy source, and only it is held to the alphabet a
    /// source expression can carry.
    #[test]
    fn a_host_a_policy_could_not_carry_is_an_application_origin_like_any_other() {
        for spelling in [
            "https://a'b.example",
            "https://a;b.example",
            "https://a~b.example",
            "https://a$b.example",
        ] {
            let member = Admitted::listed("T", spelling)
                .unwrap_or_else(|e| panic!("{spelling} must be a member: {e}"));
            assert_eq!(member.as_str(), spelling);
            let observed = Observed::stamped(spelling)
                .unwrap_or_else(|| panic!("{spelling} must be an observed origin"));
            assert!(member.admits(observed));
            assert!(
                !Origin::parse("CCDP_ORIGIN", spelling)
                    .is_ok_and(|o| o.names_a_policy_host()),
                "{spelling} must not name a policy host"
            );
        }
    }

    /// Every depth under the suffix is admitted, and both ends are anchored.
    /// These rows are the browser's, run against `isAllowedOrigin`: the two
    /// sides admit the same origins or a ceremony waits on a peer that never
    /// matches.
    #[test]
    fn a_pattern_admits_every_depth_under_its_suffix_and_nothing_else() {
        let members = [Admitted::listed("T", "*.handles.link").unwrap()];
        for (observed, wanted) in [
            ("https://improve-account-linking.handles.link", true),
            // The depth above the suffix is unbounded.
            ("https://a.b.c.d.e.handles.link", true),
            ("https://x_y.handles.link", true),
            ("https://xn--80ak6aa92e.handles.link", true),
            // An empty label is a label: the dot is where the suffix begins.
            ("https://.handles.link", true),
            // The apex carries nothing under the suffix.
            ("https://handles.link", false),
            ("http://x.handles.link", false),
            // The port falls inside the compared slice.
            ("https://x.handles.link:8443", false),
            // The label boundary, and the end of the host.
            ("https://evilhandles.link", false),
            ("https://handles.link.evil.test", false),
            // A trailing dot names a different host.
            ("https://x.handles.link.", false),
            // A browser stamps a lowercase host.
            ("https://X.handles.link", false),
        ] {
            assert_eq!(admits(&members, observed), wanted, "{observed}");
        }
    }

    /// No public suffix list is consulted, and none is to be added: telling
    /// `*.vercel.app` from `*.handles.link` needs one, and that list is a
    /// worse liability here than the case it would prevent. A pattern places
    /// the whole subdomain namespace of its suffix, at every depth, inside
    /// the trust boundary, and the operator writing one asserts control of
    /// it.
    #[test]
    fn a_public_suffix_is_a_suffix_like_any_other() {
        for (spelling, under, apex) in [
            ("*.co.uk", "https://shop.co.uk", "https://co.uk"),
            (
                "*.vercel.app",
                "https://preview.vercel.app",
                "https://vercel.app",
            ),
        ] {
            let members = [Admitted::listed("T", spelling).unwrap()];
            assert!(admits(&members, under), "{under}");
            assert!(!admits(&members, apex), "{apex}");
        }
    }

    /// There is no address pattern, and so no loopback pattern: the last
    /// label of a suffix begins with a letter, and no form of an address
    /// ends in one.
    #[test]
    fn no_pattern_names_an_address() {
        for spelling in [
            "*.127.0.0.1",
            "*.10.0.0.1",
            "*.0x7f.1",
            "*.2130706433",
            "*.[::1]",
            "*.::1",
            "*.[::ffff:127.0.0.1]",
        ] {
            let refusal = Admitted::listed("FIELD", spelling).unwrap_err();
            assert!(
                refusal.to_string().contains("FIELD"),
                "{spelling}: {refusal}"
            );
        }
    }

    /// A refusal names what is actually wrong, so an operator is not sent
    /// after the wrong mistake.
    #[test]
    fn a_refusal_names_what_is_wrong_with_the_spelling() {
        for (spelling, why) in [
            ("*.handles.link:443", "outside the lowercase DNS alphabet"),
            ("*.HANDLES.link", "outside the lowercase DNS alphabet"),
            ("*.-a.handles.link", "begins or ends with a hyphen"),
            ("*.", "an empty label"),
            ("*.127.0.0.1", "does not begin with a letter"),
            (
                "https://*.handles.link",
                "carries a * and is not an origin pattern",
            ),
        ] {
            let refusal = Admitted::listed("FIELD", spelling).unwrap_err().to_string();
            assert!(refusal.contains(why), "{spelling}: {refusal}");
        }
    }

    /// A member's own spelling is not an origin a browser stamps. Offered as
    /// one it is refused whichever members the allowlist carries, `*` among
    /// them, so it never becomes a bound origin.
    #[test]
    fn a_member_spelling_is_never_an_observed_origin() {
        let members = [
            Admitted::listed("T", "*.handles.link").unwrap(),
            Admitted::listed("T", "https://app.example").unwrap(),
            Admitted::listed("T", "*").unwrap(),
        ];
        for observed in ["*.handles.link", "*", "*.*", "https://*.handles.link"] {
            assert!(!admits(&members, observed), "{observed}");
        }
    }

    /// Anything but a bare `http`/`https` origin with a host is refused,
    /// naming the field.
    #[test]
    fn what_is_not_a_bare_origin_is_refused() {
        for spelling in [
            "not an origin",
            "",
            "https://",
            "file:///etc/passwd",
            // Special schemes with a known default port, which `Url` drops.
            "ftp://dist.example",
            "ws://dist.example",
            "https://app.example/path",
            "https://app.example/?q=1",
            "https://app.example/#f",
            "https://user@app.example",
        ] {
            let refusal = Origin::parse("FIELD", spelling).unwrap_err();
            assert!(
                refusal.to_string().contains("FIELD"),
                "{spelling}: {refusal}"
            );
        }
    }
}

mod config {
    use clap::CommandFactory as _;
    use libid_server_rs::{
        config::{
            Cli,
            Settings,
        },
        deployment::PlatformId,
        error::Result,
    };

    /// The deployment a file describes.
    fn resolved(toml: &str) -> Result<Settings> {
        let file = crate::common::ScratchFile::holding(toml);
        Settings::read(file.path())
    }

    /// What an invocation names, with no environment variable reaching a
    /// flag: what this test passes is what is read, whatever the machine
    /// running it exports.
    fn invoked(flags: &[&str]) -> Result<Cli> {
        let mut argv = vec!["libid-server-rs".to_owned()];
        argv.extend(flags.iter().map(|f| (*f).to_owned()));
        Cli::parsed_by(Cli::command().mut_args(|a| a.env(None::<&str>)), argv)
    }

    /// A file supplies what nothing else did, the platform table included.
    #[test]
    fn a_file_supplies_what_no_flag_and_no_variable_named() {
        let cfg = resolved(
            r#"
            ccdp_origin = "https://dist.example"
            allowed_app_origins = ["https://app.example", "https://wallet.example"]

            [[platforms]]
            id = "github"
            client_id = "Iv1.0123456789abcdef"
            versions = [1]
            client_credential = "c0ffee_from_the_file"
            "#,
        )
        .expect("a file this deployment can read");

        assert_eq!(cfg.ccdp_origin, "https://dist.example");
        assert_eq!(
            cfg.allowed_app_origins,
            ["https://app.example", "https://wallet.example"]
        );
        let platforms = libid_server_rs::deployment::platforms(cfg.platforms)
            .expect("the records the table describes");
        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0].client_id, "Iv1.0123456789abcdef");
        assert_eq!(
            platforms[0].client_credential.as_deref(),
            Some("c0ffee_from_the_file")
        );
    }

    /// A `github` table without its credential is refused, with the missing
    /// key named.
    #[test]
    fn a_credential_belongs_to_the_ceremonies_that_send_one() {
        // The table parses either way: whether a platform carries one is a
        // rule about the deployment, not a shape the file has to take.
        let without = resolved(
            r#"
            [[platforms]]
            id = "github"
            client_id = "Iv1.0123456789abcdef"
            versions = [1]
            "#,
        )
        .expect("a table with no credential is still a table");
        let err = libid_server_rs::deployment::platforms(without.platforms)
            .expect_err("github's ceremony sends one");
        assert!(err.to_string().contains("client_credential"), "{err}");

        let spurious = resolved(
            r#"
            [[platforms]]
            id = "x"
            client_id = "XXXXXXXXXXXXXXXXXXXXXXXXXX"
            versions = [1]
            client_credential = "c0ffee"
            "#,
        )
        .expect("a table carrying one is still a table");
        let err = libid_server_rs::deployment::platforms(spurious.platforms)
            .expect_err("x's ceremony sends none");
        assert!(err.to_string().contains("sends none"), "{err}");
    }

    /// An `x` table carries a client id and versions and no credential.
    #[test]
    fn an_x_table_is_a_public_client_with_no_credential() {
        let cfg = resolved(
            r#"
            [[platforms]]
            id = "x"
            client_id = "WHRlc3RjbGllbnQ6MTpjaQ"
            versions = [1]
            "#,
        )
        .expect("a file this deployment can read");
        let platforms = libid_server_rs::deployment::platforms(cfg.platforms)
            .expect("the records the table describes");
        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0].id, PlatformId::X);
        assert_eq!(platforms[0].client_id, "WHRlc3RjbGllbnQ6MTpjaQ");
        assert_eq!(platforms[0].versions, [1]);
        assert!(platforms[0].client_credential.as_deref().is_none());
    }

    /// A flag beats the file.
    #[test]
    fn the_file_is_the_only_place_the_deployment_is_written() {
        // Nothing but the file names a Distribution, so there is no second
        // spelling to disagree with it.
        for flag in ["--ccdp-origin", "--allowed-app-origins", "--platforms"] {
            let command = Cli::command();
            assert!(
                !command
                    .get_arguments()
                    .any(|a| a.get_long() == Some(flag.trim_start_matches("--"))),
                "{flag} is still a flag"
            );
        }

        let cfg = resolved("ccdp_origin = \"https://dist.example\"\n")
            .expect("a file this deployment can read");
        assert_eq!(cfg.ccdp_origin, "https://dist.example");
    }

    /// A file naming no Distribution selects the canonical one.
    #[test]
    fn an_omitted_ccdp_origin_selects_the_canonical_distribution() {
        let cfg = resolved("").expect("an empty file is a readable one");
        assert_eq!(cfg.ccdp_origin, "https://lib.id");
    }

    /// Where neither says anything, the default stands.
    #[test]
    fn a_silent_file_changes_nothing() {
        let cfg = resolved("allowed_app_origins = [\"https://app.example\"]\n")
            .expect("readable");
        assert_eq!(cfg.ccdp_origin, "https://lib.id");
    }

    /// A file with no `[[platforms]]` table enables no platform, which the
    /// platform check refuses by name.
    #[test]
    fn no_platform_table_means_no_platform() {
        let cfg = resolved("allowed_app_origins = [\"https://app.example\"]\n")
            .expect("readable");
        assert!(cfg.platforms.is_empty());
        let err = libid_server_rs::deployment::platforms(cfg.platforms)
            .expect_err("no platform");
        assert!(err.to_string().contains("[[platforms]]"), "{err}");
    }

    /// The example file shipped beside this code is one the code accepts.
    #[test]
    fn the_example_file_is_one_this_bridge_accepts() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bridge.toml.example");
        let cfg = Settings::read(std::path::Path::new(path))
            .expect("the example beside this code");

        assert_eq!(cfg.ccdp_origin, "https://lib.id");
        assert_eq!(
            cfg.allowed_app_origins,
            ["https://app.example", "https://wallet.example"]
        );
        let platforms = libid_server_rs::deployment::platforms(cfg.platforms)
            .expect("the example's platform table");
        let github = platforms
            .iter()
            .find(|p| p.id == PlatformId::Github)
            .expect("the example enables github");
        assert!(github.client_credential.as_deref().is_some());
    }

    /// A run that names no file is told that, not that the platforms the
    /// file would have carried are missing.
    #[test]
    fn a_run_that_names_no_file_is_told_so() {
        let err = invoked(&[])
            .expect("an invocation naming no file still parses")
            .settings()
            .expect_err("but it has no deployment to read");
        let text = err.to_string();
        assert!(text.contains("no configuration file"), "{text}");
        assert!(text.contains("--config"), "{text}");
    }

    /// A misspelled key is refused rather than ignored.
    #[test]
    fn a_misspelled_key_is_refused() {
        let err = resolved("prot = 9110\n").expect_err("an unknown key");
        assert!(err.to_string().contains("prot"), "{err}");
    }

    /// The bind address and port, and the keys of the exchange this bridge
    /// does not perform, are not settings of this file: one naming any of
    /// them is refused like any other unknown key.
    #[test]
    fn a_key_this_bridge_does_not_read_is_refused() {
        for unread in [
            "host = \"0.0.0.0\"\n",
            "port = 8722\n",
            "public_origin = \"https://bridge.example\"\n",
            "notary_wire_port = 7047\n",
            "gh_oauth_client_secret = \"s\"\n",
        ] {
            let err = resolved(unread).expect_err("a key this bridge does not read");
            let key = unread.split(' ').next().unwrap();
            assert!(err.to_string().contains(key), "{err}");
        }
    }
}
