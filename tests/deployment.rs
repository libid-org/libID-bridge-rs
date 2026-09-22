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
        assert_eq!(p[0].id(), PlatformId::Github);
        assert_eq!(p[0].client_id(), "Iv1.0");
        assert_eq!(p[0].versions(), [1]);
        assert_eq!(p[0].client_credential(), Some("c0ffee"));
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

    /// An underscore in a host is admitted; the bytes a Content-Security-Policy
    /// reads as syntax are refused.
    #[test]
    fn an_underscore_in_a_host_is_an_origin_like_any_other() {
        for spelling in [
            "https://dev_box.example",
            "https://app_staging.example:8443",
        ] {
            assert!(Origin::parse("T", spelling).is_ok(), "{spelling}");
        }
        for hostile in ["https://a;b.example", "https://a'b.example"] {
            assert!(Origin::parse("T", hostile).is_err(), "{hostile}");
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
        config::Config,
        deployment::PlatformId,
        error::Result,
    };

    /// Write a configuration file and resolve against it, with no environment
    /// variable reaching a flag: what the file supplies is what this test
    /// wrote, whatever the machine running it exports.
    fn resolved(toml: &str, flags: &[&str]) -> Result<Config> {
        let file = crate::common::ScratchFile::holding(toml);
        resolved_file(file.path(), flags)
    }

    /// The configuration `path` describes, with `flags` on the command line.
    fn resolved_file(path: &std::path::Path, flags: &[&str]) -> Result<Config> {
        let mut argv = vec![
            "libid-server-rs".to_owned(),
            "--config".to_owned(),
            path.display().to_string(),
        ];
        argv.extend(flags.iter().map(|f| (*f).to_owned()));
        Config::merged(Config::command().mut_args(|a| a.env(None::<&str>)), argv)
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
            &[],
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
        assert_eq!(platforms[0].client_id(), "Iv1.0123456789abcdef");
        assert_eq!(
            platforms[0].client_credential(),
            Some("c0ffee_from_the_file")
        );
    }

    /// A `github` table without its credential is refused, with the missing
    /// key named.
    #[test]
    fn a_github_table_without_its_credential_is_refused() {
        let err = resolved(
            r#"
            [[platforms]]
            id = "github"
            client_id = "Iv1.0123456789abcdef"
            versions = [1]
            "#,
            &[],
        )
        .expect_err("no credential");
        assert!(err.to_string().contains("client_credential"), "{err}");
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
            &[],
        )
        .expect("a file this deployment can read");
        let platforms = libid_server_rs::deployment::platforms(cfg.platforms)
            .expect("the records the table describes");
        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0].id(), PlatformId::X);
        assert_eq!(platforms[0].client_id(), "WHRlc3RjbGllbnQ6MTpjaQ");
        assert_eq!(platforms[0].versions(), [1]);
        assert!(platforms[0].client_credential().is_none());
    }

    /// A flag beats the file.
    #[test]
    fn the_command_line_beats_the_file() {
        let cfg = resolved(
            "ccdp_origin = \"https://dist.example\"\n",
            &["--ccdp-origin", "https://other.example"],
        )
        .expect("a file this deployment can read");
        assert_eq!(cfg.ccdp_origin, "https://other.example");
    }

    /// Where neither says anything, the default stands.
    #[test]
    fn a_silent_file_changes_nothing() {
        let cfg = resolved("allowed_app_origins = [\"https://app.example\"]\n", &[])
            .expect("readable");
        assert_eq!(cfg.ccdp_origin, "https://lib.id");
    }

    /// A file with no `[[platforms]]` table enables no platform, which the
    /// platform check refuses by name.
    #[test]
    fn no_platform_table_means_no_platform() {
        let cfg = resolved("allowed_app_origins = [\"https://app.example\"]\n", &[])
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
        let cfg = resolved_file(std::path::Path::new(path), &[])
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
            .find(|p| p.id() == PlatformId::Github)
            .expect("the example enables github");
        assert!(github.client_credential().is_some());
    }

    /// A run that names no file is told that, not that the platforms the
    /// file would have carried are missing.
    #[test]
    fn a_run_that_names_no_file_is_told_so() {
        let err = Config::merged(
            Config::command().mut_args(|a| a.env(None::<&str>)),
            ["libid-server-rs"],
        )
        .expect_err("no configuration file");
        let text = err.to_string();
        assert!(text.contains("LIBID_CONFIG"), "{text}");
        assert!(text.contains("--config"), "{text}");
    }

    /// A misspelled key is refused rather than ignored.
    #[test]
    fn a_misspelled_key_is_refused() {
        let err = resolved("prot = 9110\n", &[]).expect_err("an unknown key");
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
            let err = resolved(unread, &[]).expect_err("a key this bridge does not read");
            let key = unread.split(' ').next().unwrap();
            assert!(err.to_string().contains(key), "{err}");
        }
    }
}
