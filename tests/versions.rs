//! The Distribution's version list: what is accepted, and what refuses the whole of it.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

mod versions {
    use libid_bridge_rs::{
        deployment::PlatformId,
        versions::*,
    };

    fn parsed(text: &str) -> Result<Versions, VersionsError> {
        Versions::parse(text.as_bytes())
    }

    /// The list a Distribution's build writes is accepted, each known
    /// platform with its versions as listed.
    #[test]
    fn a_well_formed_list_is_accepted() {
        let list = parsed(r#"{"github":[1],"google":[1,2],"x":[3,7,65535]}"#).unwrap();
        assert_eq!(list.bundled_for(PlatformId::Github), Some(&[1][..]));
        assert_eq!(list.bundled_for(PlatformId::Google), Some(&[1, 2][..]));
        assert_eq!(list.bundled_for(PlatformId::X), Some(&[3, 7, 65535][..]));
    }

    /// Zero is an unsigned 16-bit integer, and whitespace is JSON's to
    /// ignore.
    #[test]
    fn zero_is_a_version() {
        let list = parsed("{ \"github\" : [ 0 , 1 ] }\n").unwrap();
        assert_eq!(list.bundled_for(PlatformId::Github), Some(&[0, 1][..]));
    }

    /// A platform the list does not name is bundled nowhere; a list naming
    /// no platform this bridge knows is still a list.
    #[test]
    fn a_platform_the_list_does_not_name_has_no_versions() {
        let list = parsed(r#"{"github":[1]}"#).unwrap();
        assert_eq!(list.bundled_for(PlatformId::X), None);
        assert_eq!(list.bundled_for(PlatformId::Google), None);

        let none = parsed("{}").unwrap();
        for platform in [PlatformId::Github, PlatformId::Google, PlatformId::X] {
            assert_eq!(none.bundled_for(platform), None, "{platform}");
        }
    }

    /// A key this bridge does not know is ignored, whatever its value: a
    /// Distribution may bundle a platform this bridge predates. A key is
    /// known by its exact spelling.
    #[test]
    fn an_unknown_platform_key_is_ignored_whatever_its_value() {
        let known = parsed(r#"{"github":[1]}"#).unwrap();
        for text in [
            r#"{"github":[1],"tiktok":[1]}"#,
            r#"{"github":[1],"tiktok":"soon"}"#,
            r#"{"github":[1],"tiktok":[]}"#,
            r#"{"github":[1],"tiktok":[2,1,1]}"#,
            r#"{"github":[1],"GitHub":[2]}"#,
            r#"{"github":[1],"":null}"#,
        ] {
            let list = parsed(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(list, known, "{text}");
        }
    }

    /// Key order carries no meaning.
    #[test]
    fn key_order_carries_no_meaning() {
        assert_eq!(
            parsed(r#"{"x":[1],"github":[2],"google":[3]}"#).unwrap(),
            parsed(r#"{"google":[3],"github":[2],"x":[1]}"#).unwrap()
        );
    }

    /// Anything that is not JSON, or not a JSON object, refuses the list.
    #[test]
    fn a_body_that_is_not_an_object_is_refused() {
        for text in ["", "not json", "{\"github\":[1]", "{\"github\":[1]}}"] {
            let refusal = parsed(text).expect_err(text);
            assert!(
                matches!(refusal, VersionsError::Json(_)),
                "{text}: {refusal}"
            );
        }
        for text in [
            "[]",
            "1",
            "\"github\"",
            "null",
            "true",
            "[{\"github\":[1]}]",
        ] {
            assert_eq!(
                parsed(text).expect_err(text),
                VersionsError::NotAnObject,
                "{text}"
            );
        }
    }

    /// Each of these refuses the whole list, the well-formed platforms in it
    /// included, and the refusal names the platform at fault.
    #[test]
    fn a_violation_refuses_the_whole_list() {
        use VersionsError::*;
        let x = PlatformId::X;
        for (text, expected) in [
            (r#"{"github":[1],"x":1}"#, NotAnArray { platform: x }),
            (r#"{"github":[1],"x":"1"}"#, NotAnArray { platform: x }),
            (
                r#"{"github":[1],"x":{"1":true}}"#,
                NotAnArray { platform: x },
            ),
            (r#"{"github":[1],"x":null}"#, NotAnArray { platform: x }),
            (r#"{"github":[1],"x":[]}"#, Empty { platform: x }),
            (
                r#"{"github":[1],"x":[-1]}"#,
                NotAVersion {
                    platform: x,
                    found: "-1".into(),
                },
            ),
            (
                r#"{"github":[1],"x":[1.5]}"#,
                NotAVersion {
                    platform: x,
                    found: "1.5".into(),
                },
            ),
            (
                r#"{"github":[1],"x":[1.0]}"#,
                NotAVersion {
                    platform: x,
                    found: "1.0".into(),
                },
            ),
            (
                r#"{"github":[1],"x":[65536]}"#,
                NotAVersion {
                    platform: x,
                    found: "65536".into(),
                },
            ),
            (
                r#"{"github":[1],"x":[1e2]}"#,
                NotAVersion {
                    platform: x,
                    found: "100.0".into(),
                },
            ),
            (
                r#"{"github":[1],"x":["1"]}"#,
                NotAVersion {
                    platform: x,
                    found: "a string".into(),
                },
            ),
            (
                r#"{"github":[1],"x":[true]}"#,
                NotAVersion {
                    platform: x,
                    found: "a boolean".into(),
                },
            ),
            (
                r#"{"github":[1],"x":[null]}"#,
                NotAVersion {
                    platform: x,
                    found: "null".into(),
                },
            ),
            (
                r#"{"github":[1],"x":[[1]]}"#,
                NotAVersion {
                    platform: x,
                    found: "an array".into(),
                },
            ),
            (
                r#"{"github":[1],"x":[{"version":1}]}"#,
                NotAVersion {
                    platform: x,
                    found: "an object".into(),
                },
            ),
            (
                r#"{"github":[1],"x":[1,1]}"#,
                Duplicate {
                    platform: x,
                    version: 1,
                },
            ),
            (
                r#"{"github":[1],"x":[1,2,2]}"#,
                Duplicate {
                    platform: x,
                    version: 2,
                },
            ),
            (r#"{"github":[1],"x":[2,1]}"#, Unordered { platform: x }),
            (r#"{"github":[1],"x":[1,3,2]}"#, Unordered { platform: x }),
            (r#"{"github":[1],"x":[1,2,1]}"#, Unordered { platform: x }),
        ] {
            assert_eq!(parsed(text).expect_err(text), expected, "{text}");
        }
    }

    /// A refusal names the platform and the number at fault, and never echoes
    /// a string: a value the length of the body stays out of the log.
    #[test]
    fn a_refusal_names_the_platform_and_never_echoes_a_string() {
        let refusal = parsed(r#"{"x":["zzMarkerzz"]}"#).unwrap_err().to_string();
        assert!(refusal.contains("x"), "{refusal}");
        assert!(refusal.contains("a string"), "{refusal}");
        assert!(!refusal.contains("zzMarkerzz"), "{refusal}");

        let refusal = parsed(r#"{"github":[70000]}"#).unwrap_err().to_string();
        assert!(refusal.contains("github"), "{refusal}");
        assert!(refusal.contains("70000"), "{refusal}");
    }

    /// The list displays each platform it names with its versions, and says
    /// so when it names none.
    #[test]
    fn the_list_displays_what_it_names() {
        let shown = parsed(r#"{"x":[1],"github":[1,2]}"#).unwrap().to_string();
        assert!(shown.contains("x=[1]"), "{shown}");
        assert!(shown.contains("github=[1, 2]"), "{shown}");
        assert!(!shown.contains("google"), "{shown}");
        assert_eq!(parsed("{}").unwrap().to_string(), "<none>");
    }
}
