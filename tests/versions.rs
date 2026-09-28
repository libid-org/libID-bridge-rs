//! The Distribution's version list: what is accepted, and what refuses the whole of it.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

mod versions {
    use libid_bridge_rs::{
        deployment::PlatformId,
        versions::*,
    };
    use strum::IntoEnumIterator;

    fn parsed(text: &str) -> serde_json::Result<Versions> {
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
        for platform in PlatformId::iter() {
            assert_eq!(none.bundled_for(platform), None, "{platform}");
        }
    }

    /// A key this bridge does not know is ignored: a Distribution may bundle
    /// a platform this bridge predates. A key is known by its exact
    /// spelling, and its value is held to the grammar like any other.
    #[test]
    fn an_unknown_platform_key_is_ignored() {
        let known = parsed(r#"{"github":[1]}"#).unwrap();
        for text in [
            r#"{"github":[1],"tiktok":[1]}"#,
            r#"{"github":[1],"tiktok":[2,3]}"#,
            r#"{"github":[1],"GitHub":[2]}"#,
            r#"{"github":[1],"":[1]}"#,
        ] {
            let list = parsed(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(list, known, "{text}");
        }
        for text in [
            r#"{"github":[1],"tiktok":"soon"}"#,
            r#"{"github":[1],"tiktok":[]}"#,
            r#"{"github":[1],"tiktok":[2,1,1]}"#,
            r#"{"github":[1],"":null}"#,
        ] {
            assert!(parsed(text).is_err(), "{text}");
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
            assert!(refusal.is_syntax() || refusal.is_eof(), "{text}: {refusal}");
        }
        for text in [
            "[]",
            "1",
            "\"github\"",
            "null",
            "true",
            "[{\"github\":[1]}]",
        ] {
            let refusal = parsed(text).expect_err(text);
            assert!(refusal.is_data(), "{text}: {refusal}");
            assert!(
                refusal.to_string().contains("expected a map"),
                "{text}: {refusal}"
            );
        }
    }

    /// Each of these refuses the whole list, the well-formed platforms in it
    /// included.
    #[test]
    fn a_violation_refuses_the_whole_list() {
        for text in [
            r#"{"github":[1],"x":1}"#,
            r#"{"github":[1],"x":"1"}"#,
            r#"{"github":[1],"x":{"1":true}}"#,
            r#"{"github":[1],"x":null}"#,
            r#"{"github":[1],"x":[]}"#,
            r#"{"github":[1],"x":[-1]}"#,
            r#"{"github":[1],"x":[1.5]}"#,
            r#"{"github":[1],"x":[1.0]}"#,
            r#"{"github":[1],"x":[65536]}"#,
            r#"{"github":[1],"x":[1e2]}"#,
            r#"{"github":[1],"x":["1"]}"#,
            r#"{"github":[1],"x":[true]}"#,
            r#"{"github":[1],"x":[null]}"#,
            r#"{"github":[1],"x":[[1]]}"#,
            r#"{"github":[1],"x":[{"version":1}]}"#,
            r#"{"github":[1],"x":[1,1]}"#,
            r#"{"github":[1],"x":[1,2,2]}"#,
            r#"{"github":[1],"x":[2,1]}"#,
            r#"{"github":[1],"x":[1,3,2]}"#,
            r#"{"github":[1],"x":[1,2,1]}"#,
        ] {
            let refusal = parsed(text).expect_err(text);
            assert!(refusal.is_data(), "{text}: {refusal}");
        }
    }

    /// A refusal names the rule broken and where in the body.
    #[test]
    fn a_refusal_names_the_rule_and_the_place() {
        let refusal = parsed(r#"{"github":[1],"x":[]}"#).unwrap_err().to_string();
        assert!(refusal.contains("lists no version"), "{refusal}");
        assert!(refusal.contains("column"), "{refusal}");

        let refusal = parsed(r#"{"github":[1],"x":[3,2]}"#)
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("version 2 after 3"), "{refusal}");

        let refusal = parsed(r#"{"github":[1],"x":[1,1]}"#)
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("version 1 after 1"), "{refusal}");

        let refusal = parsed(r#"{"github":[70000]}"#).unwrap_err().to_string();
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
