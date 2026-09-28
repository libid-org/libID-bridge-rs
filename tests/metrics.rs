//! What this deployment counts.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

mod metrics {
    use libid_bridge_rs::{
        artifact::upstream::Resource,
        metrics::*,
    };

    /// A deployment that has retrieved nothing says so of each resource, and
    /// invents no counter it has not reached.
    #[test]
    fn a_deployment_that_retrieved_nothing_says_so() {
        let empty = Metrics::new().rendered();
        for line in [
            "libid_bridge_available{resource=\"callback\"} 0",
            "libid_bridge_available{resource=\"versions\"} 0",
            "libid_bridge_published_timestamp_seconds{resource=\"callback\"} 0",
            "libid_bridge_published_timestamp_seconds{resource=\"versions\"} 0",
        ] {
            assert!(empty.contains(line), "{line} missing from:\n{empty}");
        }
        assert!(!empty.contains("libid_bridge_retrievals_total"), "{empty}");
        assert!(
            !empty.contains("libid_bridge_retrieval_failures_total"),
            "{empty}"
        );
        assert!(empty.ends_with("# EOF\n"), "{empty}");
    }

    /// Every outcome is counted under its own name, per resource.
    #[test]
    fn the_rendering_names_every_metric() {
        let metrics = Metrics::new();

        metrics.published(Resource::Callback);
        metrics.unchanged(Resource::Callback);
        metrics.failed(Resource::Callback, "unreachable");
        metrics.published(Resource::Versions);
        metrics.failed(Resource::Versions, "grammar");
        metrics.callback_served();
        metrics.callback_unavailable();

        let text = metrics.rendered();
        for line in [
            "libid_bridge_retrievals_total{resource=\"callback\",outcome=\"published\"} 1",
            "libid_bridge_retrievals_total{resource=\"callback\",outcome=\"unchanged\"} 1",
            "libid_bridge_retrievals_total{resource=\"callback\",outcome=\"failed\"} 1",
            "libid_bridge_retrievals_total{resource=\"versions\",outcome=\"published\"} 1",
            "libid_bridge_retrievals_total{resource=\"versions\",outcome=\"failed\"} 1",
            "libid_bridge_retrieval_failures_total{resource=\"callback\",kind=\"unreachable\"} 1",
            "libid_bridge_retrieval_failures_total{resource=\"versions\",kind=\"grammar\"} 1",
            "libid_bridge_callback_requests_total{outcome=\"document\"} 1",
            "libid_bridge_callback_requests_total{outcome=\"unavailable\"} 1",
            "libid_bridge_available{resource=\"callback\"} 1",
            "libid_bridge_available{resource=\"versions\"} 1",
        ] {
            assert!(text.contains(line), "{line} missing from:\n{text}");
        }
        for resource in ["callback", "versions"] {
            let prefix = format!(
                "libid_bridge_published_timestamp_seconds{{resource=\"{resource}\"}} "
            );
            let stamped = text
                .lines()
                .find(|l| l.starts_with(&prefix))
                .unwrap_or_else(|| panic!("{prefix} missing from:\n{text}"));
            assert_ne!(stamped, format!("{prefix}0"), "{resource} was published");
        }
    }

    /// A resource's gauges move on its own retrievals alone.
    #[test]
    fn each_resource_is_gauged_on_its_own() {
        let metrics = Metrics::new();
        metrics.published(Resource::Versions);
        let text = metrics.rendered();
        assert!(
            text.contains("libid_bridge_available{resource=\"callback\"} 0"),
            "{text}"
        );
        assert!(
            text.contains("libid_bridge_available{resource=\"versions\"} 1"),
            "{text}"
        );
        assert!(
            text.contains(
                "libid_bridge_published_timestamp_seconds{resource=\"callback\"} 0"
            ),
            "{text}"
        );
    }
}
