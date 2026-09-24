//! What this deployment counts.

// Each suite uses its part of the module.
#[allow(dead_code)]
mod common;

mod metrics {
    use libid_bridge_rs::metrics::*;

    /// A deployment that has retrieved nothing reports that it is serving
    /// nothing, and invents no counter it has not reached.
    #[test]
    fn a_deployment_that_retrieved_nothing_says_so() {
        let empty = Metrics::new().rendered();
        assert!(
            empty.contains("libid_bridge_callback_document_available 0"),
            "{empty}"
        );
        assert!(empty
            .contains("libid_bridge_callback_document_published_timestamp_seconds 0"));
        assert!(
            !empty.contains("libid_bridge_artifact_retrievals_total"),
            "{empty}"
        );
        assert!(empty.ends_with("# EOF\n"), "{empty}");
    }

    /// Every outcome is counted under its own name.
    #[test]
    fn the_rendering_names_every_metric() {
        let metrics = Metrics::new();

        metrics.published();
        metrics.unchanged();
        metrics.failed("unreachable");
        metrics.callback_served();
        metrics.callback_unavailable();

        let text = metrics.rendered();
        for line in [
            "libid_bridge_artifact_retrievals_total{outcome=\"published\"} 1",
            "libid_bridge_artifact_retrievals_total{outcome=\"unchanged\"} 1",
            "libid_bridge_artifact_retrievals_total{outcome=\"failed\"} 1",
            "libid_bridge_artifact_retrieval_failures_total{kind=\"unreachable\"} 1",
            "libid_bridge_callback_requests_total{outcome=\"document\"} 1",
            "libid_bridge_callback_requests_total{outcome=\"unavailable\"} 1",
            "libid_bridge_callback_document_available 1",
        ] {
            assert!(text.contains(line), "{line} missing from:\n{text}");
        }
        assert!(
            text.contains("libid_bridge_callback_document_published_timestamp_seconds")
        );
    }
}
