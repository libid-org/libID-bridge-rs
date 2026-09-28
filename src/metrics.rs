//! What this deployment counts: how the retrievals of each resource went,
//! whether each has something to serve, and what the callback route
//! answered.
//!
//! The Distribution is a separate deployment, so the numbers that matter are
//! how long this bridge has been serving a document or a record it could
//! not replace and how often it had none at all.

use prometheus_client::{
    encoding::{
        text::encode,
        EncodeLabelSet,
    },
    metrics::{
        counter::Counter,
        family::Family,
        gauge::Gauge,
    },
    registry::Registry,
};

use strum::IntoEnumIterator;

use crate::artifact::upstream::Resource;

/// How one retrieval ended, and of which resource.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Retrieval {
    /// `callback` or `versions`.
    resource: &'static str,
    /// `published`, `unchanged` or `failed`.
    outcome: &'static str,
}

/// Why a retrieval produced nothing, and of which resource.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Failure {
    /// `callback` or `versions`.
    resource: &'static str,
    /// The short name of the refusal.
    kind: &'static str,
}

/// One resource, for what is kept per resource.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ByResource {
    /// `callback` or `versions`.
    resource: &'static str,
}

/// What the callback route answered.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Callback {
    /// `document` or `unavailable`.
    outcome: &'static str,
}

/// The numbers this deployment publishes, and the registry that renders them.
pub struct Metrics {
    /// The registry every metric below is registered with.
    registry: Registry,
    /// One per retrieval, by resource and how it ended.
    retrievals: Family<Retrieval, Counter>,
    /// One per retrieval that produced nothing, by resource and why.
    failures: Family<Failure, Counter>,
    /// One per callback request, by what it was answered with.
    callbacks: Family<Callback, Counter>,
    /// Per resource, `1` while its product is available to serve, `0`
    /// before the first one arrives.
    available: Family<ByResource, Gauge>,
    /// Per resource, when its product was last published, in seconds since
    /// the epoch, or `0` before the first one.
    published_at: Family<ByResource, Gauge>,
}

impl Default for Metrics {
    fn default() -> Metrics {
        Metrics::new()
    }
}

impl Metrics {
    /// A registry carrying every metric, each already registered, and each
    /// gauge already reading `0` for each resource.
    pub fn new() -> Metrics {
        let mut registry = <Registry>::with_prefix("libid_bridge");
        let retrievals = Family::<Retrieval, Counter>::default();
        let failures = Family::<Failure, Counter>::default();
        let callbacks = Family::<Callback, Counter>::default();
        let available = Family::<ByResource, Gauge>::default();
        let published_at = Family::<ByResource, Gauge>::default();

        registry.register(
            "retrievals",
            "Retrievals from the Distribution, by resource and how each ended",
            retrievals.clone(),
        );
        registry.register(
            "retrieval_failures",
            "Retrievals that produced nothing, by resource and why",
            failures.clone(),
        );
        registry.register(
            "callback_requests",
            "Requests for the callback document, by what each was answered with",
            callbacks.clone(),
        );
        registry.register(
            "available",
            "Whether a resource's product is available to serve: the callback \
             document, or the ceremony configuration composed from the version list",
            available.clone(),
        );
        registry.register(
            "published_timestamp_seconds",
            "When a resource's product was last published",
            published_at.clone(),
        );

        // A gauge that reads `0` from the start says a resource is missing;
        // one that does not exist yet says nothing.
        for resource in Resource::iter() {
            let label = ByResource {
                resource: resource.label(),
            };
            available.get_or_create(&label).set(0);
            published_at.get_or_create(&label).set(0);
        }

        Metrics {
            registry,
            retrievals,
            failures,
            callbacks,
            available,
            published_at,
        }
    }

    /// A retrieval of `resource` published its product, replacing whatever
    /// was served.
    pub fn published(&self, resource: Resource) {
        self.count(resource, "published");
        let label = ByResource {
            resource: resource.label(),
        };
        self.available.get_or_create(&label).set(1);
        self.published_at.get_or_create(&label).set(unix_seconds());
    }

    /// A retrieval of `resource` found what is served to be current.
    pub fn unchanged(&self, resource: Resource) {
        self.count(resource, "unchanged")
    }

    /// A retrieval of `resource` produced nothing. Whatever was served stays.
    pub fn failed(&self, resource: Resource, kind: &'static str) {
        self.count(resource, "failed");
        self.failures
            .get_or_create(&Failure {
                resource: resource.label(),
                kind,
            })
            .inc();
    }

    /// The callback route answered with the document.
    pub fn callback_served(&self) {
        self.callbacks
            .get_or_create(&Callback {
                outcome: "document",
            })
            .inc();
    }

    /// The callback route had no document to answer with.
    pub fn callback_unavailable(&self) {
        self.callbacks
            .get_or_create(&Callback {
                outcome: "unavailable",
            })
            .inc();
    }

    /// Every metric in the Prometheus text exposition format.
    pub fn rendered(&self) -> String {
        let mut out = String::new();
        // The registry is built here and every metric it holds encodes, so a
        // failure would be this crate's own bug rather than a request's.
        encode(&mut out, &self.registry).expect("the registry encodes");
        out
    }

    /// One retrieval outcome of `resource`.
    fn count(&self, resource: Resource, outcome: &'static str) {
        self.retrievals
            .get_or_create(&Retrieval {
                resource: resource.label(),
                outcome,
            })
            .inc();
    }
}

/// Now, in seconds since the epoch. A clock before the epoch reads as `0`.
fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}
