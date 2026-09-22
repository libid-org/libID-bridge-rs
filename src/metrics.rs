//! What this deployment counts: how the callback artifact's retrievals went,
//! whether a document is available to serve, and what the callback route
//! answered.
//!
//! The Distribution is a separate deployment, so the numbers that matter are
//! how long this bridge has been serving a document it could not replace and
//! how often it had none at all.

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

/// How one retrieval ended.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Retrieval {
    /// `published`, `unchanged` or `failed`.
    outcome: &'static str,
}

/// Why a retrieval produced no document.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Failure {
    /// The short name of the refusal.
    kind: &'static str,
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
    /// One per retrieval, by how it ended.
    retrievals: Family<Retrieval, Counter>,
    /// One per retrieval that produced no document, by why.
    failures: Family<Failure, Counter>,
    /// One per callback request, by what it was answered with.
    callbacks: Family<Callback, Counter>,
    /// `1` while a document is available to serve, `0` before the first one
    /// arrives.
    available: Gauge,
    /// When a document was last published, in seconds since the epoch, or
    /// `0` before the first one.
    published_at: Gauge,
}

impl Default for Metrics {
    fn default() -> Metrics {
        Metrics::new()
    }
}

impl Metrics {
    /// A registry carrying every metric, each already registered.
    pub fn new() -> Metrics {
        let mut registry = <Registry>::with_prefix("libid_bridge");
        let retrievals = Family::<Retrieval, Counter>::default();
        let failures = Family::<Failure, Counter>::default();
        let callbacks = Family::<Callback, Counter>::default();
        let available = Gauge::default();
        let published_at = Gauge::default();

        registry.register(
            "artifact_retrievals",
            "Retrievals of the callback artifact, by how each ended",
            retrievals.clone(),
        );
        registry.register(
            "artifact_retrieval_failures",
            "Retrievals that produced no document, by why",
            failures.clone(),
        );
        registry.register(
            "callback_requests",
            "Requests for the callback document, by what each was answered with",
            callbacks.clone(),
        );
        registry.register(
            "callback_document_available",
            "Whether a callback document is available to serve",
            available.clone(),
        );
        registry.register(
            "callback_document_published_timestamp_seconds",
            "When the served callback document was published",
            published_at.clone(),
        );

        Metrics {
            registry,
            retrievals,
            failures,
            callbacks,
            available,
            published_at,
        }
    }

    /// A retrieval published a document, replacing whatever was served.
    pub fn published(&self) {
        self.count(&self.retrievals, "published");
        self.available.set(1);
        self.published_at.set(unix_seconds());
    }

    /// A retrieval found the served document to be current.
    pub fn unchanged(&self) {
        self.count(&self.retrievals, "unchanged")
    }

    /// A retrieval produced no document. Whatever was served stays.
    pub fn failed(&self, kind: &'static str) {
        self.count(&self.retrievals, "failed");
        self.failures.get_or_create(&Failure { kind }).inc();
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

    /// One retrieval outcome.
    fn count(&self, family: &Family<Retrieval, Counter>, outcome: &'static str) {
        family.get_or_create(&Retrieval { outcome }).inc();
    }
}

/// Now, in seconds since the epoch. A clock before the epoch reads as `0`.
fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}
