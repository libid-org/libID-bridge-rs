//! The live ceremony suite: a Chrome that authorizes as a person at GitHub,
//! X and Google, a notary of its own, the prover that runs the notarized
//! sessions, and what each platform's records must contain. Built to be lifted
//! out of this repository as a unit: nothing here reaches into the crate
//! under test, and every dependency is declared.

pub mod browser;
pub mod env;
pub mod github;
pub mod google;
pub mod notary;
pub mod prover;
pub mod rungs;
pub mod session;
pub mod settings;
pub mod x;

/// The time since the Unix epoch, by the system clock.
pub fn unix_now() -> std::time::Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock at or after the epoch")
}

/// The runtime the notary's listener runs on. `#[tokio::test]` drops each
/// test's runtime, and every task on it, when the test returns; this one is
/// never dropped.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> =
        std::sync::LazyLock::new(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("a runtime for the notary")
        });
    &RUNTIME
}
