//! The environment the suite reads, and its tracing.

/// The settings file, when it is not the `.env.test` found from the working
/// directory upward.
pub const ENV_FILE: &str = "CEREMONY_ENV_FILE";

fn load() {
    match std::env::var(ENV_FILE) {
        Ok(path) => {
            dotenvy::from_path(path).ok();
        }
        Err(_) => {
            dotenvy::from_filename(".env.test").ok();
        }
    }
}

/// The variable `name`, from the environment or from the settings file. An
/// exported value wins over the file. Absent or empty is a panic naming the
/// variable.
pub fn required(name: &str) -> String {
    load();
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => panic!(
            "{name} is required by the live ceremony suite: put it in a gitignored \
             .env.test, or export it. A missing variable fails the suite; it never \
             skips."
        ),
    }
}

/// The variable `name`, from the environment or from the settings file;
/// `None` when it is absent or empty.
pub fn optional(name: &str) -> Option<String> {
    load();
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Tracing to the test output, filtered by `RUST_LOG`, installed once.
pub fn logging() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
    });
}
