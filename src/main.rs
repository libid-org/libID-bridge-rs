//! Binary entrypoint: resolve the configuration, build the state, serve.

use tracing::info;

use libid_server_rs::{
    config::Config,
    serve,
    Bridge,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config::resolve()?;
    // No network request happens here: a Distribution that is unreachable
    // delays the callback document and stops nothing.
    let bridge = Bridge::start(&cfg)?;

    let listener =
        tokio::net::TcpListener::bind(format!("{}:{}", cfg.host, cfg.port)).await?;
    info!("libid-server-rs listening on {}", listener.local_addr()?);

    serve(bridge, listener, async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutting down");
    })
    .await?;
    Ok(())
}
