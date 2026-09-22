//! Binary entrypoint: resolve the configuration, build the state, serve.

use libid_server_rs::{
    config::Cli,
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

    let cli = Cli::resolve()?;
    // No network request happens here: a Distribution that is unreachable
    // delays the callback document and stops nothing.
    let bridge = Bridge::start(&cli.settings()?)?;

    let listener =
        tokio::net::TcpListener::bind(format!("{}:{}", cli.host, cli.port)).await?;
    tracing::info!("libid-server-rs listening on {}", listener.local_addr()?);

    serve(bridge, listener, async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    })
    .await?;
    Ok(())
}
