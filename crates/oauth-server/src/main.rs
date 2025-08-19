use oauth_server::create_app;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "oauth_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = create_app();

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    info!("Starting OAuth server on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;
    Ok(())
}

