use std::net::SocketAddr;
use std::sync::Arc;
use entropy_rs::config::ServerConfig;
use entropy_rs::db::redis::RedisManager;
use entropy_rs::telemetry::metrics::Metrics;
use entropy_rs::app;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let config = Arc::new(ServerConfig::load());
    let metrics = Metrics::new();
    let redis = RedisManager::new(config.clone(), metrics.clone()).await?;
    
    let app = app(config.clone(), redis.clone(), metrics.clone()).await?;

    let addr: SocketAddr = format!("{}:{}", config.address, config.port).parse().expect("Invalid address");
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
