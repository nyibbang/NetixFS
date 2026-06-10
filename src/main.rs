use axum::serve::serve;
pub(crate) use config::Config;
use eyre::Result;
use service::service;
use std::{net::SocketAddr, pin::Pin, sync::Arc};
use tokio::{net::TcpListener, spawn};
use tracing::debug;

use crate::service::meta_services;

mod config;
mod logging;
mod service;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialisation and configuration
    simple_eyre::install()?;
    let config = Arc::new(config::load(std::env::args_os())?);
    logging::setup(&config);

    // Start services
    if config.diagnostics.config_endpoint.enabled.value {
        spawn(serve_diagnostics(Arc::clone(&config)));
    }
    serve_main(config).await?;

    Ok(())
}

async fn serve_diagnostics(config: Arc<Config>) -> Result<()> {
    let address = config.diagnostics.config_endpoint.bind_address.value;
    let listener = TcpListener::bind(address).await?;
    debug!(%address, "exposing diagnostics endpoint");
    serve(listener, config::service(config)).await?;
    Ok(())
}

async fn serve_main(config: Arc<Config>) -> Result<()> {
    let address = SocketAddr::new(config.server.bind_address.value, config.server.port.value);
    let listener = TcpListener::bind(address).await?;
    debug!(%address, "exposing service endpoint");
    serve(listener, service(config).merge(meta_services())).await?;
    Ok(())
}
