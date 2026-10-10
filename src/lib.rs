pub mod config;
pub mod logging;
pub mod path;
pub mod router;
pub mod supervisor;
pub mod worker;

pub use config::Config;
use std::sync::Arc;

pub type BoxFuture<T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// # Errors
///
/// Returns an error on configuration or initialization error.
// TODO: do not use eyre in the library
pub fn start(config: Arc<Config>) -> eyre::Result<()> {
    router::start(config)?;
    Ok(())
}
