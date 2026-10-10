pub mod config;
pub mod logging;
pub mod path;
pub mod router;
pub mod supervisor;
pub mod worker;

pub use config::Config;
use fork::fork;
use std::{os::unix::net::UnixStream, sync::Arc};

pub type BoxFuture<T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// # Errors
///
/// Returns an error on configuration or initialization error.
// TODO: do not use eyre in the library
pub fn start(config: Arc<Config>) -> eyre::Result<()> {
    let (router_socket, supervisor_socket) = UnixStream::pair()?;
    match fork()? {
        // Supervisor process (parent)
        fork::Fork::Parent(child_pid) => {
            // Close the socket to the supervisor, only keep the socket to the router.
            drop(supervisor_socket);
            supervisor::run(config, router_socket);
        }
        // Router process (child)
        fork::Fork::Child => {
            // Close the socket to the router, only keep the socket to the supervisor.
            drop(router_socket);
            router::run(config, supervisor_socket)?;
        }
    }
    Ok(())
}
