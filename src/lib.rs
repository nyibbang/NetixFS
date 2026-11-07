pub mod config;
pub mod logging;
pub mod path;
pub mod router;
pub mod supervisor;
pub mod worker;

pub use config::Config;
use fork::{ProcessFork, fork_process};
use std::{io, os::unix::net::UnixStream, sync::Arc};

use crate::{router::Router, supervisor::Supervisor};

pub type BoxFuture<T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// # Errors
///
/// Returns an error on configuration or initialization error.
// TODO: do not use eyre in the library
pub fn start(config: Arc<Config>) -> eyre::Result<()> {
    match fork_supervisor(config)? {
        SupervisorFork::Router(router) => router.run(),
        SupervisorFork::Supervisor(supervisor) => match supervisor.run()? {
            supervisor::Termination::Supervisor => Ok(()),
            supervisor::Termination::ContinueAsWorker(worker) => worker.run(),
        },
    }
}

fn fork_supervisor(config: Arc<Config>) -> io::Result<SupervisorFork> {
    let (router_socket, supervisor_socket) = UnixStream::pair()?;
    match fork_process()? {
        // Router process (parent)
        ProcessFork::Parent(child_pid) => Ok(SupervisorFork::Router(Router::new(
            config,
            child_pid,
            supervisor_socket,
        )?)),
        // Supervisor process (child)
        ProcessFork::Child => Ok(SupervisorFork::Supervisor(Supervisor::new(
            config,
            router_socket,
        ))),
    }
}

enum SupervisorFork {
    Router(Router),
    Supervisor(Supervisor),
}
