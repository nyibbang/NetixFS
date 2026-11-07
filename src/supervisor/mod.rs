use crate::{Config, worker::Worker};
use std::{os::unix::net::UnixStream, sync::Arc};

#[derive(Debug)]
pub struct Supervisor {
    config: Arc<Config>,
    router_socket: UnixStream,
}

impl Supervisor {
    #[must_use]
    pub const fn new(config: Arc<Config>, router_socket: UnixStream) -> Self {
        Self {
            config,
            router_socket,
        }
    }

    /// # Errors
    ///
    /// To be defined
    pub fn run(&self) -> eyre::Result<Termination> {
        todo!()
    }
}

pub enum Termination {
    Supervisor,
    ContinueAsWorker(Worker),
}
