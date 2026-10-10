use eyre::Result;
use std::{os::unix::net::UnixStream, sync::Arc};

pub(crate) fn run(config: Arc<crate::Config>, router_socket: UnixStream) -> Result<()> {
    todo!()
}
