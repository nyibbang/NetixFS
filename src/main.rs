use eyre::Result;
use netixfs::{Config, logging, start};
use std::sync::Arc;

fn main() -> Result<()> {
    simple_eyre::install()?;
    let config = Arc::new(Config::load(std::env::args_os())?);
    logging::setup(&config);
    start(config)?;
    Ok(())
}
