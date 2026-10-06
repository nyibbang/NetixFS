pub mod config;
pub mod logging;
pub mod path;
pub mod router;
pub mod worker;

pub use config::Config;

pub type BoxFuture<T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'static>>;
