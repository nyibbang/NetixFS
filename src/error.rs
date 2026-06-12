use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Error {
    // Machine-readable error code
    pub(crate) code: String,

    // Human-readable message;
    pub(crate) message: String,

    // HTTP status code
    pub(crate) status: u16,

    /// Operation name
    pub(crate) operation: String,

    /// Normalized target path or opaque path identifier
    pub(crate) path: Option<String>,

    /// POSIX errno category, when applicable
    pub(crate) errno: Option<String>,

    // Whether the request is retryable
    pub(crate) retryable: bool,

    /// Machine-readable error code
    pub(crate) request_id: String,
}
