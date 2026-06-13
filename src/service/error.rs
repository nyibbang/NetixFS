use crate::service::RequestId;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Error {
    // Machine-readable error code
    pub(crate) code: String,

    // Human-readable message;
    pub(crate) message: String,

    // HTTP status code
    #[serde(serialize_with = "serialize_status_code")]
    pub(crate) status: StatusCode,

    /// Operation name
    pub(crate) operation: String,

    /// Normalized target path or opaque path identifier
    pub(crate) path: Option<String>,

    /// POSIX errno category, when applicable
    pub(crate) errno: Option<String>,

    // Whether the request is retryable
    pub(crate) retryable: bool,

    /// Machine-readable error code
    pub(crate) request_id: Option<RequestId>,
}

impl Error {
    pub(crate) fn missing_request_id(operation: String, path: Option<String>) -> Self {
        Self {
            code: "missing_request_id".to_owned(),
            message: "X-Request-ID header is missing".to_owned(),
            status: StatusCode::BAD_REQUEST,
            operation,
            path,
            errno: None,
            retryable: true,
            request_id: None,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status, Json(self)).into_response()
    }
}

fn serialize_status_code<S>(code: &StatusCode, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    code.as_u16().serialize(serializer)
}
