use super::jwt;
use crate::{BoxFuture, config::Config};
use axum::{
    Json,
    body::Body,
    http::{HeaderMap, Request, Response, StatusCode, header},
    response::IntoResponse,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tower_http::auth::AsyncAuthorizeRequest;
use tracing::warn;

#[derive(Clone)]
pub(crate) struct Authenticator {
    config: Arc<Config>,
}

impl Authenticator {
    pub(crate) fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl<B> AsyncAuthorizeRequest<B> for Authenticator
where
    B: Send + 'static,
{
    type RequestBody = B;
    type ResponseBody = Body;
    type Future = BoxFuture<Result<Request<B>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, request: Request<B>) -> Self::Future {
        let config = Arc::clone(&self.config);
        Box::pin(async move {
            match check_auth(&config, request).await {
                Ok((user, mut request)) => {
                    request.extensions_mut().insert(user);
                    Ok(request)
                }
                Err(error) => {
                    warn!(
                        details = %error,
                        // TODO: add request ID
                        "authentication failure"
                    );
                    Err(error.into_response())
                }
            }
        })
    }
}

async fn check_auth<B>(config: &Config, request: Request<B>) -> Result<(User, Request<B>), Error> {
    let token = extract_bearer_token(request.headers())?;
    let username = jwt::validate(config, token).await?;
    let user_data_root = config
        .filesystem
        .allowed_roots
        .value
        .iter()
        .find(|root| root.id == username)
        .ok_or_else(|| Error::UserNotFound(username.clone()))?;
    let user = User {
        name: username,
        data_root: user_data_root.path.clone(),
    };
    Ok((user, request))
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, Error> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok()?.strip_prefix("Bearer "))
        .map(str::to_owned)
        .ok_or(Error::MissingOrInvalidHeader)
}

pub(super) enum Error {
    MissingOrInvalidHeader,
    DecodeJwtHeader(jsonwebtoken::errors::Error),
    InvalidToken(jsonwebtoken::errors::Error),
    MissingKidClaim,
    KidNotFound(String),
    MissingUsernameClaim(String),
    UserNotFound(String),
    InternalKeyVerification,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MissingOrInvalidHeader => {
                f.write_str("missing or invalid \"Authorization\" header")
            }
            Error::DecodeJwtHeader(e) => write!(f, "failed to decode JWT header: {e}"),
            Error::InvalidToken(e) => write!(f, "invalid token: {e}"),
            Error::MissingKidClaim => f.write_str("JWT missing \"kid\" claim, required for JWKS"),
            Error::KidNotFound(kid) => write!(f, "JWT \"kid\" '{kid}' not found in JWKS"),
            Error::MissingUsernameClaim(claim) => {
                write!(f, "JWT missing configured username claim '{claim}'")
            }
            Error::InternalKeyVerification => {
                write!(f, "internal key verification error")
            }
            Error::UserNotFound(user) => write!(f, "user {user} not found"),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let (status, retryable) = match &self {
            Error::InternalKeyVerification => (StatusCode::SERVICE_UNAVAILABLE, true),
            _ => (StatusCode::UNAUTHORIZED, false),
        };

        let body = crate::Error {
            code: status
                .canonical_reason()
                .unwrap_or("unknown")
                .to_lowercase()
                .replace(' ', "_"),
            message: self.to_string(),
            status: status.as_u16(),
            operation: "authentication".to_string(),
            path: None, // TODO: Add path
            errno: None,
            retryable,
            request_id: String::new(), // TODO: add request ID
        };

        (status, Json(body)).into_response()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct User {
    name: String,
    data_root: PathBuf,
}

impl User {
    pub(crate) fn data_root(&self) -> &Path {
        &self.data_root
    }
}
