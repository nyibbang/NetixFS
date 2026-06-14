use super::jwt;
use crate::{
    BoxFuture,
    config::Config,
    service::{Error as ServiceError, RequestId},
};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header},
    response::IntoResponse,
};
use futures::TryFutureExt;
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

    fn authorize(&mut self, mut request: Request<B>) -> Self::Future {
        let config = Arc::clone(&self.config);
        Box::pin(
            async move {
                let method = request.method();
                let path = request.uri().path();
                let request_id = request
                    .extensions()
                    .get::<tower_http::request_id::RequestId>()
                    .cloned()
                    .map(RequestId)
                    .ok_or_else(|| {
                        ServiceError::missing_request_id(method.to_string(), Some(path.to_owned()))
                    })?;
                let user = authenticate_user(&config, request.headers())
                    .await
                    .map_err(|err| {
                        warn!(
                            details = %err,
                            %request_id,
                            "authentication failure"
                        );
                        err.into_service_error(Some(path.to_owned()), Some(request_id))
                    })?;
                request.extensions_mut().insert(user);
                Ok(request)
            }
            .map_err(ServiceError::into_response),
        )
    }
}

async fn authenticate_user(
    config: &Config,
    headers: &HeaderMap<HeaderValue>,
) -> Result<User, Error> {
    let token = extract_bearer_token(headers)?;
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
    Ok(user)
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

impl Error {
    fn into_service_error(
        self,
        path: Option<String>,
        request_id: Option<RequestId>,
    ) -> ServiceError {
        let (status, retryable) = match &self {
            Error::InternalKeyVerification => (StatusCode::SERVICE_UNAVAILABLE, true),
            _ => (StatusCode::UNAUTHORIZED, false),
        };

        ServiceError {
            code: status
                .canonical_reason()
                .unwrap_or("unknown")
                .to_lowercase()
                .replace(' ', "_"),
            message: self.to_string(),
            status,
            operation: "authentication".to_string(),
            path,
            errno: None,
            retryable,
            request_id,
        }
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
