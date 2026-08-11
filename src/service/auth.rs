use super::{jwt, user};
use crate::{
    BoxFuture,
    config::Config,
    service::{Error as ServiceError, RequestId},
};
use axum::{
    body::Body,
    http::{self, HeaderMap, Response, StatusCode, header},
    response::IntoResponse,
};
use futures::{FutureExt, TryFutureExt};
use std::sync::Arc;
use tower_http::auth::AsyncAuthorizeRequest;
use tracing::warn;
pub(crate) use user::User;

/// An authenticator for HTTP requests.
///
/// It checks that each request has an authorization header containing a Bearer token, validates it
/// as a JSON Web Token, finds the Linux user associated to this token and gets the roots that are
/// configured for this user.
#[derive(Clone)]
pub(crate) struct Authenticator {
    config: Arc<Config>,
}

impl Authenticator {
    pub(super) fn new(config: Arc<Config>) -> Self {
        Self { config }
    }
}

impl<B> AsyncAuthorizeRequest<B> for Authenticator
where
    B: Send + 'static,
{
    type RequestBody = B;
    type ResponseBody = Body;
    type Future = BoxFuture<Result<http::Request<B>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, mut request: http::Request<B>) -> Self::Future {
        let config = Arc::clone(&self.config);
        async move {
            let method = request.method();
            let path = request.uri().path();
            let request_id = match request
                .extensions()
                .get::<tower_http::request_id::RequestId>()
                .cloned()
                .map(RequestId)
            {
                Some(id) => id,
                None => {
                    return Err(ServiceError::missing_request_id(
                        method.to_string(),
                        Some(path.to_owned()),
                    ));
                }
            };
            let headers = request.headers();
            let user = async {
                let token = bearer_token(headers)?;
                lookup_user(&config, token).await.inspect_err(|err| {
                    warn!(
                        details = %err,
                        request_id = %request_id,
                        "authentication failure"
                    )
                })
            }
            .await
            .map_err(|err| err.into_service_error(Some(path.to_owned()), Some(request_id)))?;
            request.extensions_mut().insert(user);
            Ok(request)
        }
        .map_err(ServiceError::into_response)
        .boxed()
    }
}

async fn lookup_user(config: &Config, token: String) -> Result<User, Error> {
    let name = jwt::validate(config, token).await?;
    match user::resolve(name.clone()).await {
        Ok(identity) => Ok(User { name, identity }),
        Err(err) => {
            warn!(
                username = %name,
                details = %err,
                "failed to resolve local identity"
            );
            Err(Error::NssLookupFailed(name))
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<String, Error> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok()?.strip_prefix("Bearer "))
        .map(str::to_owned)
        .ok_or(Error::MissingOrInvalidHeader)
}

#[derive(Debug)]
pub(super) enum Error {
    MissingOrInvalidHeader,
    DecodeJwtHeader(jsonwebtoken::errors::Error),
    InvalidToken(jsonwebtoken::errors::Error),
    MissingKidClaim,
    KidNotFound(String),
    MissingUsernameClaim(String),
    UserNotFound(String),
    InternalKeyVerification,
    NssLookupFailed(String),
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
            Error::NssLookupFailed(user) => {
                write!(
                    f,
                    "failed to resolve local Linux identity for user '{user}'"
                )
            }
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
            Error::InternalKeyVerification | Error::NssLookupFailed(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, true)
            }
            Error::MissingOrInvalidHeader
            | Error::DecodeJwtHeader(_)
            | Error::InvalidToken(_)
            | Error::MissingKidClaim
            | Error::KidNotFound(_)
            | Error::MissingUsernameClaim(_)
            | Error::UserNotFound(_) => (StatusCode::UNAUTHORIZED, false),
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

#[cfg(test)]
mod tests {
    use super::{Error, bearer_token};
    use axum::http::{HeaderMap, StatusCode, header};

    // ── extract_bearer_token ──────────────────────────────────────────────────

    #[test]
    fn extract_bearer_token_missing_header_returns_error() {
        let headers = HeaderMap::new();
        assert!(matches!(
            bearer_token(&headers),
            Err(Error::MissingOrInvalidHeader)
        ));
    }

    #[test]
    fn extract_bearer_token_non_bearer_scheme_returns_error() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
        assert!(matches!(
            bearer_token(&headers),
            Err(Error::MissingOrInvalidHeader)
        ));
    }

    #[test]
    fn extract_bearer_token_missing_space_after_bearer_returns_error() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearertoken".parse().unwrap());
        assert!(matches!(
            bearer_token(&headers),
            Err(Error::MissingOrInvalidHeader)
        ));
    }

    #[test]
    fn extract_bearer_token_lowercase_bearer_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "bearer some-token".parse().unwrap());
        assert!(matches!(
            bearer_token(&headers),
            Err(Error::MissingOrInvalidHeader)
        ));
    }

    #[test]
    fn extract_bearer_token_valid_header_returns_token_string() {
        let token = "eyJhbGciOiJSUzI1NiJ9.e30.sig";
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers).unwrap(), token);
    }

    // ── Error Display ─────────────────────────────────────────────────────────

    #[test]
    fn error_display_messages_match_specification() {
        use jsonwebtoken::errors::{Error as JwtError, ErrorKind};
        let jwt_err = JwtError::from(ErrorKind::InvalidToken);

        assert_eq!(
            Error::MissingOrInvalidHeader.to_string(),
            r#"missing or invalid "Authorization" header"#,
        );
        assert!(
            Error::DecodeJwtHeader(jwt_err.clone())
                .to_string()
                .starts_with("failed to decode JWT header:"),
        );
        assert!(
            Error::InvalidToken(jwt_err)
                .to_string()
                .starts_with("invalid token:"),
        );
        assert_eq!(
            Error::MissingKidClaim.to_string(),
            r#"JWT missing "kid" claim, required for JWKS"#,
        );
        assert_eq!(
            Error::KidNotFound("my-key-id".to_string()).to_string(),
            r#"JWT "kid" 'my-key-id' not found in JWKS"#,
        );
        assert_eq!(
            Error::MissingUsernameClaim("sub".to_string()).to_string(),
            "JWT missing configured username claim 'sub'",
        );
        assert_eq!(
            Error::InternalKeyVerification.to_string(),
            "internal key verification error",
        );
        assert_eq!(
            Error::UserNotFound("alice".to_string()).to_string(),
            "user alice not found",
        );
        assert_eq!(
            Error::NssLookupFailed("alice".to_string()).to_string(),
            "failed to resolve local Linux identity for user 'alice'",
        );
    }

    // ── Error::into_service_error ─────────────────────────────────────────────

    #[test]
    fn into_service_error_internal_errors_are_503_and_retryable() {
        for service_error in [
            Error::InternalKeyVerification.into_service_error(Some("/test".to_string()), None),
            Error::NssLookupFailed("alice".to_string())
                .into_service_error(Some("/test".to_string()), None),
        ] {
            assert_eq!(service_error.status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(service_error.retryable);
            assert_eq!(service_error.operation, "authentication");
        }
    }

    #[test]
    fn into_service_error_all_other_errors_are_401_and_not_retryable() {
        use jsonwebtoken::errors::{Error as JwtError, ErrorKind};

        macro_rules! assert_401_not_retryable {
            ($err:expr) => {
                let service_error = $err.into_service_error(None, None);
                assert_eq!(service_error.status, StatusCode::UNAUTHORIZED);
                assert!(!service_error.retryable);
            };
        }

        assert_401_not_retryable!(Error::MissingOrInvalidHeader);
        assert_401_not_retryable!(Error::DecodeJwtHeader(JwtError::from(
            ErrorKind::InvalidToken
        )));
        assert_401_not_retryable!(Error::InvalidToken(JwtError::from(ErrorKind::InvalidToken)));
        assert_401_not_retryable!(Error::MissingKidClaim);
        assert_401_not_retryable!(Error::KidNotFound("k".into()));
        assert_401_not_retryable!(Error::MissingUsernameClaim("sub".into()));
        assert_401_not_retryable!(Error::UserNotFound("alice".into()));
    }

    #[test]
    fn into_service_error_sets_correct_path_and_operation() {
        let service_error = Error::MissingOrInvalidHeader
            .into_service_error(Some("projects/file.txt".to_string()), None);
        assert_eq!(service_error.path, Some("projects/file.txt".to_string()));
        assert_eq!(service_error.operation, "authentication");
        assert_eq!(service_error.errno, None);
        assert_eq!(service_error.code, "unauthorized");
    }
}
