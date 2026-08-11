use crate::config::Config;
use auth::{Authenticator, User};
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::Path as RequestPath,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::Bytes;
pub(crate) use error::Error;
use eyre::Result;
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::fs::File;
use tokio_util::io::ReaderStream;
use tower::ServiceBuilder;
use tower_http::{
    ServiceBuilderExt,
    auth::AsyncRequireAuthorizationLayer,
    decompression::RequestDecompressionLayer,
    on_early_drop::{EarlyDropsAsFailures, OnEarlyDropLayer},
    request_id::MakeRequestUuid,
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
};

mod auth;
mod error;
mod jwt;
mod ready;
mod user;

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

fn sanitize_path(user_data_root: &Path, file_path: String) -> Result<PathBuf, StatusCode> {
    let file_path = user_data_root
        .join(&file_path)
        .canonicalize()
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if !file_path.starts_with(user_data_root) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(file_path)
}

async fn read_file(
    Extension(user): Extension<User>,
    RequestPath(file_path): RequestPath<String>,
) -> Result<Response, StatusCode> {
    let user_file_path = sanitize_path(user.data_root(), file_path)?;
    if !user_file_path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }
    let file = File::open(&user_file_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let file_stream = ReaderStream::new(file);
    Ok(Body::from_stream(file_stream).into_response())
}

async fn write_file(
    Extension(_user): Extension<User>,
    RequestPath(_file_path): RequestPath<String>,
    _content: Bytes,
) -> Result<Response, StatusCode> {
    // let path = get_path(&request);
    // let token = authentication_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    //
    // let bytes = axum::body::to_bytes(request.body(), 1024 * 1024 * 10)
    //     .await
    //     .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    //
    // let user_dir = get_user_dir(&state.root_path, &token);
    // let file_path = user_dir.join(path);
    //
    // fs::create_dir_all(&user_dir)
    //     .await
    //     .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    //
    // fs::write(&file_path, &bytes)
    //     .await
    //     .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    //
    Ok(StatusCode::CREATED.into_response())
}

async fn delete_file(
    Extension(_user): Extension<User>,
    RequestPath(_file_path): RequestPath<String>,
) -> Result<Response, StatusCode> {
    // let path = get_path(&request);
    // let token = authentication_token(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    //
    // let user_dir = get_user_dir(&state.root_path, &token);
    // let file_path = user_dir.join(path);
    //
    // if !file_path.exists() {
    //     return Err(StatusCode::NOT_FOUND);
    // }
    //
    // fs::remove_file(&file_path)
    //     .await
    //     .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    //
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) fn service(config: Arc<Config>) -> Router {
    let generic_middleware = ServiceBuilder::new()
        // Mark the `Authorization` and `Cookie` headers as sensitive so it doesn't show in logs
        .sensitive_headers([header::AUTHORIZATION, header::COOKIE])
        // Report clients that disconnect before the response completes.
        // Fires inside the TraceLayer span so events carry the request context.
        .layer(OnEarlyDropLayer::new(EarlyDropsAsFailures::new(
            DefaultOnFailure::default(),
        )))
        // Add high level tracing/logging to all requests
        .layer(
            TraceLayer::new_for_http()
                .on_body_chunk(|chunk: &Bytes, latency: Duration, _: &tracing::Span| {
                    tracing::trace!(size_bytes = chunk.len(), latency = ?latency, "sending body chunk")
                })
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_response(DefaultOnResponse::new().include_headers(true))
        );

    let middleware = ServiceBuilder::new()
        .compression()
        .layer(RequestDecompressionLayer::new())
        .request_body_limit(
            config
                .limits
                .max_request_body_size
                .value
                .as_u64()
                .try_into()
                .unwrap_or(usize::MAX),
        )
        .set_x_request_id(MakeRequestUuid)
        .layer(AsyncRequireAuthorizationLayer::new(Authenticator::new(
            Arc::clone(&config),
        )))
        .insert_response_header_if_not_present(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );

    Router::new()
        .layer(generic_middleware)
        .route(
            "/{*path}",
            get(read_file).post(write_file).delete(delete_file),
        )
        .route_layer(middleware)
}

pub(crate) fn meta_services() -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready::run_checks))
}

#[derive(Debug, Clone)]
pub(crate) struct RequestId(tower_http::request_id::RequestId);

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        String::from_utf8_lossy(self.0.header_value().as_bytes()).fmt(f)
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = self.0.header_value();
        match value.to_str() {
            Ok(id) => id.serialize(serializer),
            Err(_) => value.as_bytes().serialize(serializer),
        }
    }
}
