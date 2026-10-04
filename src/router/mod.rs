pub use self::{error::ErrorResponse, user::User};
use crate::config::Config;
use auth::Authenticator;
use axum::{
    Json, Router,
    http::{HeaderValue, header},
    routing::get,
};
use bytes::Bytes;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
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
mod endpoints;
mod error;
mod jwt;
mod params;
mod ready;
mod user;

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub fn service(config: Arc<Config>) -> Router {
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
                    tracing::trace!(size_bytes = chunk.len(), latency = ?latency, "sending body chunk");
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
                .request_body_size
                .value
                .as_u64()
                .try_into()
                .unwrap_or(usize::MAX),
        )
        .set_x_request_id(MakeRequestUuid)
        .layer(AsyncRequireAuthorizationLayer::new(Authenticator::new(
            config,
        )))
        .insert_response_header_if_not_present(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );

    Router::new()
        .nest("/api/v1", endpoints::service())
        .layer(generic_middleware)
        .route_layer(middleware)
}

pub fn meta_services() -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready::run_checks))
}
