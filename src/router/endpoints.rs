use axum::{
    Router,
    extract::Path as RequestPath,
    http::StatusCode,
    routing::{get, patch, post},
};

pub(super) fn service() -> Router {
    Router::new().nest(
        "/roots/{root_id}",
        Router::new()
            .route("/stat", get(stat).head(head_stat))
            .route("/xattrs", get(list_xattrs))
            .route("/xattrs/{name}", get(get_xattr))
            .route("/dir", get(list_dir).post(create_dir).delete(delete_dir))
            .route("/rename", post(rename))
            .route("/copy", post(copy))
            .route(
                "/file",
                get(read_file).put(replace_file).delete(delete_file),
            )
            .route("/stream", get(stream_file))
            .route("/symlink", get(read_symlink).post(create_symlink))
            .route("/hardlink", post(create_hardlink))
            .route("/group", patch(change_group))
            .route("/mode", patch(change_mode)),
    )
}

const fn not_implemented() -> (StatusCode, &'static str) {
    (
        StatusCode::NOT_IMPLEMENTED,
        "operation is not implemented yet",
    )
}

async fn stat(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn head_stat(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn list_xattrs(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn get_xattr(
    RequestPath((_root_id, _name)): RequestPath<(String, String)>,
) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn list_dir(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn create_dir(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn delete_dir(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn rename(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn copy(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn read_file(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn replace_file(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn delete_file(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn stream_file(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn read_symlink(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn create_symlink(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn create_hardlink(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn change_mode(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}

async fn change_group(RequestPath(_root_id): RequestPath<String>) -> (StatusCode, &'static str) {
    not_implemented()
}
