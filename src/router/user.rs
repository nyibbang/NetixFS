use tokio::task;
use uzers::get_user_by_name;

/// An authenticated and identity-resolved user, attached to each request as an Axum extension.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct User {
    pub(super) name: String,
    pub(super) identity: Identity,
}

/// Local Linux identity resolved through NSS for a JWT-authenticated user.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Identity {
    pub(super) uid: u32,
    pub(super) primary_gid: u32,
    pub(super) supplementary_gids: Vec<u32>,
}

/// Resolves a username to a local Linux identity through NSS.
pub(super) async fn resolve(name: String) -> Result<Identity, ResolveError> {
    // Dispatch the calls into a blocking task because NSS functions (`getpwnam_r`, `getgrouplist`)
    // are synchronous C library calls that must not run on the Tokio executor.
    tokio::task::spawn_blocking(move || {
        let user = match get_user_by_name(&name) {
            Some(user) => user,
            None => return Err(ResolveError::UserNotFound(name)),
        };
        let uid = user.uid();
        let primary_gid = user.primary_group_id();
        let groups = user
            .groups()
            .ok_or_else(|| ResolveError::GroupsNotFound(name))?;
        let supplementary_gids = groups
            .into_iter()
            .map(|g| g.gid())
            .filter(|&gid| gid != primary_gid)
            .collect();
        Ok(Identity {
            uid,
            primary_gid,
            supplementary_gids,
        })
    })
    .await
    .map_err(ResolveError::TaskFailed)
    .flatten()
}

#[derive(Debug, thiserror::Error)]
pub(super) enum ResolveError {
    #[error("user '{0}' not found in local identity system")]
    UserNotFound(String),

    #[error("could not resolve groups for user '{0}'")]
    GroupsNotFound(String),

    #[error("identity resolution task has failed")]
    TaskFailed(#[source] task::JoinError),
}

#[cfg(test)]
mod tests {
    use super::{ResolveError, resolve};
    use uzers::{get_current_gid, get_current_uid, get_current_username};

    #[tokio::test]
    async fn resolve_current_user_succeeds() {
        let username = get_current_username()
            .expect("current username must be available")
            .to_string_lossy()
            .into_owned();
        let identity = resolve(username)
            .await
            .expect("current user must resolve via NSS");
        assert_eq!(identity.uid, get_current_uid());
        assert_eq!(identity.primary_gid, get_current_gid());
    }

    #[tokio::test]
    async fn resolve_nonexistent_user_returns_user_not_found() {
        let result = resolve("__nonexistent_user_netixfs_test__".to_owned()).await;
        assert!(matches!(result, Err(ResolveError::UserNotFound(_))));
    }
}
