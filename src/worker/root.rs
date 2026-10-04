use crate::{Config, config::SymlinkPolicy, path::RelativePath};
use rustix::{
    fs::{Mode, OFlags, ResolveFlags, open, openat2},
    io::Errno,
};
use std::os::fd::OwnedFd;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContainmentError {
    #[error("path resolves outside of the root")]
    OutsideRoot,
    #[error("symbolic links are not allowed")]
    SymlinkRejected,
    #[error("filesystem error: {0}")]
    Os(Errno),
}

#[derive(Debug)]
pub struct Root {
    fd: OwnedFd,
}

impl Root {
    pub fn open(path: &std::path::Path) -> Result<Self, ContainmentError> {
        let fd = open(path, OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
            .map_err(ContainmentError::Os)?;
        Ok(Self { fd })
    }

    pub fn open_file(
        &self,
        path: &RelativePath,
        config: &Config,
    ) -> Result<OwnedFd, ContainmentError> {
        let mut resolve = ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS;
        if !config.filesystem.allow_mount_crossing.value {
            resolve |= ResolveFlags::NO_XDEV;
        }
        if matches!(
            config.filesystem.symlink_policy.value,
            SymlinkPolicy::Reject
        ) {
            resolve |= ResolveFlags::NO_SYMLINKS;
        }
        openat2(
            &self.fd,
            path.as_path(),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )
        .map_err(
            |errno| match (errno, &config.filesystem.symlink_policy.value) {
                (Errno::XDEV, _) => ContainmentError::OutsideRoot,
                (Errno::LOOP, SymlinkPolicy::Reject) => ContainmentError::SymlinkRejected,
                (errno, _) => ContainmentError::Os(errno),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{ContainmentError, Root};
    use crate::{Config, config, path::RelativePath};
    use assert_matches::assert_matches;
    use rustix::io::Errno;
    use std::{
        fs::{self, File},
        io::Read,
        os::{fd::OwnedFd, unix::fs::symlink},
        path::PathBuf,
    };
    use tempfile::TempDir;

    fn fixture() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("dir")).unwrap();
        fs::create_dir(dir.path().join("outside")).unwrap();
        fs::write(root.join("dir/file.txt"), "inside").unwrap();
        fs::write(dir.path().join("outside/secret.txt"), "secret").unwrap();
        (dir, root)
    }

    fn relative(path: &str) -> RelativePath {
        serde_json::from_str(&format!(r#"{{"path": "{path}"}}"#)).unwrap()
    }

    fn config(symlink_policy: &str) -> Config {
        config::load([
            "netixfs",
            "--allowed-root",
            "root=/unused",
            "--jwt-public-key-path",
            "/unused",
            "--symlink-policy",
            symlink_policy,
        ])
        .unwrap()
    }

    fn read_to_string(fd: OwnedFd) -> String {
        let mut content = String::new();
        File::from(fd).read_to_string(&mut content).unwrap();
        content
    }

    #[test]
    fn regular_file_under_root_is_opened() {
        let (_dir, root_path) = fixture();
        let root = Root::open(&root_path).unwrap();
        let fd = root
            .open_file(&relative("dir/file.txt"), &config("follow-safe"))
            .unwrap();
        assert_eq!(read_to_string(fd), "inside");
    }

    #[test]
    fn missing_file_is_reported_as_os_error() {
        let (_dir, root_path) = fixture();
        let root = Root::open(&root_path).unwrap();
        assert_matches!(
            root.open_file(&relative("dir/missing.txt"), &config("follow-safe"),),
            Err(ContainmentError::Os(Errno::NOENT))
        );
    }

    #[test]
    fn absolute_symlink_target_outside_root_is_rejected() {
        let (dir, root_path) = fixture();
        symlink(
            dir.path().join("outside/secret.txt"),
            root_path.join("link"),
        )
        .unwrap();
        let root = Root::open(&root_path).unwrap();
        assert_matches!(
            root.open_file(&relative("link"), &config("follow-safe")),
            Err(ContainmentError::OutsideRoot)
        );
    }

    #[test]
    fn relative_symlink_target_outside_root_is_rejected() {
        let (_dir, root_path) = fixture();
        symlink("../outside/secret.txt", root_path.join("link")).unwrap();
        let root = Root::open(&root_path).unwrap();
        assert_matches!(
            root.open_file(&relative("link"), &config("follow-safe")),
            Err(ContainmentError::OutsideRoot)
        );
    }

    #[test]
    fn symlinked_directory_escaping_root_is_rejected() {
        let (_dir, root_path) = fixture();
        symlink("../outside", root_path.join("dirlink")).unwrap();
        let root = Root::open(&root_path).unwrap();
        assert_matches!(
            root.open_file(&relative("dirlink/secret.txt"), &config("follow-safe"),),
            Err(ContainmentError::OutsideRoot)
        );
    }

    #[test]
    fn symlink_inside_root_is_followed_when_allowed() {
        let (_dir, root_path) = fixture();
        symlink("dir/file.txt", root_path.join("alias")).unwrap();
        let root = Root::open(&root_path).unwrap();
        let fd = root
            .open_file(&relative("alias"), &config("follow-safe"))
            .unwrap();
        assert_eq!(read_to_string(fd), "inside");
    }

    #[test]
    fn symlink_inside_root_is_rejected_when_policy_rejects() {
        let (_dir, root_path) = fixture();
        symlink("dir/file.txt", root_path.join("alias")).unwrap();
        let root = Root::open(&root_path).unwrap();
        assert_matches!(
            root.open_file(&relative("alias"), &config("reject")),
            Err(ContainmentError::SymlinkRejected)
        );
    }
}
