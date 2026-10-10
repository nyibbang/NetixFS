use super::Config;
use crate::{config::SymlinkPolicy, path::RelativePath};
use rustix::{
    fs::{Mode, OFlags, ResolveFlags, open, openat2},
    io::Errno,
};
use std::os::fd::OwnedFd;

#[derive(Debug)]
pub struct Root {
    fd: OwnedFd,
}

impl Root {
    /// # Errors
    ///
    /// Returns an error if `path` cannot be opened as a directory.
    pub fn open(path: &std::path::Path) -> Result<Self, ContainmentError> {
        let fd = open(path, OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
            .map_err(ContainmentError::Os)?;
        Ok(Self { fd })
    }

    /// # Errors
    ///
    /// Returns an error if the path escapes the root, if a symlink is rejected by
    /// the configured policy, or if the file cannot be opened.
    pub fn open_file(
        &self,
        path: &RelativePath,
        config: &Config,
    ) -> Result<OwnedFd, ContainmentError> {
        let mut resolve = ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS;
        if !config.allow_mount_crossing {
            resolve |= ResolveFlags::NO_XDEV;
        }
        if config.symlink_policy == SymlinkPolicy::Reject {
            resolve |= ResolveFlags::NO_SYMLINKS;
        }
        openat2(
            &self.fd,
            path.as_path(),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )
        .map_err(|errno| match (errno, config.symlink_policy) {
            (Errno::XDEV, _) => ContainmentError::OutsideRoot,
            (Errno::LOOP, SymlinkPolicy::Reject) => ContainmentError::SymlinkRejected,
            (errno, _) => ContainmentError::Os(errno),
        })
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContainmentError {
    #[error("path resolves outside of the root")]
    OutsideRoot,
    #[error("symbolic links are not allowed")]
    SymlinkRejected,
    #[error("filesystem error: {0}")]
    Os(Errno),
}
