use crate::config::SymlinkPolicy;

pub mod root;

#[derive(Debug)]
pub struct Config {
    pub symlink_policy: SymlinkPolicy,
    pub allow_mount_crossing: bool,
}

impl From<&crate::Config> for Config {
    fn from(config: &crate::Config) -> Self {
        Self {
            symlink_policy: config.filesystem.symlink_policy.value,
            allow_mount_crossing: config.filesystem.allow_mount_crossing.value,
        }
    }
}
