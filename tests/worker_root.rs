use assert_matches::assert_matches;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use netixfs::{
    config::SymlinkPolicy,
    path::RelativePath,
    worker::{
        Config,
        root::{ContainmentError, Root},
    },
};
use rustix::io::Errno;
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    os::{
        fd::OwnedFd,
        unix::{ffi::OsStrExt, fs::symlink},
    },
    path::PathBuf,
};
use tempfile::TempDir;

// A tree of files in a temporary directory.
//
// <temp_dir>
// ├── outside
// │   └── secret.txt
// └── root
//     └── file.txt
struct Sandbox {
    temp_dir: TempDir,
    root_path: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let root_path = temp_dir.path().join("root");
        let outside_path = temp_dir.path().join("outside");
        let config_dir_path = root_path.join("config");
        let file_path = config_dir_path.join("file.txt");
        let secret_path = outside_path.join("secret.txt");
        fs::create_dir_all(config_dir_path).unwrap();
        fs::create_dir(outside_path).unwrap();
        fs::write(&file_path, "inside").unwrap();
        fs::write(&secret_path, "secret").unwrap();
        Self {
            temp_dir,
            root_path,
        }
    }
}

fn relative(path: &str) -> RelativePath {
    serde_json::from_str(&format!(r#"{{"path": "{path}"}}"#)).unwrap()
}

fn relative_b64(bytes: &[u8]) -> RelativePath {
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
    serde_json::from_str(&format!(r#"{{"path_b64": "{encoded}"}}"#)).unwrap()
}

fn config(symlink_policy: SymlinkPolicy) -> Config {
    Config {
        symlink_policy,
        allow_mount_crossing: false,
    }
}

fn read_to_string(fd: OwnedFd) -> String {
    let mut content = String::new();
    File::from(fd).read_to_string(&mut content).unwrap();
    content
}

#[test]
fn opens_file_through_normalized_path() {
    let Sandbox {
        root_path,
        temp_dir: _temp_dir,
    } = Sandbox::new();
    let root = Root::open(&root_path).unwrap();
    let fd = root
        .open_file(
            &relative("./config//file.txt"),
            &config(SymlinkPolicy::FollowSafe),
        )
        .unwrap();
    assert_eq!(read_to_string(fd), "inside");
}

#[test]
fn opens_non_utf8_file_name_given_as_path_b64() {
    let Sandbox {
        root_path,
        temp_dir: _temp_dir,
    } = Sandbox::new();
    let name = OsStr::from_bytes(&[0xFF, 0xFE]);
    fs::write(root_path.join(name), "raw").unwrap();
    let root = Root::open(&root_path).unwrap();
    let fd = root
        .open_file(
            &relative_b64(name.as_bytes()),
            &config(SymlinkPolicy::Reject),
        )
        .unwrap();
    assert_eq!(read_to_string(fd), "raw");
}

#[test]
fn parent_component_is_rejected_before_lookup() {
    let result: Result<RelativePath, _> =
        serde_json::from_str(r#"{"path": "../outside/secret.txt"}"#);
    assert!(result.is_err());
}

#[test]
fn missing_file_is_reported_as_os_error() {
    let Sandbox {
        root_path,
        temp_dir: _temp_dir,
    } = Sandbox::new();
    let root = Root::open(&root_path).unwrap();
    assert_matches!(
        root.open_file(
            &relative("dir/missing.txt"),
            &config(SymlinkPolicy::FollowSafe)
        ),
        Err(ContainmentError::Os(Errno::NOENT))
    );
}

#[test]
fn root_must_be_a_directory() {
    let Sandbox {
        root_path,
        temp_dir: _temp_dir,
    } = Sandbox::new();
    assert_matches!(
        Root::open(&root_path.join("config/file.txt")),
        Err(ContainmentError::Os(Errno::NOTDIR))
    );
}

#[test]
fn absolute_symlink_outside_root_is_rejected() {
    let Sandbox {
        temp_dir,
        root_path,
    } = Sandbox::new();
    symlink(
        temp_dir.path().join("outside/secret.txt"),
        root_path.join("link"),
    )
    .unwrap();
    let root = Root::open(&root_path).unwrap();
    assert_matches!(
        root.open_file(&relative("link"), &config(SymlinkPolicy::FollowSafe)),
        Err(ContainmentError::OutsideRoot)
    );
}

#[test]
fn relative_symlink_outside_root_is_rejected() {
    let Sandbox {
        root_path,
        temp_dir: _temp_dir,
    } = Sandbox::new();
    symlink("../outside/secret.txt", root_path.join("link")).unwrap();
    let root = Root::open(&root_path).unwrap();
    assert_matches!(
        root.open_file(&relative("link"), &config(SymlinkPolicy::FollowSafe)),
        Err(ContainmentError::OutsideRoot)
    );
}

#[test]
fn symlinked_directory_outside_root_is_rejected() {
    let Sandbox {
        root_path,
        temp_dir: _temp_dir,
    } = Sandbox::new();
    symlink("../outside", root_path.join("dirlink")).unwrap();
    let root = Root::open(&root_path).unwrap();
    assert_matches!(
        root.open_file(
            &relative("dirlink/secret.txt"),
            &config(SymlinkPolicy::FollowSafe)
        ),
        Err(ContainmentError::OutsideRoot)
    );
}

#[test]
fn symlink_chain_leaving_root_is_rejected() {
    let Sandbox {
        root_path,
        temp_dir: _temp_dir,
    } = Sandbox::new();
    symlink("b", root_path.join("a")).unwrap();
    symlink("../outside/secret.txt", root_path.join("b")).unwrap();
    let root = Root::open(&root_path).unwrap();
    assert_matches!(
        root.open_file(&relative("a"), &config(SymlinkPolicy::FollowSafe)),
        Err(ContainmentError::OutsideRoot)
    );
}

#[test]
fn symlink_loop_is_reported_as_os_error() {
    let Sandbox {
        root_path,
        temp_dir: _temp_dir,
    } = Sandbox::new();
    symlink("b", root_path.join("a")).unwrap();
    symlink("a", root_path.join("b")).unwrap();
    let root = Root::open(&root_path).unwrap();
    assert_matches!(
        root.open_file(&relative("a"), &config(SymlinkPolicy::FollowSafe)),
        Err(ContainmentError::Os(Errno::LOOP))
    );
}

#[test]
fn symlink_inside_root_is_followed_when_allowed() {
    let Sandbox {
        root_path,
        temp_dir: _temp_dir,
    } = Sandbox::new();
    symlink("config/file.txt", root_path.join("alias")).unwrap();
    let root = Root::open(&root_path).unwrap();
    let fd = root
        .open_file(&relative("alias"), &config(SymlinkPolicy::FollowSafe))
        .unwrap();
    assert_eq!(read_to_string(fd), "inside");
}

#[test]
fn symlink_inside_root_is_rejected_when_policy_rejects() {
    let Sandbox {
        root_path,
        temp_dir: _temp_dir,
    } = Sandbox::new();
    symlink("dir/file.txt", root_path.join("alias")).unwrap();
    let root = Root::open(&root_path).unwrap();
    assert_matches!(
        root.open_file(&relative("alias"), &config(SymlinkPolicy::Reject)),
        Err(ContainmentError::SymlinkRejected)
    );
}
