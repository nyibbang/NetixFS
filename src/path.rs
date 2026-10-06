use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelativePath(PathBuf);

impl RelativePath {
    /// Try to constructs a relative path from a path by sanitizing and normalizing it.
    ///
    /// # Errors
    ///
    /// Returns an `Error` if either the path:
    ///   - has some null bytes,
    ///   - has an ancestor component ('..'),
    ///   - is absolute,
    ///   - is empty after normalization (e.g. './').
    pub fn from_path(path: &Path) -> Result<Self, Error> {
        if path.as_os_str().as_bytes().contains(&0) {
            return Err(Error::NullByte);
        }
        let mut normalized_sanitized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(name) => normalized_sanitized.push(name),
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(Error::AncestorComponent);
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(Error::Absolute);
                }
            }
        }
        if normalized_sanitized.as_os_str().is_empty() {
            return Err(Error::Empty);
        }
        Ok(Self(normalized_sanitized))
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the path contains NUL bytes")]
    NullByte,

    #[error("the path contains an ancestor component")]
    AncestorComponent,

    #[error("the path is absolute")]
    Absolute,

    #[error("the path is empty")]
    Empty,
}

impl<'de> serde::Deserialize<'de> for RelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as DeserError;
        #[derive(serde::Deserialize)]
        struct RawOrBase64<'a> {
            #[serde(borrow)]
            path: Option<&'a str>,

            #[serde(borrow)]
            path_b64: Option<&'a str>,
        }
        let RawOrBase64 { path, path_b64 } = RawOrBase64::deserialize(deserializer)?;
        let raw = match (path, path_b64) {
            (Some(path), None) => path.as_bytes().to_vec(),
            (None, Some(path_b64)) => {
                BASE64_URL_SAFE_NO_PAD
                    .decode(path_b64.as_bytes())
                    .map_err(|decode_error| {
                        D::Error::custom(format!("could not decode path_b64 value: {decode_error}"))
                    })?
            }
            (None, None) => return Err(DeserError::custom("neither path or path_b64 are present")),
            (Some(_), Some(_)) => {
                return Err(DeserError::custom("both path and path_b64 are present"));
            }
        };
        let raw_path = Path::new(OsStr::from_bytes(&raw));
        let relative_path = Self::from_path(raw_path).map_err(D::Error::custom)?;
        Ok(relative_path)
    }
}

#[cfg(test)]
mod tests {
    use super::RelativePath;
    use assert_matches::assert_matches;
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::PathBuf};

    fn deserialize(json: &str) -> Result<RelativePath, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn raw_path_is_accepted() {
        assert_eq!(
            deserialize(r#"{"path": "docs/readme.txt"}"#).unwrap(),
            RelativePath(PathBuf::from("docs/readme.txt"))
        );
    }

    #[test]
    fn raw_path_that_is_absolute_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path": "/etc/passwd"}"#),
            Err(error) if error.to_string().contains("path is absolute")
        );
    }

    #[test]
    fn path_containing_ancestors_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path": "foo/../bar"}"#),
            Err(error) if error.to_string().contains("path contains an ancestor component")
        );
    }

    #[test]
    fn empty_path_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path": ""}"#),
            Err(error) if error.to_string().contains("path is empty")
        );
    }

    #[test]
    fn null_path_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path": null}"#),
            Err(error) if error.to_string().contains("neither path or path_b64 are present")
        );
    }

    #[test]
    fn base64_path_is_accepted() {
        assert_eq!(
            deserialize(r#"{"path_b64": "ZG9jcy9yZWFkbWUudHh0"}"#).unwrap(), // "docs/readme.txt"
            RelativePath(PathBuf::from("docs/readme.txt"))
        );
    }

    #[test]
    fn base64_path_with_non_ascii_utf8_is_accepted() {
        assert_eq!(
            deserialize(r#"{"path_b64": "ZGlyL2NhZsOpIPCfk4E"}"#).unwrap(), // "dir/café 📁"
            RelativePath(PathBuf::from("dir/café 📁"))
        );
    }

    #[test]
    fn base64_path_uses_url_safe_alphabet() {
        assert_eq!(
            deserialize(r#"{"path_b64": "YT8-"}"#).unwrap(), // "a?>"
            RelativePath(PathBuf::from("a?>"))
        );
        assert_matches!(
            deserialize(r#"{"path_b64": "YT8+"}"#), // "a?>" with the standard alphabet, not URL-safe
            Err(error) if error.to_string().contains("could not decode path_b64 value")
        );
    }

    #[test]
    fn base64_path_with_padding_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "Zg=="}"#), // "f"
            Err(error) if error.to_string().contains("could not decode path_b64 value")
        );
    }

    #[test]
    fn base64_path_with_invalid_characters_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "not base64!"}"#), // contains spaces and "!", no decoding
            Err(error) if error.to_string().contains("could not decode path_b64 value")
        );
    }

    #[test]
    fn base64_path_that_is_not_utf8_is_accepted() {
        assert_eq!(
            deserialize(r#"{"path_b64": "__4"}"#).unwrap(), // bytes FF FE, not UTF-8
            RelativePath(PathBuf::from(OsStr::from_bytes(&[0xFF, 0xFE])))
        );
    }

    #[test]
    fn base64_path_that_is_absolute_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "L2V0Yy9wYXNzd2Q"}"#), // "/etc/passwd"
            Err(error) if error.to_string().contains("path is absolute")
        );
    }

    #[test]
    fn base64_path_containing_ancestors_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "Zm9vLy4uL2Jhcg"}"#), // "foo/../bar"
            Err(error) if error.to_string().contains("path contains an ancestor component")
        );
    }

    #[test]
    fn empty_base64_path_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": ""}"#), // ""
            Err(error) if error.to_string().contains("path is empty")
        );
    }

    #[test]
    fn null_base64_path_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": null}"#),
            Err(error) if error.to_string().contains("neither path or path_b64 are present")
        );
    }

    #[test]
    fn missing_path_and_path_b64_is_rejected() {
        assert_matches!(
            deserialize("{}"),
            Err(error) if error.to_string().contains("neither path or path_b64 are present")
        );
    }

    #[test]
    fn both_path_and_path_b64_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path": "docs", "path_b64": "ZG9jcw"}"#), // "docs"
            Err(error) if error.to_string().contains("both path and path_b64 are present")
        );
    }

    #[test]
    fn raw_path_is_normalized() {
        assert_eq!(
            deserialize(r#"{"path": "./docs//readme.txt"}"#).unwrap(),
            RelativePath(PathBuf::from("docs/readme.txt"))
        );
    }

    #[test]
    fn path_reducing_to_nothing_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path": "./"}"#),
            Err(error) if error.to_string().contains("path is empty")
        );
    }

    #[test]
    fn base64_path_containing_nul_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "YQBi"}"#), // "a\0b"
            Err(error) if error.to_string().contains("path contains NUL bytes")
        );
    }
}
