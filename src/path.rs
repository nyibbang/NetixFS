use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::de::Error;
use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Component, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelativePath(PathBuf);

impl RelativePath {
    #[must_use]
    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for RelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
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
            (None, None) => return Err(D::Error::custom("neither path or path_b64 are present")),
            (Some(_), Some(_)) => {
                return Err(D::Error::custom("both path and path_b64 are present"));
            }
        };
        let raw_path = std::path::Path::new(OsStr::from_bytes(&raw));
        let path = normalize_sanitize(raw_path).map_err(D::Error::custom)?;
        Ok(Self(path))
    }
}

fn normalize_sanitize(path: &std::path::Path) -> Result<PathBuf, String> {
    if path.as_os_str().as_bytes().contains(&0) {
        return Err("path must not contain NUL bytes".to_string());
    }
    let mut normalized_sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => normalized_sanitized.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err("path must not contain ancestor components".to_string());
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err("path must be relative".to_string());
            }
        }
    }
    if normalized_sanitized.as_os_str().is_empty() {
        return Err("path must not be empty".to_string());
    }
    Ok(normalized_sanitized)
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
            Err(error) if error.to_string().contains("path must be relative")
        );
    }

    #[test]
    fn path_containing_ancestors_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path": "foo/../bar"}"#),
            Err(error) if error.to_string().contains("path must not contain ancestor components")
        );
    }

    #[test]
    fn empty_path_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path": ""}"#),
            Err(error) if error.to_string().contains("path must not be empty")
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
            Err(error) if error.to_string().contains("path must be relative")
        );
    }

    #[test]
    fn base64_path_containing_ancestors_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "Zm9vLy4uL2Jhcg"}"#), // "foo/../bar"
            Err(error) if error.to_string().contains("path must not contain ancestor components")
        );
    }

    #[test]
    fn empty_base64_path_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": ""}"#), // ""
            Err(error) if error.to_string().contains("path must not be empty")
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
            Err(error) if error.to_string().contains("path must not be empty")
        );
    }

    #[test]
    fn base64_path_containing_nul_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "YQBi"}"#), // "a\0b"
            Err(error) if error.to_string().contains("path must not contain NUL bytes")
        );
    }
}
