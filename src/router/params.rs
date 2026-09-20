use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use relative_path::RelativePathBuf;
use serde::de::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Path(RelativePathBuf);

impl<'de> serde::Deserialize<'de> for Path {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct RawOrBase64<'a> {
            path: Option<&'a std::path::Path>,

            #[serde(borrow)]
            path_b64: Option<&'a str>,
        }
        let RawOrBase64 { path, path_b64 } = RawOrBase64::deserialize(deserializer)?;
        match (path, path_b64) {
            (Some(path), None) => {
                let path = RelativePathBuf::from_path(path).map_err(|from_path_err| {
                    D::Error::custom(format!(
                        "could not build a path from path value: {from_path_err}",
                    ))
                })?;
                Ok(Self(path))
            }
            (None, Some(path_b64)) => {
                let path_as_bytes =
                    BASE64_URL_SAFE_NO_PAD
                        .decode(path_b64.as_bytes())
                        .map_err(|decode_error| {
                            D::Error::custom(format!(
                                "could not decode path_b64 value: {decode_error}"
                            ))
                        })?;
                let path_as_os_str = OsStr::from_bytes(&path_as_bytes);
                let path = RelativePathBuf::from_path(path_as_os_str).map_err(|from_path_err| {
                    D::Error::custom(format!(
                        "could not build a path from base64 bytes {from_path_err}",
                    ))
                })?;
                Ok(Self(path))
            }
            (None, None) => Err(D::Error::custom("neither path or path_b64 are present")),
            (Some(_), Some(_)) => Err(D::Error::custom("both path and path_b64 are present")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Path;
    use assert_matches::assert_matches;
    use relative_path::RelativePathBuf;

    fn deserialize(json: &str) -> Result<Path, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn raw_path_is_accepted() {
        assert_eq!(
            deserialize(r#"{"path": "docs/readme.txt"}"#).ok(),
            Some(Path(RelativePathBuf::from("docs/readme.txt")))
        );
    }

    #[test]
    fn raw_path_that_is_absolute_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path": "/etc/passwd"}"#),
            Err(error) if error.to_string().contains("could not build a path from path value")
        );
    }

    #[test]
    fn base64_path_is_accepted() {
        assert_eq!(
            deserialize(r#"{"path_b64": "ZG9jcy9yZWFkbWUudHh0"}"#).ok(),
            Some(Path(RelativePathBuf::from("docs/readme.txt")))
        );
    }

    #[test]
    fn base64_path_with_non_ascii_utf8_is_accepted() {
        assert_eq!(
            deserialize(r#"{"path_b64": "ZGlyL2NhZsOpIPCfk4E"}"#).ok(),
            Some(Path(RelativePathBuf::from("dir/café 📁")))
        );
    }

    #[test]
    fn base64_path_uses_url_safe_alphabet() {
        assert_eq!(
            deserialize(r#"{"path_b64": "YT8-"}"#).ok(),
            Some(Path(RelativePathBuf::from("a?>")))
        );
        assert_matches!(
            deserialize(r#"{"path_b64": "YT8+"}"#),
            Err(error) if error.to_string().contains("could not decode path_b64 value")
        );
    }

    #[test]
    fn base64_path_with_padding_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "Zg=="}"#),
            Err(error) if error.to_string().contains("could not decode path_b64 value")
        );
    }

    #[test]
    fn base64_path_with_invalid_characters_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "not base64!"}"#),
            Err(error) if error.to_string().contains("could not decode path_b64 value")
        );
    }

    #[test]
    fn base64_path_that_is_not_utf8_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "__4"}"#),
            Err(error) if error.to_string().contains("could not build a path from base64 bytes")
        );
    }

    #[test]
    fn base64_path_that_is_absolute_is_rejected() {
        assert_matches!(
            deserialize(r#"{"path_b64": "L2V0Yy9wYXNzd2Q"}"#),
            Err(error) if error.to_string().contains("could not build a path from base64 bytes")
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
            deserialize(r#"{"path": "docs", "path_b64": "ZG9jcw"}"#),
            Err(error) if error.to_string().contains("both path and path_b64 are present")
        );
    }
}
