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
            path: Option<RelativePathBuf>,

            #[serde(borrow)]
            path_b64: Option<&'a str>,
        }
        let RawOrBase64 { path, path_b64 } = RawOrBase64::deserialize(deserializer)?;
        match (path, path_b64) {
            (Some(path), None) => Ok(Self(path)),
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
