use super::auth::Error;
use crate::config::{Config, JwtSource};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use reqwest::get;
use serde_json::Value as JsonValue;
use std::{collections::HashMap, path::Path};
use tokio::fs::read_to_string;
use tracing::warn;
use url::Url;

enum KeySource<'a> {
    PublicKey(SourceFile<'a>),
    Jwks(SourceFile<'a>),
}

impl<'a> From<&'a JwtSource> for KeySource<'a> {
    fn from(source: &'a JwtSource) -> Self {
        match &source {
            JwtSource::PublicKeyPath(path) => KeySource::PublicKey(SourceFile::Path(&path.value)),
            JwtSource::PublicKeyUrl(url) => KeySource::PublicKey(SourceFile::Url(&url.value)),
            JwtSource::JwksPath(path) => KeySource::Jwks(SourceFile::Path(&path.value)),
            JwtSource::JwksUrl(url) => KeySource::Jwks(SourceFile::Url(&url.value)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SourceFile<'a> {
    Path(&'a Path),
    Url(&'a Url),
}

impl std::fmt::Display for SourceFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceFile::Path(path) => path.display().fmt(f),
            SourceFile::Url(url) => url.fmt(f),
        }
    }
}

impl SourceFile<'_> {
    async fn read(self) -> Result<String, Error> {
        Ok(match self {
            SourceFile::Path(path) => read_to_string(path).await.map_err(|err| {
                warn!(
                    path = %path.display(),
                    error = %err,
                    "could not read source file as string"
                );
                Error::InternalKeyVerification
            })?,
            SourceFile::Url(url) => get(url.clone())
                .await
                .map_err(|err| {
                    warn!(
                        %url,
                        error = %err,
                        "could not access source"
                    );
                    Error::InternalKeyVerification
                })?
                .text()
                .await
                .map_err(|err| {
                    warn!(
                        %url,
                        error = %err,
                        "could not interpret source content as text"
                    );
                    Error::InternalKeyVerification
                })?,
        })
    }
}

/// Validates a JWT token and returns the username that is associated to it.
pub(super) async fn validate(config: &Config, token: String) -> Result<String, Error> {
    let header = decode_header(&token).map_err(Error::DecodeJwtHeader)?;
    let algorithm = header.alg;
    let jwt_config = &config.auth.jwt;
    let username_claim = &jwt_config.username_claim.value;

    let decoding_key = match KeySource::from(&jwt_config.source) {
        KeySource::PublicKey(file) => {
            let key_data = file.read().await?;
            DecodingKey::from_rsa_pem(key_data.as_bytes()).map_err(|err| {
                warn!(
                    %file,
                    error = %err,
                    "could not read RSA PEM key from file"
                );
                Error::InternalKeyVerification
            })?
        }
        KeySource::Jwks(file) => {
            let jwks_data = file.read().await?;
            let jwks: jsonwebtoken::jwk::JwkSet =
                serde_json::from_str(&jwks_data).map_err(|err| {
                    warn!(
                        %file,
                        error = %err,
                        "could not parse JSON from JWKS data"
                    );
                    Error::InternalKeyVerification
                })?;

            let kid = header.kid.as_ref().ok_or(Error::MissingKidClaim)?;
            let jwk = jwks
                .find(kid)
                .ok_or_else(|| Error::KidNotFound(kid.clone()))?;

            DecodingKey::from_jwk(jwk).map_err(|err| {
                warn!(
                    %file,
                    error = %err,
                    "could not read RSA PEM key from file"
                );
                Error::InternalKeyVerification
            })?
        }
    };

    let mut validation = Validation::new(algorithm);

    if let Some(issuer) = &jwt_config.issuer.value {
        validation.set_issuer(&[issuer.as_str()]);
    }

    if let Some(audience) = &jwt_config.audience.value {
        validation.set_audience(&[audience.as_str()]);
    }

    let username = decode::<HashMap<String, JsonValue>>(&token, &decoding_key, &validation)
        .map_err(Error::InvalidToken)?
        .claims
        .remove(username_claim)
        .and_then(|value| {
            if let JsonValue::String(s) = value {
                Some(s)
            } else {
                None
            }
        })
        .ok_or_else(|| Error::MissingUsernameClaim(username_claim.clone()))?;
    Ok(username.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{Error, validate};
    use crate::config;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::json;
    use std::{io::Write, path::Path};
    use tempfile::NamedTempFile;

    // RSA-2048 PKCS#8 key pair used exclusively for tests. These are not secret.
    const RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJETqse41HRBsc\n\
        7cfcq3ak4oZWFCoZlcic525A3FfO4qW9BMtRO/iXiyCCHn8JhiL9y8j5JdVP2Q9Z\n\
        IpfElcFd3/guS9w+5RqQGgCR+H56IVUyHZWtTJbKPcwWXQdNUX0rBFcsBzCRESJL\n\
        eelOEdHIjG7LRkx5l/FUvlqsyHDVJEQsHwegZ8b8C0fz0EgT2MMEdn10t6Ur1rXz\n\
        jMB/wvCg8vG8lvciXmedyo9xJ8oMOh0wUEgxziVDMMovmC+aJctcHUAYubwoGN8T\n\
        yzcvnGqL7JSh36Pwy28iPzXZ2RLhAyJFU39vLaHdljwthUaupldlNyCfa6Ofy4qN\n\
        ctlUPlN1AgMBAAECggEAdESTQjQ70O8QIp1ZSkCYXeZjuhj081CK7jhhp/4ChK7J\n\
        GlFQZMwiBze7d6K84TwAtfQGZhQ7km25E1kOm+3hIDCoKdVSKch/oL54f/BK6sKl\n\
        qlIzQEAenho4DuKCm3I4yAw9gEc0DV70DuMTR0LEpYyXcNJY3KNBOTjN5EYQAR9s\n\
        2MeurpgK2MdJlIuZaIbzSGd+diiz2E6vkmcufJLtmYUT/k/ddWvEtz+1DnO6bRHh\n\
        xuuDMeJA/lGB/EYloSLtdyCF6sII6C6slJJtgfb0bPy7l8VtL5iDyz46IKyzdyzW\n\
        tKAn394dm7MYR1RlUBEfqFUyNK7C+pVMVoTwCC2V4QKBgQD64syfiQ2oeUlLYDm4\n\
        CcKSP3RnES02bcTyEDFSuGyyS1jldI4A8GXHJ/lG5EYgiYa1RUivge4lJrlNfjyf\n\
        dV230xgKms7+JiXqag1FI+3mqjAgg4mYiNjaao8N8O3/PD59wMPeWYImsWXNyeHS\n\
        55rUKiHERtCcvdzKl4u35ZtTqQKBgQDNKnX2bVqOJ4WSqCgHRhOm386ugPHfy+8j\n\
        m6cicmUR46ND6ggBB03bCnEG9OtGisxTo/TuYVRu3WP4KjoJs2LD5fwdwJqpgtHl\n\
        yVsk45Y1Hfo+7M6lAuR8rzCi6kHHNb0HyBmZjysHWZsn79ZM+sQnLpgaYgQGRbKV\n\
        DZWlbw7g7QKBgQCl1u+98UGXAP1jFutwbPsx40IVszP4y5ypCe0gqgon3UiY/G+1\n\
        zTLp79GGe/SjI2VpQ7AlW7TI2A0bXXvDSDi3/5Dfya9ULnFXv9yfvH1QwWToySpW\n\
        Kvd1gYSoiX84/WCtjZOr0e0HmLIb0vw0hqZA4szJSqoxQgvF22EfIWaIaQKBgQCf\n\
        34+OmMYw8fEvSCPxDxVvOwW2i7pvV14hFEDYIeZKW2W1HWBhVMzBfFB5SE8yaCQy\n\
        pRfOzj9aKOCm2FjjiErVNpkQoi6jGtLvScnhZAt/lr2TXTrl8OwVkPrIaN0bG/AS\n\
        aUYxmBPCpXu3UjhfQiWqFq/mFyzlqlgvuCc9g95HPQKBgAscKP8mLxdKwOgX8yFW\n\
        GcZ0izY/30012ajdHY+/QK5lsMoxTnn0skdS+spLxaS5ZEO4qvPVb8RAoCkWMMal\n\
        2pOhmquJQVDPDLuZHdrIiKiDM20dy9sMfHygWcZjQ4WSxf/J7T9canLZIXFhHAZT\n\
        3wc9h4G8BBCtWN2TN/LsGZdB\n\
        -----END PRIVATE KEY-----\n";

    const RSA_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\n\
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyRE6rHuNR0QbHO3H3Kt2\n\
        pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXB\n\
        Xd/4LkvcPuUakBoAkfh+eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHR\n\
        yIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8Lw\n\
        oPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xq\n\
        i+yUod+j8MtvIj812dkS4QMiRVN/by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5T\n\
        dQIDAQAB\n\
        -----END PUBLIC KEY-----\n";

    fn write_temp(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("failed to create temp file");
        file.write_all(content.as_bytes())
            .expect("temp file write failed");
        file
    }

    fn config_pubkey(key_path: &Path) -> config::Config {
        let path_str = key_path.to_str().expect("path is valid UTF-8");
        config::load([
            "netixfs",
            "--allowed-root",
            "home=/tmp",
            "--jwt-public-key-path",
            path_str,
        ])
        .expect("config creation failed")
    }

    fn config_jwks(jwks_path: &Path) -> config::Config {
        let path_str = jwks_path.to_str().expect("path is valid UTF-8");
        config::load([
            "netixfs",
            "--allowed-root",
            "home=/tmp",
            "--jwt-jwks-path",
            path_str,
        ])
        .expect("config creation failed")
    }

    fn future_exp() -> u64 {
        (std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sign_rs256(claims: &serde_json::Value, kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::RS256);
        if let Some(k) = kid {
            header.kid = Some(k.to_string());
        }
        let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY.as_bytes())
            .expect("test RSA private key is valid");
        jsonwebtoken::encode(&header, claims, &key).expect("JWT encoding must succeed")
    }

    // ── DecodeJwtHeader error ─────────────────────────────────────────────────

    #[tokio::test]
    async fn validate_completely_invalid_token_returns_decode_jwt_header_error() {
        let key_file = write_temp(RSA_PUBLIC_KEY);
        let config = config_pubkey(key_file.path());
        let result = validate(&config, "not-a-jwt".to_string()).await;
        assert!(matches!(result, Err(Error::DecodeJwtHeader(_))));
    }

    // ── JWKS path errors ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn validate_jwks_path_token_without_kid_returns_missing_kid_claim() {
        let jwks_file = write_temp(r#"{"keys":[]}"#);
        let config = config_jwks(jwks_file.path());
        // Token signed with HS256 (no kid in header) — error occurs before signature check.
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &json!({"exp": future_exp()}),
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        let result = validate(&config, token).await;
        assert!(matches!(result, Err(Error::MissingKidClaim)));
    }

    #[tokio::test]
    async fn validate_jwks_path_token_with_unknown_kid_returns_kid_not_found() {
        let jwks_file = write_temp(r#"{"keys":[]}"#);
        let config = config_jwks(jwks_file.path());
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("unknown-kid".to_string());
        let token = jsonwebtoken::encode(
            &header,
            &json!({"exp": future_exp()}),
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        let result = validate(&config, token).await;
        assert!(matches!(result, Err(Error::KidNotFound(kid)) if kid == "unknown-kid"),);
    }

    // ── PublicKey path errors ─────────────────────────────────────────────────

    #[tokio::test]
    async fn validate_public_key_path_invalid_pem_returns_internal_error() {
        let key_file = write_temp("this is not a PEM file");
        let config = config_pubkey(key_file.path());
        // The header of any validly-encoded JWT suffices; we fail before signature verification.
        let token = sign_rs256(&json!({"sub": "alice", "exp": future_exp()}), None);
        let result = validate(&config, token).await;
        assert!(matches!(result, Err(Error::InternalKeyVerification)));
    }

    // ── Token validation errors ───────────────────────────────────────────────

    #[tokio::test]
    async fn validate_expired_token_returns_invalid_token_error() {
        let key_file = write_temp(RSA_PUBLIC_KEY);
        let config = config_pubkey(key_file.path());
        let token = sign_rs256(&json!({"sub": "alice", "exp": 1000u64}), None);
        let result = validate(&config, token).await;
        assert!(matches!(result, Err(Error::InvalidToken(_))));
    }

    #[tokio::test]
    async fn validate_issuer_mismatch_returns_invalid_token_error() {
        let key_file = write_temp(RSA_PUBLIC_KEY);
        let key_file_path = key_file
            .path()
            .to_str()
            .expect("key file path is valid UTF-8");
        let config = config::load([
            "netixfs",
            "--allowed-root",
            "home=/tmp",
            "--jwt-public-key-path",
            key_file_path,
            "--jwt-issuer",
            "https://expected-issuer.example.com",
        ])
        .expect("config file succssfully loads");
        let token = sign_rs256(
            &json!({"sub": "alice", "exp": future_exp(), "iss": "https://wrong-issuer.example.com"}),
            None,
        );
        let result = validate(&config, token).await;
        assert!(matches!(result, Err(Error::InvalidToken(_))));
    }

    #[tokio::test]
    async fn validate_audience_mismatch_returns_invalid_token_error() {
        let key_file = write_temp(RSA_PUBLIC_KEY);
        let key_file_path = key_file
            .path()
            .to_str()
            .expect("key file path is valid UTF-8");
        let config = config::load([
            "netixfs",
            "--allowed-root",
            "home=/tmp",
            "--jwt-public-key-path",
            key_file_path,
            "--jwt-audience",
            "my-api",
        ])
        .unwrap();
        // Token with a non-matching aud claim fails audience validation.
        let token = sign_rs256(
            &json!({"sub": "alice", "exp": future_exp(), "aud": "wrong-audience"}),
            None,
        );
        let result = validate(&config, token).await;
        assert!(matches!(result, Err(Error::InvalidToken(_))));
    }

    #[tokio::test]
    async fn validate_missing_configured_username_claim_returns_error() {
        let key_file = write_temp(RSA_PUBLIC_KEY);
        let key_file_path = key_file
            .path()
            .to_str()
            .expect("key file path is valid UTF-8");
        let config = config::load([
            "netixfs",
            "--allowed-root",
            "home=/tmp",
            "--jwt-public-key-path",
            key_file_path,
            "--jwt-username-claim",
            "username",
        ])
        .unwrap();
        // Token has "sub" but the config expects "username" claim.
        let token = sign_rs256(&json!({"sub": "alice", "exp": future_exp()}), None);
        let result = validate(&config, token).await;
        assert!(matches!(result, Err(Error::MissingUsernameClaim(claim)) if claim == "username"),);
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn validate_valid_token_returns_username_from_configured_claim() {
        let key_file = write_temp(RSA_PUBLIC_KEY);
        let config = config_pubkey(key_file.path());
        let token = sign_rs256(&json!({"sub": "alice", "exp": future_exp()}), None);
        let result = validate(&config, token).await;
        assert_eq!(result.unwrap(), "alice");
    }
}
