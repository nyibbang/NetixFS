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
