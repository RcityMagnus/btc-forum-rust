use std::env;

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};

/// JWT Claims expected from Rainbow-Auth tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthClaims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub session_id: Option<String>,
}

/// Rejection type returned when auth fails.
#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidToken,
    MissingSecret,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        use axum::http::StatusCode;
        let status = match self {
            AuthError::MissingToken => StatusCode::UNAUTHORIZED,
            AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            AuthError::MissingSecret => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let msg = match self {
            AuthError::MissingToken => "missing bearer token",
            AuthError::InvalidToken => "invalid token",
            AuthError::MissingSecret => "server jwt secret not configured",
        };
        (status, msg).into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthClaims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        use axum::{
            TypedHeader,
            headers::{Authorization, authorization::Bearer},
        };
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::MissingToken)?;

        let secret = env::var("JWT_SECRET").map_err(|_| AuthError::MissingSecret)?;

        let token_data = decode::<AuthClaims>(
            bearer.token(),
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}
