use axum::extract::Query;
use axum::Json;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response, Result},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::super::{
    aes,
    api::{serde_base64, serde_base64_opt},
};

#[derive(Error, Debug)]
enum AppError {
    #[error("aes oracle error: {0:?}")]
    AesError(#[from] aes::AesError),

    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}
impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::AesError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidParameter(_) => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status_code(), self.to_string()).into_response()
    }
}

#[derive(Deserialize)]
struct AesConfig {
    bits: Option<usize>,
}

#[derive(Deserialize)]
struct EncryptRequest {
    #[serde(with = "serde_base64")]
    msg: Vec<u8>,
    #[serde(with = "serde_base64_opt", default)]
    aad: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct EncryptResponse {
    #[serde(with = "serde_base64")]
    key: Vec<u8>,
    #[serde(with = "serde_base64")]
    nonce: Vec<u8>,
    #[serde(with = "serde_base64")]
    ciphertext: Vec<u8>,
    #[serde(with = "serde_base64")]
    tag: Vec<u8>,
}
impl From<aes::EncryptedPayload> for EncryptResponse {
    fn from(value: aes::EncryptedPayload) -> Self {
        EncryptResponse {
            key: value.key,
            nonce: value.nonce,
            ciphertext: value.ciphertext,
            tag: value.tag,
        }
    }
}

#[derive(Deserialize)]
struct DecryptRequest {
    #[serde(with = "serde_base64")]
    key: Vec<u8>,
    #[serde(with = "serde_base64")]
    nonce: Vec<u8>,
    #[serde(with = "serde_base64")]
    ciphertext: Vec<u8>,
    #[serde(with = "serde_base64")]
    tag: Vec<u8>,
    #[serde(with = "serde_base64_opt", default)]
    aad: Option<Vec<u8>>,
}
impl DecryptRequest {
    fn payload(&self) -> aes::EncryptedPayload {
        aes::EncryptedPayload {
            key: self.key.clone(),
            nonce: self.nonce.clone(),
            ciphertext: self.ciphertext.clone(),
            tag: self.tag.clone(),
        }
    }
}

#[derive(Serialize)]
struct DecryptResponse {
    #[serde(with = "serde_base64")]
    msg: Vec<u8>,
}

async fn encrypt(
    aes_config: Query<AesConfig>,
    Json(req): Json<EncryptRequest>,
) -> Result<Json<EncryptResponse>> {
    let res: EncryptResponse = (match aes_config.bits {
        Some(128) => aes::encrypt_aes_128_gcm,
        Some(192) => aes::encrypt_aes_192_gcm,
        Some(256) | None => aes::encrypt_aes_256_gcm,
        Some(_) => return Err(AppError::InvalidParameter("aes_config.bits".to_string()).into()),
    })(&req.msg, req.aad.as_ref())
    .map_err(AppError::AesError)?
    .into();
    Ok(Json(res))
}

async fn decrypt(
    aes_config: Query<AesConfig>,
    Json(req): Json<DecryptRequest>,
) -> Result<Json<DecryptResponse>> {
    let msg = (match aes_config.bits {
        Some(128) => aes::decrypt_aes_128_gcm,
        Some(192) => aes::decrypt_aes_192_gcm,
        Some(256) | None => aes::decrypt_aes_256_gcm,
        Some(_) => return Err(AppError::InvalidParameter("aes_config.bits".to_string()).into()),
    })(&req.payload(), req.aad.as_ref())
    .map_err(AppError::AesError)?;
    Ok(Json(DecryptResponse { msg }))
}

pub fn router() -> Router {
    Router::new()
        .route("/encrypt", post(encrypt))
        .route("/decrypt", post(decrypt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{self, Request, StatusCode},
    };
    use base64::prelude::*;
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use test_case::test_matrix;
    use tower::ServiceExt;

    #[test_matrix(
        [128, 192, 256],
        [None, Some(b"some aad 42")]
    )]
    #[tokio::test]
    async fn test_serde(bits: usize, aad: Option<&[u8]>) {
        let msg = b"foobar 123";

        // Encrypt
        let mut req = json!({"msg": BASE64_STANDARD.encode(msg)});
        if let Some(aad) = aad {
            req.as_object_mut().unwrap().insert(
                "aad".to_string(),
                Value::String(BASE64_STANDARD.encode(aad)),
            );
        }
        let response = router()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/encrypt?bits={bits}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        let b64 = |k| {
            BASE64_STANDARD
                .decode(body.as_object().unwrap()[k].as_str().unwrap())
                .unwrap()
        };
        let enc = aes::EncryptedPayload {
            key: b64("key"),
            nonce: b64("nonce"),
            ciphertext: b64("ciphertext"),
            tag: b64("tag"),
        };
        assert_eq!(enc.key.len() * 8, bits);

        // Decrypt
        let mut req = json!({
            "key": BASE64_STANDARD.encode(enc.key),
            "nonce": BASE64_STANDARD.encode(enc.nonce),
            "ciphertext": BASE64_STANDARD.encode(enc.ciphertext),
            "tag": BASE64_STANDARD.encode(enc.tag),
        });
        if let Some(aad) = aad {
            req.as_object_mut().unwrap().insert(
                "aad".to_string(),
                Value::String(BASE64_STANDARD.encode(aad)),
            );
        }
        let response = router()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/decrypt?bits={bits}"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        let b64 = |k| {
            BASE64_STANDARD
                .decode(body.as_object().unwrap()[k].as_str().unwrap())
                .unwrap()
        };
        assert_eq!(b64("msg"), msg);
    }

    #[tokio::test]
    async fn test_bad_bits() {
        let msg = b"foobar 123";
        let req = json!({"msg": BASE64_STANDARD.encode(msg)});

        let response = router()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/encrypt?bits=42"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body[..].to_vec()).unwrap();
        assert!(body.contains("bits"));
    }

    #[tokio::test]
    async fn test_crypto_error() {
        let msg = b"foobar 123";
        let mut enc = aes::encrypt_aes_256_gcm(&msg.to_vec(), None).unwrap();
        enc.key[0] ^= 1;

        let req = json!({
            "key": BASE64_STANDARD.encode(enc.key),
            "nonce": BASE64_STANDARD.encode(enc.nonce),
            "ciphertext": BASE64_STANDARD.encode(enc.ciphertext),
            "tag": BASE64_STANDARD.encode(enc.tag),
        });
        let response = router()
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri(format!("/decrypt?bits=256"))
                    .header(http::header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
                    .body(Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body[..].to_vec()).unwrap();
        assert!(body.contains("aes oracle error"));
    }
}
