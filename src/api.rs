use axum::{routing::get, Json, Router};

use super::aes::api::router as aes_router;

pub async fn ping() -> Json<String> {
    Json(String::from("pong"))
}

pub fn app() -> Router {
    Router::new()
        .route("/ping", get(ping))
        .nest("/aes-gcm", aes_router())
}

pub mod serde_base64 {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(val: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        String::serialize(&BASE64_STANDARD.encode(val), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        BASE64_STANDARD
            .decode(String::deserialize(d)?.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

pub mod serde_base64_opt {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(val: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        Option::<String>::serialize(&val.as_ref().map(|x| BASE64_STANDARD.encode(x)), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let val = Option::<String>::deserialize(d)?;
        match val {
            Some(base64) => BASE64_STANDARD
                .decode(base64.as_bytes())
                .map_err(serde::de::Error::custom)
                .map(Some),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    #[tokio::test]
    async fn ping() {
        let app = app();

        let response = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!("pong"));
    }
}
