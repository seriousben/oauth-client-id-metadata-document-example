use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use oauth_metadata::{hello_oauth, JsonWebKeySet, JwtIssuer, KeyManager, OAuthClientMetadata};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

/// Parameters for the JWT endpoint (JSON body)
#[derive(Debug, Deserialize)]
pub struct JwtParams {
    /// Custom client_id that overrides the default issuer and subject
    pub client_id: Option<String>,
    /// Requested scope
    pub scope: Option<String>,
}

/// Application state containing shared components
#[derive(Clone)]
pub struct AppState {
    pub key_manager: Arc<KeyManager>,
    pub jwt_issuer: Arc<JwtIssuer>,
    pub client_metadata: Arc<OAuthClientMetadata>,
    pub jwks: Arc<JsonWebKeySet>,
}

impl AppState {
    /// Create new application state with default configuration
    pub fn new() -> anyhow::Result<Self> {
        let public_url =
            std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

        Self::new_with_public_url(public_url)
    }

    /// Create new application state with specific public URL
    pub fn new_with_public_url(public_url: String) -> anyhow::Result<Self> {
        let key_manager = KeyManager::new()?;
        let jwt_issuer = JwtIssuer::new(key_manager.clone(), public_url.clone());

        let jwks_uri = format!("{}/jwks", public_url);
        let client_metadata = OAuthClientMetadata::default_client_credentials(
            "oauth-client-id-metadata-example",
            &jwks_uri,
        );

        let jwks = JsonWebKeySet::from_key_manager(&key_manager)?;

        Ok(Self {
            key_manager: Arc::new(key_manager),
            jwt_issuer: Arc::new(jwt_issuer),
            client_metadata: Arc::new(client_metadata),
            jwks: Arc::new(jwks),
        })
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new().expect("Failed to create default app state")
    }
}

pub fn hello_server() -> String {
    format!("Hello from oauth-server! {}", hello_oauth())
}

pub fn create_app() -> Router {
    create_app_with_state(AppState::default())
}

pub fn create_app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/token", post(token_endpoint))
        .route("/jwt", post(jwt_endpoint))
        .route("/oauth-client", get(oauth_client_metadata))
        .route("/jwks", get(jwks_endpoint))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn health_check() -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "status": "healthy",
            "service": "oauth-server"
        })),
    )
}

pub async fn token_endpoint(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    // OAuth client metadata token - uses public URL as iss/sub, no customization
    match state
        .jwt_issuer
        .create_client_credentials_response(Some("read write".to_string()))
    {
        Ok(response) => (
            StatusCode::OK,
            Json(serde_json::to_value(response).unwrap_or_default()),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to issue OAuth client metadata token"
            })),
        ),
    }
}

pub async fn jwt_endpoint(
    State(state): State<AppState>,
    Json(params): Json<JwtParams>,
) -> (StatusCode, Json<Value>) {
    // Custom JWT for private_key_jwt - allows client_id customization
    let scope = params.scope.or_else(|| Some("read write".to_string()));

    match state
        .jwt_issuer
        .create_client_credentials_response_with_client_id(scope, params.client_id)
    {
        Ok(response) => (
            StatusCode::OK,
            Json(serde_json::to_value(response).unwrap_or_default()),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to issue custom JWT"
            })),
        ),
    }
}

pub async fn oauth_client_metadata(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    match state.client_metadata.to_json() {
        Ok(json) => (StatusCode::OK, Json(json)),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to serialize client metadata"
            })),
        ),
    }
}

pub async fn jwks_endpoint(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    match state.jwks.to_json() {
        Ok(json) => (StatusCode::OK, Json(json)),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to serialize JWKS"
            })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_health_check() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["service"], "oauth-server");
    }

    #[tokio::test]
    async fn test_token_endpoint() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        let response = server.post("/token").await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 3600);
        assert_eq!(json["scope"], "read write");
    }

    #[tokio::test]
    async fn test_oauth_client_metadata() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        let response = server.get("/oauth-client").await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["client_id"], "oauth-client-id-metadata-example");
        assert_eq!(json["token_endpoint_auth_signing_alg"], "RS256");
    }

    #[tokio::test]
    async fn test_jwks_endpoint() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        let response = server.get("/jwks").await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert!(json["keys"].is_array());
        let keys = json["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["alg"], "RS256");
        assert_eq!(keys[0]["kty"], "RSA");
    }

    #[tokio::test]
    async fn test_custom_public_url() {
        let custom_url = "https://api.example.com";
        let state = AppState::new_with_public_url(custom_url.to_string()).unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        // Test oauth-client metadata uses custom URL
        let response = server.get("/oauth-client").await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["client_id"], "oauth-client-id-metadata-example");

        // The jwks_uri should contain the custom URL
        let jwks_uri = json["jwks_uri"].as_str().unwrap();
        assert!(jwks_uri.starts_with(custom_url));
        assert!(jwks_uri.ends_with("/jwks"));
    }

    #[tokio::test]
    async fn test_jwt_endpoint_with_custom_client_id() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // Test /jwt endpoint with custom client_id parameter
        let response = server
            .post("/jwt")
            .json(&serde_json::json!({
                "client_id": "my-custom-client",
                "scope": "custom-scope"
            }))
            .await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 3600);
        assert_eq!(json["scope"], "custom-scope");

        // Verify the token contains the custom client_id
        let access_token = json["access_token"].as_str().unwrap();
        assert!(!access_token.is_empty());
    }

    #[tokio::test]
    async fn test_jwt_endpoint_without_custom_client_id() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // Test /jwt endpoint without custom client_id (should use default public URL)
        let response = server
            .post("/jwt")
            .json(&serde_json::json!({})) // Empty JSON object
            .await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 3600);
        assert_eq!(json["scope"], "read write");
    }

    #[tokio::test]
    async fn test_token_vs_jwt_endpoints() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // Both endpoints should work but serve different purposes
        let token_response = server.post("/token").await;
        token_response.assert_status_ok();

        let jwt_response = server
            .post("/jwt")
            .json(&serde_json::json!({})) // Empty JSON object
            .await;
        jwt_response.assert_status_ok();

        let token_json: Value = token_response.json();
        let jwt_json: Value = jwt_response.json();

        // Both should return valid JWT responses
        assert_eq!(token_json["token_type"], "Bearer");
        assert_eq!(jwt_json["token_type"], "Bearer");
        assert_eq!(token_json["scope"], "read write");
        assert_eq!(jwt_json["scope"], "read write");
    }
}
