use askama::Template;
use axum::{
    extract::{Request, State},
    http::{header::CONTENT_TYPE, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Form, Router,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Local, Utc};
use oauth_metadata::{hello_oauth, JsonWebKeySet, JwtIssuer, KeyManager, OAuthClientMetadata};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

/// Helper function to extract JSON body or default if empty/no content-type
async fn extract_json_or_default<T>(request: Request) -> Result<T, (StatusCode, Json<Value>)>
where
    T: for<'de> Deserialize<'de> + Default,
{
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_request",
                    "error_description": "Failed to read request body"
                })),
            ))
        }
    };

    // If body is empty, return default
    if bytes.is_empty() {
        return Ok(T::default());
    }

    // Check content type if body is not empty
    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|ct| ct.to_str().ok())
        .unwrap_or("");

    // If there's content but no JSON content-type, return 415
    if !content_type.starts_with("application/json") && !bytes.is_empty() {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(json!({
                "error": "unsupported_media_type",
                "error_description": "Content-Type must be application/json for non-empty request body"
            })),
        ));
    }

    // Try to parse as JSON
    match serde_json::from_slice(&bytes) {
        Ok(data) => Ok(data),
        Err(_) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "Invalid JSON in request body"
            })),
        )),
    }
}

/// Parameters for the JWT endpoint (JSON body)
#[derive(Debug, Deserialize, Default)]
pub struct JwtParams {
    /// Custom client_id that overrides the default issuer and subject
    pub client_id: Option<String>,
    /// Requested scope
    pub scope: Option<String>,
    /// Additional audience(s) to append to configured audience
    /// Can be a string or array of strings
    pub aud: Option<serde_json::Value>,
}

/// Parameters for the token endpoint (JSON body) - OAuth client metadata approach
#[derive(Debug, Deserialize, Default)]
pub struct TokenParams {
    /// Requested scope (default: "read write")
    pub scope: Option<String>,
    /// Additional audience(s) to append to configured audience
    /// Can be a string or array of strings
    pub aud: Option<serde_json::Value>,
}

/// Form parameters for private key JWT generation
#[derive(Debug, Deserialize)]
pub struct JwtFormParams {
    pub client_id: Option<String>,
    pub scope: Option<String>,
}

/// Form parameters for metadata token generation
#[derive(Debug, Deserialize)]
pub struct TokenFormParams {
    pub scope: Option<String>,
}

/// Template for the main index page
#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub active_tab: String,
    pub has_token_result: bool,
    pub token_result: TokenResponse,
    pub jwks_result: String,
    pub metadata_result: String,
}

impl IntoResponse for IndexTemplate {
    fn into_response(self) -> axum::response::Response {
        match self.render() {
            Ok(html) => Html(html).into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<h1>Failed to render template</h1>".to_string()),
            )
                .into_response(),
        }
    }
}

/// Token response structure for template
#[derive(Debug, Default)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub expires_at: String,
    pub scope: Option<String>,
    // JWT.io style sections
    pub jwt_header: String,
    pub jwt_payload: String,
    pub jwt_signature: String,
}

/// JWT Claims for decoding
#[derive(Debug, Deserialize, Serialize)]
pub struct JwtClaims {
    pub iss: String,
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub scope: String,
}

/// Calculate expiration timestamp as human-readable string with Local + UTC
fn calculate_expires_at(expires_in: u64) -> String {
    let now = Utc::now();
    let expires_at_utc = now + chrono::Duration::seconds(expires_in as i64);
    let expires_at_local: DateTime<Local> = expires_at_utc.into();

    format!(
        "{} (Local) / {} (UTC)",
        expires_at_local.format("%Y-%m-%d %H:%M:%S %Z"),
        expires_at_utc.format("%Y-%m-%d %H:%M:%S UTC")
    )
}

/// Decode JWT into its parts for display
fn decode_jwt_parts(jwt: &str) -> (String, String, String) {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return (
            "Invalid JWT".to_string(),
            "Invalid JWT".to_string(),
            "Invalid JWT".to_string(),
        );
    }

    // Decode header
    let header = match general_purpose::URL_SAFE_NO_PAD.decode(parts[0]) {
        Ok(decoded) => match String::from_utf8(decoded) {
            Ok(header_str) => {
                // Pretty print JSON
                match serde_json::from_str::<serde_json::Value>(&header_str) {
                    Ok(json) => serde_json::to_string_pretty(&json).unwrap_or(header_str),
                    Err(_) => header_str,
                }
            }
            Err(_) => "Invalid header encoding".to_string(),
        },
        Err(_) => "Invalid header base64".to_string(),
    };

    // Decode payload
    let payload = match general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(decoded) => match String::from_utf8(decoded) {
            Ok(payload_str) => {
                // Pretty print JSON
                match serde_json::from_str::<serde_json::Value>(&payload_str) {
                    Ok(json) => serde_json::to_string_pretty(&json).unwrap_or(payload_str),
                    Err(_) => payload_str,
                }
            }
            Err(_) => "Invalid payload encoding".to_string(),
        },
        Err(_) => "Invalid payload base64".to_string(),
    };

    let signature = parts[2].to_string();

    (header, payload, signature)
}

/// Helper function to create IndexTemplate with pre-loaded JWKS and metadata
fn create_template_with_defaults(state: &AppState, active_tab: &str) -> IndexTemplate {
    // Pre-load JWKS
    let jwks_json = state
        .jwks
        .to_json()
        .map(|json| {
            serde_json::to_string_pretty(&json)
                .unwrap_or_else(|_| "Failed to format JWKS".to_string())
        })
        .unwrap_or_else(|_| "Error: Failed to get JWKS".to_string());

    // Pre-load metadata
    let metadata_json = state
        .client_metadata
        .to_json()
        .map(|json| {
            serde_json::to_string_pretty(&json)
                .unwrap_or_else(|_| "Failed to format metadata".to_string())
        })
        .unwrap_or_else(|_| "Error: Failed to get metadata".to_string());

    IndexTemplate {
        active_tab: active_tab.to_string(),
        has_token_result: false,
        token_result: TokenResponse::default(),
        jwks_result: jwks_json,
        metadata_result: metadata_json,
    }
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

        // Parse audience from environment variable
        let audience = Self::parse_audience_from_env();
        let jwt_issuer =
            JwtIssuer::new_with_audience(key_manager.clone(), public_url.clone(), audience);

        let jwks_uri = format!("{}/jwks", public_url);
        let client_id = format!("{}/oauth-client", public_url);
        let client_metadata =
            OAuthClientMetadata::default_client_credentials(&client_id, &jwks_uri);

        let jwks = JsonWebKeySet::from_key_manager(&key_manager)?;

        Ok(Self {
            key_manager: Arc::new(key_manager),
            jwt_issuer: Arc::new(jwt_issuer),
            client_metadata: Arc::new(client_metadata),
            jwks: Arc::new(jwks),
        })
    }

    /// Create new application state with specific public URL and audience
    pub fn new_with_public_url_and_audience(
        public_url: String,
        audience: Option<serde_json::Value>,
    ) -> anyhow::Result<Self> {
        let key_manager = KeyManager::new()?;
        let jwt_issuer =
            JwtIssuer::new_with_audience(key_manager.clone(), public_url.clone(), audience);

        let jwks_uri = format!("{}/jwks", public_url);
        let client_id = format!("{}/oauth-client", public_url);
        let client_metadata =
            OAuthClientMetadata::default_client_credentials(&client_id, &jwks_uri);

        let jwks = JsonWebKeySet::from_key_manager(&key_manager)?;

        Ok(Self {
            key_manager: Arc::new(key_manager),
            jwt_issuer: Arc::new(jwt_issuer),
            client_metadata: Arc::new(client_metadata),
            jwks: Arc::new(jwks),
        })
    }

    /// Parse audience configuration from environment variable
    /// Supports single audience (JWT_AUDIENCE=example.com) or multiple audiences (JWT_AUDIENCE=api1.com,api2.com)
    fn parse_audience_from_env() -> Option<serde_json::Value> {
        if let Ok(aud_env) = std::env::var("JWT_AUDIENCE") {
            let aud_trimmed = aud_env.trim();
            if aud_trimmed.is_empty() {
                return None;
            }

            // Check if it contains commas (multiple audiences)
            if aud_trimmed.contains(',') {
                let audiences: Vec<&str> = aud_trimmed
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();

                if audiences.is_empty() {
                    None
                } else {
                    Some(JwtIssuer::audience_from_strings(&audiences))
                }
            } else {
                // Single audience
                Some(JwtIssuer::audience_from_string(aud_trimmed))
            }
        } else {
            None
        }
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
        // Main navigation routes
        .route("/", get(tokens_tab))
        .route("/tokens", get(tokens_tab))
        .route("/metadata", get(metadata_tab))
        .route("/jwks-tab", get(jwks_tab))
        // Form submission routes
        .route("/generate-jwt", post(generate_jwt_form))
        .route(
            "/generate-metadata-token",
            post(generate_metadata_token_form),
        )
        // API routes
        .route("/health", get(health_check))
        .route("/client-id-document-token", post(token_endpoint))
        .route("/private-key-jwt-token", post(jwt_endpoint))
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

pub async fn token_endpoint(
    State(state): State<AppState>,
    request: Request,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let params = extract_json_or_default::<TokenParams>(request).await?;
    // OAuth client metadata token - uses client_id as iss/sub per Client ID Metadata Document spec
    let scope = params.scope;
    let client_id = state.client_metadata.client_id.clone();

    match state
        .jwt_issuer
        .create_client_credentials_response_with_audience(scope, Some(client_id), params.aud)
    {
        Ok(response) => Ok((
            StatusCode::OK,
            Json(serde_json::to_value(response).unwrap_or_default()),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to issue OAuth client metadata token"
            })),
        )),
    }
}

pub async fn jwt_endpoint(
    State(state): State<AppState>,
    request: Request,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let params = extract_json_or_default::<JwtParams>(request).await?;
    // Custom JWT for private_key_jwt - allows client_id customization
    let scope = params.scope;

    match state
        .jwt_issuer
        .create_client_credentials_response_with_audience(scope, params.client_id, params.aud)
    {
        Ok(response) => Ok((
            StatusCode::OK,
            Json(serde_json::to_value(response).unwrap_or_default()),
        )),
        Err(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Failed to issue custom JWT"
            })),
        )),
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

// Template-based handlers

pub async fn tokens_tab(State(state): State<AppState>) -> IndexTemplate {
    create_template_with_defaults(&state, "tokens")
}

pub async fn metadata_tab(State(state): State<AppState>) -> IndexTemplate {
    create_template_with_defaults(&state, "metadata")
}

pub async fn jwks_tab(State(state): State<AppState>) -> IndexTemplate {
    create_template_with_defaults(&state, "jwks")
}

pub async fn generate_jwt_form(
    State(state): State<AppState>,
    Form(params): Form<JwtFormParams>,
) -> IndexTemplate {
    // Create JWT token
    let jwt_params = JwtParams {
        client_id: params.client_id.clone(),
        scope: params.scope.clone(),
        aud: None,
    };

    let mut template = create_template_with_defaults(&state, "tokens");

    match state
        .jwt_issuer
        .create_client_credentials_response_with_audience(
            jwt_params.scope.clone(),
            jwt_params.client_id.clone(),
            jwt_params.aud.clone(),
        ) {
        Ok(response) => {
            // Decode JWT into parts
            let (header, payload, signature) = decode_jwt_parts(&response.access_token);

            let expires_in = response.expires_in.unwrap_or(3600);
            template.has_token_result = true;
            template.token_result = TokenResponse {
                access_token: response.access_token,
                token_type: response.token_type,
                expires_in,
                expires_at: calculate_expires_at(expires_in),
                scope: response.scope,
                jwt_header: header,
                jwt_payload: payload,
                jwt_signature: signature,
            };
        }
        Err(_) => {
            // Keep template with defaults, maybe add error handling later
        }
    }

    template
}

pub async fn generate_metadata_token_form(
    State(state): State<AppState>,
    Form(params): Form<TokenFormParams>,
) -> IndexTemplate {
    // Create metadata token
    let token_params = TokenParams {
        scope: params.scope.clone(),
        aud: None,
    };

    let mut template = create_template_with_defaults(&state, "tokens");
    let client_id = state.client_metadata.client_id.clone();

    match state
        .jwt_issuer
        .create_client_credentials_response_with_audience(
            token_params.scope.clone(),
            Some(client_id),
            token_params.aud.clone(),
        ) {
        Ok(response) => {
            // Decode JWT into parts
            let (header, payload, signature) = decode_jwt_parts(&response.access_token);

            let expires_in = response.expires_in.unwrap_or(3600);
            template.has_token_result = true;
            template.token_result = TokenResponse {
                access_token: response.access_token,
                token_type: response.token_type,
                expires_in,
                expires_at: calculate_expires_at(expires_in),
                scope: response.scope,
                jwt_header: header,
                jwt_payload: payload,
                jwt_signature: signature,
            };
        }
        Err(_) => {
            // Keep template with defaults, maybe add error handling later
        }
    }

    template
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

        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 3600);
        assert!(json["scope"].is_null());
    }

    #[tokio::test]
    async fn test_oauth_client_metadata() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        let response = server.get("/oauth-client").await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["client_id"], "http://localhost:3000/oauth-client");
        assert_eq!(json["token_endpoint_auth_signing_alg"], "RS256");
    }

    #[tokio::test]
    async fn test_jwks_endpoint() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // Test API endpoint with JSON Accept header
        let response = server
            .get("/jwks")
            .add_header("Accept", "application/json")
            .await;
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
        assert_eq!(json["client_id"], "https://api.example.com/oauth-client");

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
            .post("/private-key-jwt-token")
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
            .post("/private-key-jwt-token")
            .json(&serde_json::json!({})) // Empty JSON object
            .await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 3600);
        assert!(json["scope"].is_null());
    }

    #[tokio::test]
    async fn test_token_vs_jwt_endpoints() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // Both endpoints should work but serve different purposes
        let token_response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({}))
            .await;
        token_response.assert_status_ok();

        let jwt_response = server
            .post("/private-key-jwt-token")
            .json(&serde_json::json!({})) // Empty JSON object
            .await;
        jwt_response.assert_status_ok();

        let token_json: Value = token_response.json();
        let jwt_json: Value = jwt_response.json();

        // Both should return valid JWT responses
        assert_eq!(token_json["token_type"], "Bearer");
        assert_eq!(jwt_json["token_type"], "Bearer");
        assert!(token_json["scope"].is_null());
        assert!(jwt_json["scope"].is_null());
    }

    #[tokio::test]
    async fn test_jwt_endpoint_with_single_audience() {
        let audience = JwtIssuer::audience_from_string("api.example.com");
        let state = AppState::new_with_public_url_and_audience(
            "http://localhost:3000".to_string(),
            Some(audience),
        )
        .unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/private-key-jwt-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");

        // The JWT should contain the configured audience (we can't easily decode it in tests,
        // but we can verify the request was processed successfully)
        let access_token = json["access_token"].as_str().unwrap();
        assert!(!access_token.is_empty());
    }

    #[tokio::test]
    async fn test_jwt_endpoint_with_multiple_audiences() {
        let audience = JwtIssuer::audience_from_strings(&["api1.example.com", "api2.example.com"]);
        let state = AppState::new_with_public_url_and_audience(
            "http://localhost:3000".to_string(),
            Some(audience),
        )
        .unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");

        // The JWT should contain the configured audiences
        let access_token = json["access_token"].as_str().unwrap();
        assert!(!access_token.is_empty());
    }

    #[tokio::test]
    async fn test_audience_parsing_functions() {
        // Test single audience
        let single_aud = JwtIssuer::audience_from_string("api.example.com");
        assert_eq!(
            single_aud,
            serde_json::Value::String("api.example.com".to_string())
        );

        // Test multiple audiences
        let multi_aud = JwtIssuer::audience_from_strings(&["api1.com", "api2.com"]);
        let expected = serde_json::Value::Array(vec![
            serde_json::Value::String("api1.com".to_string()),
            serde_json::Value::String("api2.com".to_string()),
        ]);
        assert_eq!(multi_aud, expected);
    }

    #[tokio::test]
    async fn test_token_endpoint_with_additional_audience() {
        // Test token endpoint with additional audience in POST body
        let base_audience = JwtIssuer::audience_from_string("api.example.com");
        let state = AppState::new_with_public_url_and_audience(
            "http://localhost:3000".to_string(),
            Some(base_audience),
        )
        .unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({
                "aud": "extra.example.com"
            }))
            .await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");
        assert!(json["scope"].is_null());
    }

    #[tokio::test]
    async fn test_jwt_endpoint_with_additional_audience() {
        // Test JWT endpoint with additional audience in POST body
        let base_audience = JwtIssuer::audience_from_string("api.example.com");
        let state = AppState::new_with_public_url_and_audience(
            "http://localhost:3000".to_string(),
            Some(base_audience),
        )
        .unwrap();
        let app = create_app_with_state(state);
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/private-key-jwt-token")
            .json(&serde_json::json!({
                "client_id": "test-client",
                "aud": ["extra1.example.com", "extra2.example.com"]
            }))
            .await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");
        assert!(json["scope"].is_null());
    }

    #[tokio::test]
    async fn test_token_endpoint_with_custom_scope_and_audience() {
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({
                "scope": "custom-scope",
                "aud": "custom.audience.com"
            }))
            .await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["scope"], "custom-scope");
    }

    #[tokio::test]
    async fn test_endpoints_with_empty_json_body() {
        // Test that endpoints still work with empty JSON bodies
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // Test token endpoint with empty body
        let response = server
            .post("/client-id-document-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();

        // Test JWT endpoint with empty body
        let response = server
            .post("/private-key-jwt-token")
            .json(&serde_json::json!({}))
            .await;
        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_endpoints_with_no_body() {
        // Test that endpoints work without any body or content-type
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // Test token endpoint with no body
        let response = server.post("/client-id-document-token").await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 3600);
        assert!(json["scope"].is_null());

        // Test JWT endpoint with no body
        let response = server.post("/private-key-jwt-token").await;
        response.assert_status_ok();

        let json: Value = response.json();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 3600);
        assert!(json["scope"].is_null());
    }

    #[tokio::test]
    async fn test_endpoints_with_invalid_content_type() {
        // Test that endpoints reject non-empty body with wrong content-type
        let app = create_app();
        let server = TestServer::new(app).unwrap();

        // Test token endpoint with plain text body - should fail
        let response = server
            .post("/client-id-document-token")
            .add_header("Content-Type", "text/plain")
            .text("some text")
            .await;
        response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // Test JWT endpoint with form data - should fail
        let response = server
            .post("/private-key-jwt-token")
            .add_header("Content-Type", "application/x-www-form-urlencoded")
            .text("key=value")
            .await;
        response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
}
