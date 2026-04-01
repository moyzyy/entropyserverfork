use serde_json::json;
use axum::{
    http::{StatusCode, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use crate::config::ServerConfig;
use crate::server::registry::Registry;
use crate::telemetry::metrics::Metrics;

pub struct HealthHandler {
    config: Arc<ServerConfig>,
    registry: Arc<Registry>,
    metrics: Arc<Metrics>,
}

impl HealthHandler {
    pub fn new(config: Arc<ServerConfig>, registry: Arc<Registry>, metrics: Arc<Metrics>) -> Self {
        Self { config, registry, metrics }
    }

    pub async fn handle_health(&self) -> Response {
        let mut res = Json(json!({
            "status": "healthy",
            "storage": "none",
            "message": "Ephemeral relay only - no data stored",
            "tls": self.config.enable_tls
        })).into_response();
        
        self.add_headers(res.headers_mut());
        res
    }

    pub async fn handle_stats(&self, headers: &HeaderMap) -> Response {
        if !self.verify_admin_request(headers) {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }

        let mut res = Json(json!({
            "active_connections": self.registry.connection_count() as i64,
            "uptime_info": "Server stores ZERO messages"
        })).into_response();
        
        self.add_headers(res.headers_mut());
        res
    }

    pub async fn handle_metrics(&self, headers: &HeaderMap) -> Response {
        if !self.verify_admin_request(headers) {
             return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }

        let body = self.metrics.collect_prometheus();
        let mut res = body.into_response();
        
        res.headers_mut().insert("Content-Type", HeaderValue::from_static("text/plain; version=0.0.4"));
        self.add_headers(res.headers_mut());
        res
    }

    pub fn verify_admin_request(&self, headers: &HeaderMap) -> bool {
        if self.config.admin_token.is_empty() {
            return false;
        }

        if let Some(token) = headers.get("X-Admin-Token") {
            if let Ok(token_str) = token.to_str() {
                return token_str == self.config.admin_token;
            }
        }
        false
    }

    fn add_headers(&self, headers: &mut HeaderMap) {
        headers.insert("Server", HeaderValue::from_static("Entropy/2.0"));
        headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
        headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
        headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
        headers.insert("Strict-Transport-Security", HeaderValue::from_static("max-age=31536000; includeSubDomains"));
        headers.insert("Content-Security-Policy", HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"));
        
        // CORS
        headers.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
        headers.insert("Access-Control-Allow-Methods", HeaderValue::from_static("GET, POST, OPTIONS"));
        headers.insert("Access-Control-Allow-Headers", HeaderValue::from_static("Content-Type, Authorization, X-Admin-Token"));
    }
}
