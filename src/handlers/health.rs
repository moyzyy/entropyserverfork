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

use crate::db::redis::RedisManager;

pub struct HealthHandler {
    config: Arc<ServerConfig>,
    registry: Arc<Registry>,
    metrics: Arc<Metrics>,
    redis: Arc<RedisManager>,
}

impl HealthHandler {
    pub fn new(config: Arc<ServerConfig>, registry: Arc<Registry>, metrics: Arc<Metrics>, redis: Arc<RedisManager>) -> Self {
        Self { config, registry, metrics, redis }
    }

    pub async fn handle_health(&self) -> Response {
        let redis_healthy = self.redis.health_check().await;
        let status = if redis_healthy { "healthy" } else { "degraded" };
        
        let mut res = Json(json!({
            "status": status,
            "backend": if redis_healthy { "connected" } else { "disconnected" },
            "message": "Entropy Privacy Relay"
        })).into_response();
        
        self.add_headers(res.headers_mut());
        res
    }

    pub async fn handle_stats(&self, headers: &HeaderMap) -> Response {
        if !self.verify_admin_request(headers) {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }

        let redis_healthy = self.redis.health_check().await;
        let total_rejections = self.metrics.get_gauge("global_limit_rejected");

        let mut res = Json(json!({
            "active_connections": self.registry.connection_count() as i64,
            "redis_status": if redis_healthy { "up" } else { "down" },
            "rejections_since_restart": total_rejections as i64,
            "privacy_mode": "strict",
            "uptime_info": "Stateless relay"
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
    }
}
