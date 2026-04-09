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

use tokio::sync::RwLock;

pub struct HealthHandler {
    config: Arc<ServerConfig>,
    registry: Arc<Registry>,
    metrics: Arc<Metrics>,
    redis: Arc<RedisManager>,
    stats_cache: Arc<RwLock<(std::time::Instant, serde_json::Value)>>,
}

impl HealthHandler {
    pub fn new(config: Arc<ServerConfig>, registry: Arc<Registry>, metrics: Arc<Metrics>, redis: Arc<RedisManager>) -> Self {
        Self { 
            config, 
            registry, 
            metrics, 
            redis,
            stats_cache: Arc::new(RwLock::new((
                std::time::Instant::now() - std::time::Duration::from_secs(60),
                json!({})
            ))),
        }
    }

    pub async fn handle_health(&self) -> Response {
        let start = std::time::Instant::now();
        
        let redis_healthy = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            self.redis.health_check()
        ).await.unwrap_or(false);

        let latency_ms = start.elapsed().as_millis();
        
        let status = if redis_healthy && latency_ms < 500 { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
        
        let body = json!({
            "status": if redis_healthy { "UP" } else { "DOWN" },
            "version": env!("CARGO_PKG_VERSION"),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "checks": {
                "redis": {
                    "status": if redis_healthy { "connected" } else { "disconnected" },
                    "latency_ms": latency_ms
                }
            }
        });

        let mut res = (status, Json(body)).into_response();
        self.add_headers(res.headers_mut());
        res
    }

    pub async fn handle_stats(&self, headers: &HeaderMap) -> Response {
        if !self.verify_admin_request(headers) {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized"}))).into_response();
        }

        {
            let cache = self.stats_cache.read().await;
            if cache.0.elapsed() < std::time::Duration::from_secs(2) {
                let mut res = Json(cache.1.clone()).into_response();
                self.add_headers(res.headers_mut());
                return res;
            }
        }

        let mut cache_writer = self.stats_cache.write().await;
        
        
        use sysinfo::System;
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let process = sysinfo::get_current_pid().ok()
            .and_then(|pid| sys.process(pid));
        
        let mem_usage_mb = process.map(|p| p.memory() / 1024 / 1024).unwrap_or(0);

        let redis_stats = self.redis.get_deep_stats().await.unwrap_or(json!({}));
        
        let uptime = self.metrics.uptime_sec();
        
        let stats = json!({
            "process": {
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_seconds": uptime,
                "memory_rss_mb": mem_usage_mb,
                "cpu_usage_pct": process.map(|p| p.cpu_usage()).unwrap_or(0.0),
                "active_connections": self.registry.connection_count(),
            },
            "traffic": {
                "messages_relayed": self.metrics.get_counter("relay_messages_total") as i64,
                "bytes_processed": self.metrics.get_counter("relay_bytes_total") as i64,
                "avg_throughput_mps": self.metrics.get_counter("relay_messages_total") / (uptime as f64).max(1.0),
            },
            "security": {
                "auth_failures": self.metrics.get_counter("auth_failures_total") as i64,
                "global_rejections": self.metrics.get_counter("global_limit_rejected") as i64,
                "jail_threshold": self.config.violation_jail_threshold,
            },
            "database": {
                "redis_status": if self.redis.health_check().await { "up" } else { "down" },
                "redis_keys_total": redis_stats.get("total_keys"),
                "redis_memory": redis_stats.get("memory_usage_human"),
            },
            "system": {
                "os": System::name().unwrap_or_default(),
                "kernel": System::kernel_version().unwrap_or_default(),
                "cores": num_cpus::get(),
            }
        });

        *cache_writer = (std::time::Instant::now(), stats.clone());

        let mut res = Json(stats).into_response();
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
                use subtle::ConstantTimeEq;
                let actual = token_str.as_bytes();
                let expected = self.config.admin_token.as_bytes();
                if actual.len() == expected.len() {
                    return actual.ct_eq(expected).into();
                }
            }
        }
        false
    }

    fn add_headers(&self, headers: &mut HeaderMap) {
        headers.insert("Server", HeaderValue::from_static("Entropy/2.0"));
    }
}
