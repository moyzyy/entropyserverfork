use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub redis_url: String,
    pub redis_password: Option<String>,
    pub redis_username: Option<String>,
    pub thread_count: usize,
    
    // TLS
    pub enable_tls: bool,
    pub cert_path: String,
    pub key_path: String,
    
    // Resource Limits
    pub max_message_size: usize,
    pub max_connections_per_ip: usize,
    pub max_global_connections: usize,
    pub connection_timeout_sec: u64,
    pub websocket_ping_interval_sec: u64,
    
    // Rate Limiting
    pub rate_limit_per_sec: f64,
    pub rate_limit_burst: usize,
    
    // PoW
    pub pow_rate_limit: i32,
    
    // Redis-backed Window Limits
    pub global_rate_limit: i32,
    pub keys_upload_limit: i32,
    pub keys_fetch_limit: i32,
    pub keys_random_limit: i32,
    pub relay_limit: i32,
    pub nick_register_limit: i32,
    pub nick_lookup_limit: i32,
    pub account_burn_limit: i32,

    // Keys
    pub secret_salt: String,
    pub admin_token: String,
    
    // CORS
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    
    // Protocol
    pub max_nickname_length: usize,
    pub max_prekeys_per_upload: usize,
    pub max_pow_difficulty: i32,
    pub max_json_depth: usize,

    // Traffic Pacing
    pub pacing: PacingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacingConfig {
    pub idle_threshold_ms: u64,
    pub packet_size: usize,
    pub tick_interval_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".to_string(),
            port: 8080,
            redis_url: "redis://127.0.0.1:6379".to_string(),
            redis_password: None,
            redis_username: None,
            thread_count: num_cpus::get(),
            enable_tls: false,
            cert_path: "certs/server.crt".to_string(),
            key_path: "certs/server.key".to_string(),
            max_message_size: 5 * 1024 * 1024,
            max_connections_per_ip: 10,
            max_global_connections: 100000,
            connection_timeout_sec: 60,
            websocket_ping_interval_sec: 15,
            rate_limit_per_sec: 200.0,
            rate_limit_burst: 400,
            pow_rate_limit: 20,
            global_rate_limit: 300,
            keys_upload_limit: 10,
            keys_fetch_limit: 50,
            keys_random_limit: 20,
            relay_limit: 150,
            nick_register_limit: 5,
            nick_lookup_limit: 30,
            account_burn_limit: 3,
            secret_salt: "entropy_default_deployment_salt".to_string(),
            admin_token: "".to_string(),
            allowed_origins: vec!["localhost".to_string(), "127.0.0.1".to_string(), "tauri://".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "OPTIONS".to_string()],
            allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
            max_nickname_length: 32,
            max_prekeys_per_upload: 100,
            max_pow_difficulty: 5,
            max_json_depth: 16,
            pacing: PacingConfig {
                idle_threshold_ms: 5000,
                packet_size: 1536,
                tick_interval_ms: 500,
            },
        }
    }
}

impl ServerConfig {
    pub fn load() -> Self {
        let _ = dotenvy::dotenv();
        
        let mut config = Self::default();

        if let Ok(addr) = env::var("ENTROPY_ADDR") { config.address = addr; }
        if let Ok(port) = env::var("ENTROPY_PORT") { config.port = port.parse().unwrap_or(8080); }
        if let Ok(redis) = env::var("ENTROPY_REDIS_URL") { config.redis_url = redis; }
        if let Ok(salt) = env::var("ENTROPY_SECRET_SALT") { config.secret_salt = salt; }
        if let Ok(admin) = env::var("ENTROPY_ADMIN_TOKEN") { config.admin_token = admin; }
        
        if let Ok(origins) = env::var("ENTROPY_ALLOWED_ORIGINS") {
            config.allowed_origins = origins.split(',').map(|s| s.to_string()).collect();
        }

        if let Ok(val) = env::var("ENTROPY_MAX_CONNS_PER_IP") {
            config.max_connections_per_ip = val.parse().unwrap_or(config.max_connections_per_ip);
        }

        if let Ok(val) = env::var("ENTROPY_RATE_LIMIT") {
            if let Ok(rate) = val.parse::<f64>() {
                config.rate_limit_per_sec = rate;
                config.rate_limit_burst = (rate * 2.0) as usize;
            }
        }

        if let Ok(val) = env::var("ENTROPY_POW_LIMIT") {
            config.pow_rate_limit = val.parse().unwrap_or(config.pow_rate_limit);
        }

        if let Ok(val) = env::var("ENTROPY_LIMIT_GLOBAL") { config.global_rate_limit = val.parse().unwrap_or(config.global_rate_limit); }
        if let Ok(val) = env::var("ENTROPY_LIMIT_KEYS_UPLOAD") { config.keys_upload_limit = val.parse().unwrap_or(config.keys_upload_limit); }
        if let Ok(val) = env::var("ENTROPY_LIMIT_KEYS_FETCH") { config.keys_fetch_limit = val.parse().unwrap_or(config.keys_fetch_limit); }
        if let Ok(val) = env::var("ENTROPY_LIMIT_KEYS_RANDOM") { config.keys_random_limit = val.parse().unwrap_or(config.keys_random_limit); }
        if let Ok(val) = env::var("ENTROPY_LIMIT_RELAY") { config.relay_limit = val.parse().unwrap_or(config.relay_limit); }
        if let Ok(val) = env::var("ENTROPY_LIMIT_NICK_REGISTER") { config.nick_register_limit = val.parse().unwrap_or(config.nick_register_limit); }
        if let Ok(val) = env::var("ENTROPY_LIMIT_NICK_LOOKUP") { config.nick_lookup_limit = val.parse().unwrap_or(config.nick_lookup_limit); }
        if let Ok(val) = env::var("ENTROPY_LIMIT_ACCOUNT_BURN") { config.account_burn_limit = val.parse().unwrap_or(config.account_burn_limit); }

        config
    }
}
