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
    pub max_global_connections: usize,
    pub connection_timeout_sec: u64,
    pub session_ttl_sec: u64,
    
    // Rate Limiting
    pub rate_limit_per_sec: f64,
    pub rate_limit_burst: usize,
    
    // PoW
    pub pow_base_difficulty: i32,
    
    // Redis-backed Window Limits
    pub global_rate_limit: i32,
    pub keys_upload_limit: i32,
    pub keys_fetch_limit: i32,
    pub relay_limit: i32,
    pub nick_register_limit: i32,
    pub nick_lookup_limit: i32,
    pub account_burn_limit: i32,

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
    pub max_offline_messages: usize,
    
    // Traffic Pacing
    pub pacing: PacingConfig,
    
    // VDF (Hardened)
    pub vdf_modulus: String,
    pub vdf_phi: String,
    pub jail_duration_sec: u64,
    pub violation_reset_sec: u64,
    pub registration_intensity_low: u32,
    pub registration_intensity_high: u32,
    pub identity_violation_threshold: u64,
    pub violation_jail_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacingConfig {
    pub packet_size: usize,
    pub tick_interval_ms: u64,
}

impl ServerConfig {
    pub fn load() -> Self {
        let _ = dotenvy::dotenv();
        
        Self {
            address: env::var("ENTROPY_ADDR").expect("ENTROPY_ADDR missing"),
            port: env::var("ENTROPY_PORT").expect("ENTROPY_PORT missing").parse().expect("Invalid port"),
            redis_url: env::var("ENTROPY_REDIS_URL").expect("ENTROPY_REDIS_URL missing"),
            redis_password: env::var("ENTROPY_REDIS_PASSWORD").ok(),
            redis_username: env::var("ENTROPY_REDIS_USERNAME").ok(),
            thread_count: num_cpus::get(),
            enable_tls: env::var("ENTROPY_ENABLE_TLS").expect("ENTROPY_ENABLE_TLS missing") == "true",
            cert_path: env::var("ENTROPY_CERT_PATH").expect("ENTROPY_CERT_PATH missing"),
            key_path: env::var("ENTROPY_KEY_PATH").expect("ENTROPY_KEY_PATH missing"),
            max_message_size: env::var("ENTROPY_MAX_MSG_SIZE").expect("ENTROPY_MAX_MSG_SIZE missing").parse().expect("Invalid size"),
            max_global_connections: env::var("ENTROPY_MAX_GLOBAL_CONNS").expect("ENTROPY_MAX_GLOBAL_CONNS missing").parse().expect("Invalid count"),
            connection_timeout_sec: env::var("ENTROPY_CONN_TIMEOUT").expect("ENTROPY_CONN_TIMEOUT missing").parse().expect("Invalid timeout"),
            session_ttl_sec: env::var("ENTROPY_SESSION_TTL").expect("ENTROPY_SESSION_TTL missing").parse().expect("Invalid TTL"),
            jail_duration_sec: env::var("ENTROPY_JAIL_TTL").unwrap_or_else(|_| "300".to_string()).parse().expect("Invalid Jail TTL"),
            violation_reset_sec: env::var("ENTROPY_VIOL_RESET").unwrap_or_else(|_| "3600".to_string()).parse().expect("Invalid Viol Reset TTL"),
            rate_limit_per_sec: env::var("ENTROPY_RATE_LIMIT").expect("ENTROPY_RATE_LIMIT missing").parse().expect("Invalid rate"),
            rate_limit_burst: env::var("ENTROPY_RATE_BURST").expect("ENTROPY_RATE_BURST missing").parse().expect("Invalid burst"),
            pow_base_difficulty: env::var("ENTROPY_POW_BASE").expect("ENTROPY_POW_BASE missing").parse().expect("Invalid difficulty"),
            global_rate_limit: env::var("ENTROPY_LIMIT_GLOBAL").expect("ENTROPY_LIMIT_GLOBAL missing").parse().expect("Invalid limit"),
            keys_upload_limit: env::var("ENTROPY_LIMIT_KEYS_UPLOAD").expect("ENTROPY_LIMIT_KEYS_UPLOAD missing").parse().expect("Invalid limit"),
            keys_fetch_limit: env::var("ENTROPY_LIMIT_KEYS_FETCH").expect("ENTROPY_LIMIT_KEYS_FETCH missing").parse().expect("Invalid limit"),
            relay_limit: env::var("ENTROPY_LIMIT_RELAY").expect("ENTROPY_LIMIT_RELAY missing").parse().expect("Invalid limit"),
            nick_register_limit: env::var("ENTROPY_LIMIT_NICK_REGISTER").expect("ENTROPY_LIMIT_NICK_REGISTER missing").parse().expect("Invalid limit"),
            nick_lookup_limit: env::var("ENTROPY_LIMIT_NICK_LOOKUP").expect("ENTROPY_LIMIT_NICK_LOOKUP missing").parse().expect("Invalid limit"),
            account_burn_limit: env::var("ENTROPY_LIMIT_ACCOUNT_BURN").expect("ENTROPY_LIMIT_ACCOUNT_BURN missing").parse().expect("Invalid limit"),
            admin_token: env::var("ENTROPY_ADMIN_TOKEN").expect("ENTROPY_ADMIN_TOKEN missing"),
            allowed_origins: env::var("ENTROPY_ALLOWED_ORIGINS").expect("ENTROPY_ALLOWED_ORIGINS missing").split(',').map(|s| s.to_string()).collect(),
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "OPTIONS".to_string()],
            allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
            max_nickname_length: env::var("ENTROPY_MAX_NICK_LEN").expect("ENTROPY_MAX_NICK_LEN missing").parse().expect("Invalid length"),
            max_prekeys_per_upload: env::var("ENTROPY_MAX_PREKEYS").expect("ENTROPY_MAX_PREKEYS missing").parse().expect("Invalid count"),
            max_pow_difficulty: env::var("ENTROPY_POW_DIFF").expect("ENTROPY_POW_DIFF missing").parse().expect("Invalid diff"),
            max_json_depth: env::var("ENTROPY_MAX_JSON_DEPTH").expect("ENTROPY_MAX_JSON_DEPTH missing").parse().expect("Invalid depth"),
            max_offline_messages: env::var("ENTROPY_MAX_OFFLINE_MSGS").expect("ENTROPY_MAX_OFFLINE_MSGS missing").parse().expect("Invalid count"),
            pacing: PacingConfig {
                packet_size: env::var("ENTROPY_PACING_SIZE").expect("ENTROPY_PACING_SIZE missing").parse().expect("Invalid size"),
                tick_interval_ms: env::var("ENTROPY_PACING_TICK").expect("ENTROPY_PACING_TICK missing").parse().expect("Invalid tick"),
            },
            vdf_modulus: env::var("ENTROPY_VDF_MODULUS").expect("ENTROPY_VDF_MODULUS missing"),
            vdf_phi: env::var("ENTROPY_VDF_PHI").expect("ENTROPY_VDF_PHI missing"),
            registration_intensity_low: env::var("ENTROPY_INTENSITY_LOW").unwrap_or_else(|_| "10".to_string()).parse().expect("Invalid intensity"),
            registration_intensity_high: env::var("ENTROPY_INTENSITY_HIGH").unwrap_or_else(|_| "50".to_string()).parse().expect("Invalid intensity"),
            identity_violation_threshold: env::var("ENTROPY_VIOL_LIMIT").unwrap_or_else(|_| "3".to_string()).parse().expect("Invalid violation limit"),
            violation_jail_threshold: env::var("ENTROPY_VIOL_THRESHOLD").unwrap_or_else(|_| "5".to_string()).parse().expect("Invalid threshold"),
        }
    }
}
