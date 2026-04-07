use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub redis_url: String,
    pub redis_password: Option<String>,
    pub redis_username: Option<String>,
    
    // Resource Limits
    pub max_message_size: usize,
    pub max_global_connections: usize,
    pub connection_timeout_sec: u64,
    pub session_ttl_sec: u64,
    pub offline_ttl_sec: u64,
    
    // Rate Limiting
    pub rate_limit_per_sec: f64,
    pub rate_limit_burst: usize,
    pub relay_window_sec: i64,
    pub keys_window_sec: i64,
    
    // PoW
    pub pow_base_difficulty: i32,
    
    // Redis-backed Window Limits
    pub keys_upload_limit: i32,
    pub relay_limit: i32,
    pub nick_register_limit: i32,
    pub media_limit: i32,
    pub lookup_limit: i32,
    pub key_fetch_limit: i32,

    pub admin_token: String,
    
    // Protocol
    pub max_nickname_length: usize,
    pub max_prekeys_per_upload: usize,
    pub max_pow_difficulty: i32,
    pub max_json_depth: usize,
    pub max_offline_messages: usize,
    pub max_offline_messages_per_sender: usize,
    
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
            max_message_size: env::var("ENTROPY_MAX_MSG_SIZE").expect("ENTROPY_MAX_MSG_SIZE missing").parse().expect("Invalid size"),
            max_global_connections: env::var("ENTROPY_MAX_GLOBAL_CONNS").expect("ENTROPY_MAX_GLOBAL_CONNS missing").parse().expect("Invalid count"),
            connection_timeout_sec: env::var("ENTROPY_CONN_TIMEOUT").expect("ENTROPY_CONN_TIMEOUT missing").parse().expect("Invalid timeout"),
            session_ttl_sec: env::var("ENTROPY_SESSION_TTL").expect("ENTROPY_SESSION_TTL missing").parse().expect("Invalid TTL"),
            offline_ttl_sec: env::var("ENTROPY_OFFLINE_TTL").unwrap_or_else(|_| "86400".to_string()).parse().expect("Invalid TTL"),
            jail_duration_sec: env::var("ENTROPY_JAIL_TTL").unwrap_or_else(|_| "300".to_string()).parse().expect("Invalid Jail TTL"),
            violation_reset_sec: env::var("ENTROPY_VIOL_RESET").unwrap_or_else(|_| "3600".to_string()).parse().expect("Invalid Viol Reset TTL"),
            rate_limit_per_sec: env::var("ENTROPY_RATE_LIMIT").expect("ENTROPY_RATE_LIMIT missing").parse().expect("Invalid rate"),
            rate_limit_burst: env::var("ENTROPY_RATE_BURST").expect("ENTROPY_RATE_BURST missing").parse().expect("Invalid burst"),
            relay_window_sec: env::var("ENTROPY_RELAY_WINDOW").unwrap_or_else(|_| "60".to_string()).parse().expect("Invalid window"),
            keys_window_sec: env::var("ENTROPY_KEYS_WINDOW").unwrap_or_else(|_| "3600".to_string()).parse().expect("Invalid window"),
            pow_base_difficulty: env::var("ENTROPY_POW_BASE").expect("ENTROPY_POW_BASE missing").parse().expect("Invalid difficulty"),
            keys_upload_limit: env::var("ENTROPY_LIMIT_KEYS_UPLOAD").expect("ENTROPY_LIMIT_KEYS_UPLOAD missing").parse().expect("Invalid limit"),
            relay_limit: env::var("ENTROPY_LIMIT_RELAY").expect("ENTROPY_LIMIT_RELAY missing").parse().expect("Invalid limit"),
            nick_register_limit: env::var("ENTROPY_LIMIT_NICK_REGISTER").expect("ENTROPY_LIMIT_NICK_REGISTER missing").parse().expect("Invalid limit"),
            media_limit: env::var("ENTROPY_LIMIT_MEDIA").unwrap_or_else(|_| "10000".to_string()).parse().expect("Invalid limit"),
            lookup_limit: env::var("ENTROPY_LIMIT_LOOKUP").unwrap_or_else(|_| "3".to_string()).parse().expect("Invalid limit"),
            key_fetch_limit: env::var("ENTROPY_LIMIT_KEY_FETCH").unwrap_or_else(|_| "10".to_string()).parse().expect("Invalid limit"),
            admin_token: env::var("ENTROPY_ADMIN_TOKEN").expect("ENTROPY_ADMIN_TOKEN missing"),
            max_nickname_length: env::var("ENTROPY_MAX_NICK_LEN").expect("ENTROPY_MAX_NICK_LEN missing").parse().expect("Invalid length"),
            max_prekeys_per_upload: env::var("ENTROPY_MAX_PREKEYS").expect("ENTROPY_MAX_PREKEYS missing").parse().expect("Invalid count"),
            max_pow_difficulty: env::var("ENTROPY_POW_DIFF").expect("ENTROPY_POW_DIFF missing").parse().expect("Invalid diff"),
            max_json_depth: env::var("ENTROPY_MAX_JSON_DEPTH").expect("ENTROPY_MAX_JSON_DEPTH missing").parse().expect("Invalid depth"),
            max_offline_messages: env::var("ENTROPY_MAX_OFFLINE_MSGS").expect("ENTROPY_MAX_OFFLINE_MSGS missing").parse().expect("Invalid count"),
            max_offline_messages_per_sender: env::var("ENTROPY_MAX_OFFLINE_PER_SENDER").unwrap_or_else(|_| "5".to_string()).parse().expect("Invalid count"),
            pacing: PacingConfig {
                packet_size: env::var("ENTROPY_PACING_SIZE").expect("ENTROPY_PACING_SIZE missing").parse().expect("Invalid size"),
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
