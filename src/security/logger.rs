use std::sync::{Arc, Mutex};
use std::time::Instant;
use rand::{thread_rng, RngCore};
use once_cell::sync::Lazy;
use chrono::Utc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum LogLevel {
    INFO,
    WARNING,
    ERROR,
    CRITICAL,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum EventType {
    AuthSuccess,
    AuthFailure,
    RateLimitHit,
    InvalidInput,
    PowFailure,
    ReplayAttempt,
    SuspiciousActivity,
    ConnectionRejected,
    ConnectionAbandoned,
    ProtocolViolation,
}

#[allow(dead_code)]
pub struct SecurityLogger;

#[allow(dead_code)]
struct LoggerState {
    min_level: LogLevel,
    log_salt: String,
    last_rotation: Instant,
}

#[allow(dead_code)]
static STATE: Lazy<Arc<Mutex<LoggerState>>> = Lazy::new(|| {
    let min_level = match std::env::var("ENTROPY_LOG_LEVEL").unwrap_or_default().as_str() {
        "CRITICAL" => LogLevel::CRITICAL,
        "ERROR" => LogLevel::ERROR,
        "WARNING" => LogLevel::WARNING,
        _ => LogLevel::INFO,
    };
    
    let mut salt_bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut salt_bytes);
    let log_salt = hex::encode(salt_bytes);

    Arc::new(Mutex::new(LoggerState {
        min_level,
        log_salt,
        last_rotation: Instant::now(),
    }))
});

#[allow(dead_code)]
impl SecurityLogger {
    pub fn log(level: LogLevel, event: EventType, id_hash: &str, message: &str) {
        let state = STATE.lock().unwrap();
        
        if level < state.min_level {
            return;
        }

        let mut display_id = id_hash.to_string();
        if id_hash != "unknown" && id_hash != "internal" && id_hash != "SYSTEM" {
            // Truncate the 64-char hash for cleaner logging while preserving identity
            let len = id_hash.len().min(8);
            display_id = format!("id_{}", &id_hash[0..len]);
        }

        let level_str = match level {
            LogLevel::INFO => "INFO",
            LogLevel::WARNING => "WARN",
            LogLevel::ERROR => "ERROR",
            LogLevel::CRITICAL => "CRIT",
        };

        let event_str = match event {
            EventType::AuthSuccess => "AUTH_SUCCESS",
            EventType::AuthFailure => "Auth_Failure",
            EventType::RateLimitHit => "RATE_LIMIT",
            EventType::InvalidInput => "InvalidInput",
            EventType::PowFailure => "PowFailure",
            EventType::ReplayAttempt => "ReplayAttempt",
            EventType::SuspiciousActivity => "SUSPICIOUS",
            EventType::ConnectionRejected => "CONN_REJECTED",
            EventType::ConnectionAbandoned => "CONN_ABANDONED",
            EventType::ProtocolViolation => "PROTO_VIOLATION",
        };

        let sanitized_msg = Self::sanitize_log_message(message);
        let log_line = format!("[{} UTC] [{}] [{}] {} msg=\"{}\"", 
            Utc::now().format("%Y-%m-%d %H:%M:%S"),
            level_str,
            event_str,
            display_id,
            sanitized_msg
        );

        if level >= LogLevel::ERROR {
            eprintln!("{}", log_line);
        } else {
            println!("{}", log_line);
        }
    }

    fn sanitize_log_message(msg: &str) -> String {
        msg.chars().map(|c| {
            if c == '"' || c == '\\' || c == '\n' || c == '\r' {
                ' '
            } else if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                ' '
            }
        }).collect()
    }
}
