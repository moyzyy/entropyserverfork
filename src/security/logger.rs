use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sha2::{Sha256, Digest};
use rand::{thread_rng, RngCore};
use once_cell::sync::Lazy;
use chrono::Utc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

pub struct SecurityLogger;

struct LoggerState {
    min_level: LogLevel,
    log_salt: String,
    last_rotation: Instant,
}

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

impl SecurityLogger {
    pub fn log(level: LogLevel, event: EventType, remote_addr: &str, message: &str) {
        let mut state = STATE.lock().unwrap();
        
        if level < state.min_level {
            return;
        }

        let now = Instant::now();
        if now.duration_since(state.last_rotation) >= Duration::from_secs(24 * 3600) {
            let mut salt_bytes = [0u8; 32];
            thread_rng().fill_bytes(&mut salt_bytes);
            state.log_salt = hex::encode(salt_bytes);
            state.last_rotation = now;
            
            // Log rotation info
            if LogLevel::INFO >= state.min_level {
                println!("[{} UTC] [INFO] [SECURITY] msg=\"IP blinding salt rotated for log forward secrecy (daily update)\"", Utc::now().format("%Y-%m-%d %H:%M:%S"));
            }
        }

        let mut hidden_ip = remote_addr.to_string();
        if remote_addr != "unknown" && remote_addr != "internal" && remote_addr != "SYSTEM" {
            let mut hasher = Sha256::new();
            hasher.update(remote_addr.as_bytes());
            hasher.update(state.log_salt.as_bytes());
            let hash = hasher.finalize();
            hidden_ip = format!("anon_{}", hex::encode(&hash[0..6]));
        }

        let level_str = match level {
            LogLevel::INFO => "INFO",
            LogLevel::WARNING => "WARN",
            LogLevel::ERROR => "ERROR",
            LogLevel::CRITICAL => "CRIT",
        };

        let event_str = match event {
            EventType::AuthSuccess => "AUTH_SUCCESS",
            EventType::AuthFailure => "AuthFailure",
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
        let log_line = format!("[{} UTC] [{}] [{}] ip={} msg=\"{}\"", 
            Utc::now().format("%Y-%m-%d %H:%M:%S"),
            level_str,
            event_str,
            hidden_ip,
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
