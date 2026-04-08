use tracing::{info, warn, error};

#[allow(non_camel_case_types)]
pub enum LogLevel {
    INFO,
    WARNING,
    ERROR,
    CRITICAL,
}

#[allow(non_camel_case_types)]
pub enum EventType {
    AUTH_SUCCESS,
    CONNECTION_REJECTED,
    RATE_LIMIT_HIT,
    SUSPICIOUS_ACTIVITY,
    INVALID_INPUT,
}

pub struct SecurityLogger;

impl SecurityLogger {
    pub fn log(level: LogLevel, event: EventType, remote_addr: &str, message: &str) {
        let level_str = match level {
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARNING",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRITICAL",
        };

        let event_str = match event {
            EventType::AUTH_SUCCESS => "AUTH_SUCCESS",
            EventType::CONNECTION_REJECTED => "CONNECTION_REJECTED",
            EventType::RATE_LIMIT_HIT => "RATE_LIMIT_HIT",
            EventType::SUSPICIOUS_ACTIVITY => "SUSPICIOUS_ACTIVITY",
            EventType::INVALID_INPUT => "INVALID_INPUT",
        };

        match level {
            LogLevel::Info => info!("[{}] [{}] {} - {}", level_str, event_str, remote_addr, message),
            LogLevel::Warning => warn!("[{}] [{}] {} - {}", level_str, event_str, remote_addr, message),
            LogLevel::Error | LogLevel::Critical => error!("[{}] [{}] {} - {}", level_str, event_str, remote_addr, message),
        }
    }
}
