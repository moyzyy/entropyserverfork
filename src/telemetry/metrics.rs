use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::fmt::Write;

/// Multi-Dimensional Production Metrics for Entropy.
/// Designed for high-fidelity monitoring with zero process-level logging.
pub struct Metrics {
    // --- Traffic & Relay ---
    relay_messages_total: AtomicU64,
    relay_bytes_total: AtomicU64,
    relay_offline_stored_total: AtomicU64,
    
    // --- Connections & Life Cycle ---
    active_connections: AtomicU64,
    connections_total: AtomicU64,
    handshake_timeouts_total: AtomicU64,
    
    // --- Security & Enforcement ---
    auth_failures_total: AtomicU64,
    global_limit_rejected: AtomicU64,
    jail_events_total: AtomicU64,
    
    // --- Infrastructure Health ---
    redis_errors_total: AtomicU64,
    start_time: std::time::Instant,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            relay_messages_total: AtomicU64::new(0),
            relay_bytes_total: AtomicU64::new(0),
            relay_offline_stored_total: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            connections_total: AtomicU64::new(0),
            handshake_timeouts_total: AtomicU64::new(0),
            auth_failures_total: AtomicU64::new(0),
            global_limit_rejected: AtomicU64::new(0),
            jail_events_total: AtomicU64::new(0),
            redis_errors_total: AtomicU64::new(0),
            start_time: std::time::Instant::now(),
        })
    }

    pub fn uptime_sec(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn increment_counter(&self, name: &str, value: f64) {
        let val = value as u64;
        match name {
            "relay_messages_total" => { self.relay_messages_total.fetch_add(val, Ordering::Relaxed); }
            "relay_bytes_total" => { self.relay_bytes_total.fetch_add(val, Ordering::Relaxed); }
            "relay_offline_stored_total" => { self.relay_offline_stored_total.fetch_add(val, Ordering::Relaxed); }
            "connections_total" => { self.connections_total.fetch_add(val, Ordering::Relaxed); }
            "handshake_timeouts_total" => { self.handshake_timeouts_total.fetch_add(val, Ordering::Relaxed); }
            "auth_failures_total" => { self.auth_failures_total.fetch_add(val, Ordering::Relaxed); }
            "global_limit_rejected" => { self.global_limit_rejected.fetch_add(val, Ordering::Relaxed); }
            "jail_events_total" => { self.jail_events_total.fetch_add(val, Ordering::Relaxed); }
            "redis_errors_total" => { self.redis_errors_total.fetch_add(val, Ordering::Relaxed); }
            _ => {}
        }
    }

    pub fn set_gauge(&self, name: &str, value: f64) {
        let val = value as u64;
        if name == "active_connections" {
            self.active_connections.store(val, Ordering::Relaxed);
        }
    }

    pub fn increment_gauge(&self, name: &str, value: f64) {
        let val = value as u64;
        if name == "active_connections" {
            self.active_connections.fetch_add(val, Ordering::Relaxed);
        }
    }

    pub fn decrement_gauge(&self, name: &str, value: f64) {
        let val = value as u64;
        if name == "active_connections" {
            self.active_connections.fetch_sub(val, Ordering::Relaxed);
        }
    }

    pub fn get_counter(&self, name: &str) -> f64 {
        match name {
            "relay_messages_total" => self.relay_messages_total.load(Ordering::Relaxed) as f64,
            "relay_bytes_total" => self.relay_bytes_total.load(Ordering::Relaxed) as f64,
            "relay_offline_stored_total" => self.relay_offline_stored_total.load(Ordering::Relaxed) as f64,
            "connections_total" => self.connections_total.load(Ordering::Relaxed) as f64,
            "handshake_timeouts_total" => self.handshake_timeouts_total.load(Ordering::Relaxed) as f64,
            "auth_failures_total" => self.auth_failures_total.load(Ordering::Relaxed) as f64,
            "global_limit_rejected" => self.global_limit_rejected.load(Ordering::Relaxed) as f64,
            "jail_events_total" => self.jail_events_total.load(Ordering::Relaxed) as f64,
            "redis_errors_total" => self.redis_errors_total.load(Ordering::Relaxed) as f64,
            _ => 0.0,
        }
    }

    pub fn get_gauge(&self, name: &str) -> f64 {
        match name {
            "active_connections" => self.active_connections.load(Ordering::Relaxed) as f64,
            _ => 0.0,
        }
    }

    pub fn collect_prometheus(&self) -> String {
        let mut ss = String::with_capacity(2048);
        
        let mut write_metric = |name: &str, mtype: &str, help: &str, val: u64| {
            let _ = writeln!(ss, "# HELP entropy_{} {}", name, help);
            let _ = writeln!(ss, "# TYPE entropy_{} {}", name, mtype);
            let _ = writeln!(ss, "entropy_{} {}", name, val);
        };

        write_metric("uptime_seconds", "counter", "Server uptime in seconds", self.uptime_sec());
        write_metric("relay_messages_total", "counter", "Total messages relayed", self.relay_messages_total.load(Ordering::Relaxed));
        write_metric("relay_bytes_total", "counter", "Total bytes relayed", self.relay_bytes_total.load(Ordering::Relaxed));
        write_metric("relay_offline_stored_total", "counter", "Messages moved to offline storage", self.relay_offline_stored_total.load(Ordering::Relaxed));
        write_metric("active_connections", "gauge", "Current active WebSocket connections", self.active_connections.load(Ordering::Relaxed));
        write_metric("connections_total", "counter", "Total cumulative connections", self.connections_total.load(Ordering::Relaxed));
        write_metric("handshake_timeouts_total", "counter", "Handshakes that timed out before auth", self.handshake_timeouts_total.load(Ordering::Relaxed));
        write_metric("auth_failures_total", "counter", "Total failed authentication attempts", self.auth_failures_total.load(Ordering::Relaxed));
        write_metric("global_limit_rejected", "counter", "Total connections rejected by global rate limiting", self.global_limit_rejected.load(Ordering::Relaxed));
        write_metric("jail_events_total", "counter", "Total number of identity ban events triggered", self.jail_events_total.load(Ordering::Relaxed));
        write_metric("redis_errors_total", "counter", "Total Redis cluster connection or command errors", self.redis_errors_total.load(Ordering::Relaxed));
        
        ss
    }
}
