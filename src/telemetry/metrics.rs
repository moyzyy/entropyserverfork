use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::fmt::Write;

pub struct Metrics {
    counters: DashMap<String, AtomicU64>,
    gauges: DashMap<String, AtomicU64>,
    start_time: std::time::Instant,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            counters: DashMap::new(),
            gauges: DashMap::new(),
            start_time: std::time::Instant::now(),
        })
    }

    pub fn uptime_sec(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    pub fn increment_counter(&self, name: &str, value: f64) {
        let entry = self.counters.entry(name.to_string()).or_insert(AtomicU64::new(0));
        entry.fetch_add(value as u64, Ordering::Relaxed);
    }

    pub fn set_gauge(&self, name: &str, value: f64) {
        let entry = self.gauges.entry(name.to_string()).or_insert(AtomicU64::new(0));
        entry.store(value as u64, Ordering::Relaxed);
    }

    pub fn increment_gauge(&self, name: &str, value: f64) {
        let entry = self.gauges.entry(name.to_string()).or_insert(AtomicU64::new(0));
        entry.fetch_add(value as u64, Ordering::Relaxed);
    }

    pub fn decrement_gauge(&self, name: &str, value: f64) {
        if let Some(entry) = self.gauges.get(name) {
            entry.fetch_sub(value as u64, Ordering::Relaxed);
        }
    }

    pub fn get_gauge(&self, name: &str) -> f64 {
        self.gauges.get(name).map(|v| v.load(Ordering::Relaxed) as f64).unwrap_or(0.0)
    }

    pub fn get_counter(&self, name: &str) -> f64 {
        self.counters.get(name).map(|v| v.load(Ordering::Relaxed) as f64).unwrap_or(0.0)
    }

    pub fn collect_prometheus(&self) -> String {
        let mut ss = String::new();
        
        for entry in self.counters.iter() {
            let name = entry.key();
            let val = entry.value().load(Ordering::Relaxed);
            let _ = writeln!(ss, "# TYPE {} counter", name);
            let _ = writeln!(ss, "{} {}", name, val);
        }
        
        for entry in self.gauges.iter() {
            let name = entry.key();
            let val = entry.value().load(Ordering::Relaxed);
            let _ = writeln!(ss, "# TYPE {} gauge", name);
            let _ = writeln!(ss, "{} {}", name, val);
        }
        
        ss
    }
}
