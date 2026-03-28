use dashmap::DashMap;
use tokio::sync::mpsc;
use sha2::{Sha256, Digest};
use crate::relay::QueuedMessage;

pub type MessageSender = mpsc::UnboundedSender<QueuedMessage>;

pub struct Registry {
    connections: DashMap<String, MessageSender>,
    ip_counts: DashMap<String, usize>,
    salt: String,
}

impl Registry {
    pub fn new(salt: String) -> Self {
        Self {
            connections: DashMap::new(),
            ip_counts: DashMap::new(),
            salt,
        }
    }

    pub fn blind_id(&self, id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        hasher.update(self.salt.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn add_connection(&self, blinded_id: String, sender: MessageSender) {
        self.connections.insert(blinded_id, sender);
    }

    pub fn remove_connection(&self, blinded_id: &str) {
        self.connections.remove(blinded_id);
    }

    pub fn get_connection(&self, blinded_id: &str) -> Option<MessageSender> {
        self.connections.get(blinded_id).map(|s| s.clone())
    }

    pub fn increment_ip_count(&self, blinded_ip: &str, limit: usize) -> bool {
        let mut entry = self.ip_counts.entry(blinded_ip.to_string()).or_insert(0);
        if *entry >= limit {
            return false;
        }
        *entry += 1;
        true
    }

    pub fn decrement_ip_count(&self, blinded_ip: &str) {
        if let Some(mut entry) = self.ip_counts.get_mut(blinded_ip) {
            if *entry > 0 {
                *entry -= 1;
            }
            if *entry == 0 {
                drop(entry);
                self.ip_counts.remove(blinded_ip);
            }
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn close_all(&self) {
        self.connections.clear();
    }
}
