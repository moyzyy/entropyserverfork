use dashmap::DashMap;
use tokio::sync::mpsc;
use crate::relay::QueuedMessage;

pub type MessageSender = mpsc::UnboundedSender<QueuedMessage>;

pub struct Registry {
    connections: DashMap<String, MessageSender>,
    total_connections: std::sync::atomic::AtomicUsize,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            total_connections: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn add_connection(&self, identity_hash: String, sender: MessageSender) -> Option<MessageSender> {
        self.connections.insert(identity_hash, sender)
    }

    pub fn remove_connection(&self, identity_hash: &str) {
        self.connections.remove(identity_hash);
    }

    pub fn get_connection(&self, identity_hash: &str) -> Option<MessageSender> {
        self.connections.get(identity_hash).map(|s| s.clone())
    }

    pub fn connection_count(&self) -> usize {
        self.total_connections.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn inc_total(&self) {
        self.total_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn dec_total(&self) {
        self.total_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn close_all(&self) {
        self.connections.clear();
    }
}
