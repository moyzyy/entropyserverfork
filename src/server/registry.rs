use dashmap::DashMap;
use tokio::sync::mpsc;
use crate::relay::QueuedMessage;

pub type MessageSender = mpsc::UnboundedSender<QueuedMessage>;

#[derive(Default)]
pub struct Registry {
    connections: DashMap<String, MessageSender>,
    total_connections: std::sync::atomic::AtomicUsize,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_lifecycle() {
        let registry = Registry::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        
        // Initial state
        assert_eq!(registry.connection_count(), 0);
        
        // Add connection
        registry.add_connection("user1".to_string(), tx);
        assert!(registry.get_connection("user1").is_some());
        
        // Displacement
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let old = registry.add_connection("user1".to_string(), tx2);
        assert!(old.is_some(), "Should return the old sender");
        
        // Atomic counts
        registry.inc_total();
        registry.inc_total();
        assert_eq!(registry.connection_count(), 2);
        registry.dec_total();
        assert_eq!(registry.connection_count(), 1);
        
        // Removal
        registry.remove_connection("user1");
        assert!(registry.get_connection("user1").is_none());
    }
}
