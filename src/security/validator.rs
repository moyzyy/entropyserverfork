use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use sha2::{Sha256, Digest};
use libsignal_protocol::IdentityKey;

pub struct InputValidator;

impl InputValidator {
    pub fn sanitize_field(input: &str, max_len: usize) -> String {
        let mut result = String::with_capacity(input.len().min(max_len));
        for c in input.chars().take(max_len) {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == ' ' {
                result.push(c);
            }
        }
        result
    }

    pub fn normalize_nickname(input: &str) -> String {
        let trimmed = input.trim();
        let mut normalized = String::with_capacity(trimmed.len());
        let mut last_was_space = false;
        
        for c in trimmed.chars().take(32) { 
            if c.is_alphanumeric() || c == '_' || c == '-' {
                normalized.push(c);
                last_was_space = false;
            } else if c == ' ' && !last_was_space {
                normalized.push(' ');
                last_was_space = true;
            }
        }
        normalized
    }

    pub fn is_valid_hex(input: &str, expected_len: Option<usize>) -> bool {
        if input.is_empty() { return false; }
        if let Some(len) = expected_len {
            if input.len() != len { return false; }
        }
        input.chars().all(|c| c.is_ascii_hexdigit())
    }

    pub fn is_valid_hash(input: &str) -> bool {
        Self::is_valid_hex(input, Some(64))
    }

    pub fn verify_id_hash(id_hash: &str, pubkey_bytes: &[u8]) -> bool {
        if id_hash.len() != 64 { return false; }
        let mut hasher = Sha256::new();
        hasher.update(pubkey_bytes);
        let result = hex::encode(hasher.finalize());
        result == id_hash
    }

    pub fn verify_xeddsa(x25519_pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let mut key_32 = x25519_pubkey.to_vec();
        if key_32.len() == 33 && key_32[0] == 0x05 {
            key_32.remove(0);
        }
        
        if key_32.len() != 32 || signature.len() != 64 { return false; }
        
        // Use libsignal directly for XEdDSA verification parity
        let mut full_pk = key_32.clone();
        full_pk.insert(0, 0x05);

        let Ok(id_key) = IdentityKey::decode(&full_pk) else {
            return false;
        };

        if id_key.public_key().verify_signature(message, signature) {
            return true;
        }

        // Fallback to raw Ed25519 check just in case
        Self::verify_ed25519(&key_32, message, signature)
    }

    pub fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let mut key_32 = pubkey.to_vec();
        if key_32.len() == 33 && key_32[0] == 0x05 {
            key_32.remove(0);
        }
        if key_32.len() != 32 { return false; }
        let Ok(key) = VerifyingKey::from_bytes(key_32.as_slice().try_into().unwrap_or(&[0;32])) else { 
            return false; 
        };
        let sig = Signature::from_bytes(signature.try_into().unwrap_or(&[0;64]));
        key.verify(message, &sig).is_ok()
    }
    pub fn get_json_depth(v: &serde_json::Value) -> usize {
        match v {
            serde_json::Value::Object(map) => {
                let mut max = 0;
                for val in map.values() {
                    let d = Self::get_json_depth(val);
                    if d > max { max = d; }
                }
                max + 1
            }
            serde_json::Value::Array(arr) => {
                let mut max = 0;
                for val in arr {
                    let d = Self::get_json_depth(val);
                    if d > max { max = d; }
                }
                max + 1
            }
            _ => 1,
        }
    }

    /// Counts raw bracket depth before parsing to avoid Stack Overflow/Nesting Bombs.
    pub fn pre_scan_depth(input: &str, max_depth: usize) -> bool {
        let mut depth = 0;
        let mut max_observed = 0;
        for c in input.chars() {
            match c {
                '{' | '[' => {
                    depth += 1;
                    if depth > max_observed { max_observed = depth; }
                    if depth > max_depth { return false; }
                }
                '}' | ']' => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nickname_normalization() {
        assert_eq!(InputValidator::normalize_nickname("  Hello_World  "), "Hello_World");
        assert_eq!(InputValidator::normalize_nickname("Multiple   Spaces"), "Multiple Spaces");
        assert_eq!(InputValidator::normalize_nickname("Special!@#Characters"), "SpecialCharacters");
        assert_eq!(InputValidator::normalize_nickname("VeryLongNicknameThatIsOverThirtyTwoCharacters"), "VeryLongNicknameThatIsOverThirty");
    }

    #[test]
    fn test_hex_validation() {
        assert!(InputValidator::is_valid_hex("abc123DEF", None));
        assert!(InputValidator::is_valid_hex("abc123DEF", Some(9)));
        assert!(!InputValidator::is_valid_hex("abc123DEG", None)); // G is not hex
        assert!(!InputValidator::is_valid_hex("abc", Some(4))); // Wrong length
    }

    #[test]
    fn test_pre_scan_depth() {
        assert!(InputValidator::pre_scan_depth("{}", 5));
        assert!(InputValidator::pre_scan_depth("[[[[]]]]", 5));
        assert!(!InputValidator::pre_scan_depth("[[[[]]]]", 3)); // Depth is 4
        assert!(InputValidator::pre_scan_depth("no brackets", 0));
    }

    #[test]
    fn test_sanitize_field() {
        assert_eq!(InputValidator::sanitize_field("drop table users;", 10), "drop table");
        assert_eq!(InputValidator::sanitize_field("valid-name_123", 20), "valid-name_123");
    }
}
