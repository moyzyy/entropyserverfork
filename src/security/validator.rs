use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use sha2::{Sha256, Digest};
use libsignal_protocol::IdentityKey;

pub struct InputValidator;

impl InputValidator {
    pub fn sanitize_field(input: &str, max_len: usize) -> String {
        let mut result = String::with_capacity(input.len().min(max_len));
        for c in input.chars().take(max_len) {
            if c.is_alphanumeric() || c == '_' || c == '-' {
                result.push(c);
            }
        }
        result
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
        if x25519_pubkey.len() != 32 || signature.len() != 64 { return false; }
        
        // Use libsignal directly for XEdDSA verification parity
        let mut full_pk = x25519_pubkey.to_vec();
        if full_pk.len() == 32 {
            full_pk.insert(0, 0x05);
        }

        let Ok(id_key) = IdentityKey::decode(&full_pk) else {
            tracing::info!("verify_xeddsa: failed to decode IdentityKey (len={})", full_pk.len());
            return false;
        };

        if id_key.public_key().verify_signature(message, signature) {
            tracing::info!("XEdDSA verified successfully using libsignal");
            return true;
        }

        // Fallback to raw Ed25519 check for non-signal keys
        Self::verify_ed25519(x25519_pubkey, message, signature)
    }

    pub fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if pubkey.len() != 32 { return false; }
        let Ok(key) = VerifyingKey::from_bytes(pubkey.try_into().unwrap_or(&[0;32])) else { 
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
}
