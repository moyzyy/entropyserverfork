use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use base64::Engine;

pub struct InputValidator;

impl InputValidator {
    pub fn sanitize_field(input: &str, max_len: usize) -> String {
        let mut result = String::with_capacity(input.len().min(max_len));
        for c in input.chars().take(max_len) {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == ' ' {
                result.push(c);
            } else {
                result.push(' ');
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
        Self::is_valid_hex(input, Some(64)) || Self::is_valid_hex(input, Some(66))
    }

    pub fn verify_xeddsa(x25519_pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if x25519_pubkey.len() != 32 || signature.len() != 64 { return false; }
        
        let mont_point = MontgomeryPoint(x25519_pubkey.try_into().unwrap());
        // Collect all variations to try
        let mut variations: Vec<Vec<u8>> = vec![message.to_vec()];

        if let Ok(msg_str) = String::from_utf8(message.to_vec()) {
            if msg_str.starts_with("BURN_ACCOUNT:") {
                let hash_part = &msg_str[13..];
                
                // 1. Try uppercase/lowercase hex
                variations.push(format!("BURN_ACCOUNT:{}", hash_part.to_uppercase()).into_bytes());
                variations.push(format!("BURN_ACCOUNT:{}", hash_part.to_lowercase()).into_bytes());
                
                // 2. Try hex of the public key (sometimes used as id)
                variations.push(format!("BURN_ACCOUNT:{}", hex::encode(x25519_pubkey)).into_bytes());
                variations.push(format!("BURN_ACCOUNT:05{}", hex::encode(x25519_pubkey)).into_bytes());
                
                // 3. Try Base64 encoded hash (some Signal clients use this)
                let hash_bytes = if hash_part.len() == 64 { hex::decode(hash_part).unwrap_or_default() } else { Vec::new() };
                if !hash_bytes.is_empty() {
                    let h_b64 = base64::engine::general_purpose::STANDARD.encode(&hash_bytes);
                    variations.push(format!("BURN_ACCOUNT:{}", h_b64).into_bytes());
                    
                    // 4. Try raw bytes of the hash
                    let mut raw_v = b"BURN_ACCOUNT:".to_vec();
                    raw_v.extend_from_slice(&hash_bytes);
                    variations.push(raw_v);
                }
            }
        }

        // Try direct Ed25519 first (if the key is already Edwards)
        for var in &variations {
            if Self::verify_ed25519(x25519_pubkey, var, signature) {
                return true;
            }
        }

        // Try XEdDSA (Montgomery -> Edwards conversion)
        for sign in 0..=1 {
            if let Some(ed_point) = mont_point.to_edwards(sign) {
                let ed_bytes = ed_point.compress().to_bytes();
                for var in &variations {
                    if Self::verify_ed25519(&ed_bytes, var, signature) {
                        tracing::debug!("XEdDSA verified successfully (sign={}, var_len={})", sign, var.len());
                        return true;
                    }
                }
            }
        }
        
        false
    }

    pub fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(pubkey.try_into().unwrap_or(&[0;32])) else { return false; };
        let sig = Signature::from_bytes(signature.try_into().unwrap_or(&[0;64]));
        key.verify(message, &sig).is_ok()
    }
}
