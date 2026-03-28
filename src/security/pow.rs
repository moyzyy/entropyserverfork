use sha2::{Sha256, Digest};
use std::cmp::max;

pub struct PoWVerifier;

impl PoWVerifier {
    pub const BASE_DIFFICULTY: i32 = 8;

    pub fn get_required_difficulty(active_connections: usize, intensity_penalty: i32) -> i32 {
        let mut base = Self::BASE_DIFFICULTY + intensity_penalty;

        // Ensure difficulty never drops below a safe minimum
        base = max(Self::BASE_DIFFICULTY - 2, base);

        // Scale difficulty based on active connection count
        if active_connections > 5000 {
            return base + 3;
        }
        if active_connections > 1000 {
            return base + 2;
        }

        base
    }

    pub fn get_difficulty_for_nickname(nickname: &str, active_connections: usize, intensity_penalty: i32) -> i32 {
        let base = Self::get_required_difficulty(active_connections, intensity_penalty);
        if nickname.len() <= 5 {
            return base + 3;
        }
        if nickname.len() <= 7 {
            return base + 2;
        }
        if nickname.len() <= 9 {
            return base + 1;
        }
        base
    }

    pub fn verify(seed: &str, nonce: &str, context: &str, mut target_difficulty: i32) -> bool {
        if seed.is_empty() || nonce.is_empty() {
            return false;
        }

        if target_difficulty == -1 {
            target_difficulty = Self::get_required_difficulty(0, 0); // Match C++ default
        }

        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(context.as_bytes());
        hasher.update(nonce.as_bytes());
        let hash = hasher.finalize();

        let mut zeros = 0;
        for &byte in hash.iter() {
            if byte == 0 {
                zeros += 2;
            } else {
                if (byte & 0xF0) == 0 {
                    zeros += 1;
                }
                break;
            }
        }

        zeros >= target_difficulty
    }
}
