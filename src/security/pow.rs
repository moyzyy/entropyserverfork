use num_bigint::BigUint;
use num_traits::Num;

pub struct PoWVerifier;

impl PoWVerifier {
    pub fn get_required_difficulty(base: i32, active_connections: usize, penalty_multiplier: u32, max_diff: u32) -> u32 {
        let mut diff_base = base as usize;
        if active_connections > 500 { diff_base *= 2; }
        if active_connections > 1000 { diff_base *= 4; }
        if active_connections > 5000 { diff_base *= 10; }
        if active_connections > 10000 { diff_base *= 20; }
        
        let mut diff = diff_base;
        if penalty_multiplier > 0 {
            diff *= penalty_multiplier as usize;
        }
        
        std::cmp::min(diff as u32, max_diff)
    }

    pub fn get_difficulty_for_nickname(len: usize) -> u32 {
        if len <= 3 { return 500000; }
        if len <= 5 { return 100000; }
        10000
    }

    pub fn validate_vdf(seed_hex: &str, result_hex: &str, difficulty: u32, modulus_hex: &str, phi_hex: &str) -> bool {
        let Ok(n) = BigUint::from_str_radix(modulus_hex, 10) else { return false; };
        let Ok(phi) = BigUint::from_str_radix(phi_hex, 10) else { return false; };
        let Ok(x_bytes) = hex::decode(seed_hex) else { return false; };
        let Ok(y_bytes) = hex::decode(result_hex) else { return false; };
        let y_claimed = BigUint::from_bytes_be(&y_bytes);

        // 🛡️ THE MAGIC: Verification in O(log T) using Phi
        // We need to check if y = x^(2^t) mod n
        // Instead of doing t squarings, we compute e = 2^t mod phi
        let t_big = BigUint::from(difficulty);
        let two = BigUint::from(2u32);
        let e = two.modpow(&t_big, &phi);

        // Then check if y == x^e mod n
        let x: BigUint = BigUint::from_bytes_be(&x_bytes) % &n;
        let expected_y = x.modpow(&e, &n);
        y_claimed == expected_y
    }
}
