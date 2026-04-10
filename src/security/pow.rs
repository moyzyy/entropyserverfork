use num_bigint::BigUint;
use num_traits::Num;

pub struct PoWVerifier;

impl PoWVerifier {
    pub fn get_required_difficulty(base: i32, active_connections: usize, penalty_multiplier: u32, max_diff: u32) -> u32 {
        let mut diff_base = base as usize;
        if active_connections > 10000 { diff_base *= 10; }
        else if active_connections > 5000 { diff_base *= 6; }
        else if active_connections > 1000 { diff_base *= 4; }
        else if active_connections > 500 { diff_base *= 2; }
        
        let mut diff = diff_base;
        if penalty_multiplier > 0 {
            diff *= penalty_multiplier as usize;
        }
        
        std::cmp::min(diff as u32, max_diff)
    }



    pub fn validate_vdf(seed_hex: &str, result_hex: &str, difficulty: u32, modulus_hex: &str, phi_hex: &str) -> bool {
        let Ok(n) = BigUint::from_str_radix(modulus_hex, 10) else { return false; };
        let Ok(phi) = BigUint::from_str_radix(phi_hex, 10) else { return false; };
        let Ok(x_bytes) = hex::decode(seed_hex) else { return false; };
        let Ok(y_bytes) = hex::decode(result_hex) else { return false; };
        let y_claimed = BigUint::from_bytes_be(&y_bytes);

        // Verification in O(log T) using Phi
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_scaling() {
        // Base case
        assert_eq!(PoWVerifier::get_required_difficulty(10, 100, 0, 100), 10);
        // Connection load scaling
        assert_eq!(PoWVerifier::get_required_difficulty(10, 600, 0, 100), 20);
        assert_eq!(PoWVerifier::get_required_difficulty(10, 10001, 0, 1000), 100);
        // Penalty scaling
        assert_eq!(PoWVerifier::get_required_difficulty(10, 100, 2, 100), 20);
        // Max diff cap
        assert_eq!(PoWVerifier::get_required_difficulty(10, 100, 100, 50), 50);
    }

    #[test]
    fn test_vdf_logic() {
        // Small numbers for testability
        // n = 77 (7*11), phi = 60 (6*10)
        // x = 3
        // diff = 2 (t=2)
        // e = 2^2 mod 60 = 4
        // y = 3^4 mod 77 = 81 mod 77 = 4
        let modulus = "77";
        let phi = "60";
        let seed = "03"; // 3 in hex
        let result = "04"; // 4 in hex
        assert!(PoWVerifier::validate_vdf(seed, result, 2, modulus, phi));
        
        // Invalid result
        assert!(!PoWVerifier::validate_vdf(seed, "05", 2, modulus, phi));
    }
}
