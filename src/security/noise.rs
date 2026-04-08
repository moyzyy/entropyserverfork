

pub struct TrafficNormalizer;

impl TrafficNormalizer {

    pub fn pad_json_str(json_str: &mut String, target_size: usize) {
        let current_len = json_str.len();
        if current_len >= target_size {
            return;
        }

        let padding_needed = target_size - current_len;
        json_str.push_str(&" ".repeat(padding_needed));
    }

    pub fn pad_binary(data: &mut Vec<u8>, target_size: usize) {
        if data.len() < target_size {
            data.resize(target_size, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_padding() {
        let mut s = "{\"a\":1}".to_string(); // len 7
        TrafficNormalizer::pad_json_str(&mut s, 10);
        assert_eq!(s.len(), 10);
        assert_eq!(s, "{\"a\":1}   ");
        
        // No truncation
        TrafficNormalizer::pad_json_str(&mut s, 5);
        assert_eq!(s.len(), 10);
    }

    #[test]
    fn test_binary_padding() {
        let mut b = vec![1, 2, 3];
        TrafficNormalizer::pad_binary(&mut b, 5);
        assert_eq!(b.len(), 5);
        assert_eq!(b[3], 0);
        assert_eq!(b[4], 0);
    }
}
