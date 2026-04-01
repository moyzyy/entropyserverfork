

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
