use serde_json::Value;

pub struct TrafficNormalizer;

impl TrafficNormalizer {
    pub const REQUIRED_PACKET_SIZE: usize = 1400;

    pub const FIXED_FRAME_SIZE: usize = 1400;

    pub fn pad_json(val: &mut Value) {
        let current_str = serde_json::to_string(val).unwrap();
        let current_len = current_str.len();
        
        // Ensure we don't exceed the fixed size (leave room for padding key)
        if current_len + 15 > Self::FIXED_FRAME_SIZE {
            // Already large, just let it be (safety cap)
            return;
        }

        let padding_size = Self::FIXED_FRAME_SIZE - current_len - 15;
        let padding = " ".repeat(padding_size);
        
        if let Some(obj) = val.as_object_mut() {
            obj.insert("padding".to_string(), Value::String(padding));
        }
    }

    pub fn pad_binary(data: &mut Vec<u8>) {
        if data.len() < Self::FIXED_FRAME_SIZE {
            data.resize(Self::FIXED_FRAME_SIZE, 0);
        }
    }
}
