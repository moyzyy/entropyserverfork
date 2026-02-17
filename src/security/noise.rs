use serde_json::Value;

pub struct TrafficNormalizer;

impl TrafficNormalizer {
    pub const REQUIRED_PACKET_SIZE: usize = 1536;

    pub fn pad_json(val: &mut Value) {
        let current_str = serde_json::to_string(val).unwrap();
        let current_len = current_str.len();
        
        if current_len >= Self::REQUIRED_PACKET_SIZE {
            return;
        }

        let needed = Self::REQUIRED_PACKET_SIZE - current_len;
        
        // C++: if (needed < 15) return;
        if needed < 15 {
            return;
        }

        // C++: std::string pad_str(needed - 13, ' ');
        // obj["padding"] = pad_str;
        // Calculation: ,"padding":" (12) + pad + " (1) = 13 + pad_len
        let padding_size = needed - 13;
        let padding = " ".repeat(padding_size);
        
        if let Some(obj) = val.as_object_mut() {
            obj.insert("padding".to_string(), Value::String(padding));
        }
    }
}
