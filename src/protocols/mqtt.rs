use super::{ProtocolFuzzer, common};
use anyhow::Result;
use arbitrary::{Arbitrary, Unstructured};
use bytes::{BufMut, BytesMut};
use mqttrs::{Packet, Connect, Publish, Subscribe, Unsubscribe, QoS, Pid};
use rand::{thread_rng, Rng};
use std::collections::HashMap;

pub struct MQTTFuzzer {
    /// Common topic patterns for realistic fuzzing
    topic_corpus: Vec<String>,
    /// Client ID patterns
    client_id_corpus: Vec<String>,
    /// Payload patterns
    payload_corpus: Vec<Vec<u8>>,
    /// Malformed patterns specific to MQTT
    malformed_patterns: Vec<MalformedMQTTPattern>,
}

#[derive(Clone)]
enum MalformedMQTTPattern {
    InvalidFixedHeader,
    OversizedRemainingLength,
    InvalidPacketType,
    TruncatedPayload,
    OversizedPayload,
    InvalidQoS,
    MalformedUtf8,
    InvalidTopicFilter,
    ExcessiveSubscriptions,
    ProtocolViolation,
}

impl MQTTFuzzer {
    pub fn new() -> Self {
        Self {
            topic_corpus: vec![
                "sensor/temperature".to_string(),
                "device/status".to_string(),
                "home/living-room/light".to_string(),
                "factory/machine1/alerts".to_string(),
                "$SYS/broker/load/messages/received".to_string(),
                "iot/+/telemetry".to_string(),
                "building/floor/+/room/+/sensor/+".to_string(),
                "/".to_string(),
                "".to_string(), // Empty topic for edge case testing
            ],
            client_id_corpus: vec![
                "sensor001".to_string(),
                "gateway-12345".to_string(),
                "mobile-app-user123".to_string(),
                "".to_string(), // Empty client ID
                "very-long-client-id-that-exceeds-normal-limits-and-might-cause-buffer-overflows-in-poorly-implemented-brokers".to_string(),
            ],
            payload_corpus: vec![
                b"Hello, MQTT!".to_vec(),
                b"{\"temperature\": 23.5, \"humidity\": 60.2}".to_vec(),
                b"ON".to_vec(),
                b"OFF".to_vec(),
                vec![0; 1000], // Large payload
                vec![0xFF; 100], // Binary payload
                Vec::new(), // Empty payload
            ],
            malformed_patterns: vec![
                MalformedMQTTPattern::InvalidFixedHeader,
                MalformedMQTTPattern::OversizedRemainingLength,
                MalformedMQTTPattern::InvalidPacketType,
                MalformedMQTTPattern::TruncatedPayload,
                MalformedMQTTPattern::OversizedPayload,
                MalformedMQTTPattern::InvalidQoS,
                MalformedMQTTPattern::MalformedUtf8,
                MalformedMQTTPattern::InvalidTopicFilter,
                MalformedMQTTPattern::ExcessiveSubscriptions,
                MalformedMQTTPattern::ProtocolViolation,
            ],
        }
    }
    
    fn select_topic(&self, data: &mut Unstructured) -> String {
        if data.arbitrary::<bool>().unwrap_or(false) && !self.topic_corpus.is_empty() {
            let idx = data.arbitrary::<usize>().unwrap_or(0) % self.topic_corpus.len();
            self.topic_corpus[idx].clone()
        } else {
            self.generate_random_topic(data)
        }
    }
    
    fn generate_random_topic(&self, data: &mut Unstructured) -> String {
        let segment_count = data.arbitrary::<usize>().unwrap_or(2) % 10 + 1;
        let mut segments = Vec::new();
        
        for _ in 0..segment_count {
            let segment_len = data.arbitrary::<usize>().unwrap_or(5) % 50 + 1;
            let segment: String = (0..segment_len)
                .map(|_| {
                    let charset = b"abcdefghijklmnopqrstuvwxyz0123456789_-+#";
                    let idx = data.arbitrary::<usize>().unwrap_or(0) % charset.len();
                    charset[idx] as char
                })
                .collect();
            segments.push(segment);
        }
        
        segments.join("/")
    }
    
    fn select_client_id(&self, data: &mut Unstructured) -> String {
        if data.arbitrary::<bool>().unwrap_or(false) && !self.client_id_corpus.is_empty() {
            let idx = data.arbitrary::<usize>().unwrap_or(0) % self.client_id_corpus.len();
            self.client_id_corpus[idx].clone()
        } else {
            self.generate_random_client_id(data)
        }
    }
    
    fn generate_random_client_id(&self, data: &mut Unstructured) -> String {
        let len = data.arbitrary::<usize>().unwrap_or(10) % 100 + 1;
        (0..len)
            .map(|_| {
                let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
                let idx = data.arbitrary::<usize>().unwrap_or(0) % charset.len();
                charset[idx] as char
            })
            .collect()
    }
    
    fn select_payload(&self, data: &mut Unstructured) -> Vec<u8> {
        if data.arbitrary::<bool>().unwrap_or(false) && !self.payload_corpus.is_empty() {
            let idx = data.arbitrary::<usize>().unwrap_or(0) % self.payload_corpus.len();
            self.payload_corpus[idx].clone()
        } else {
            self.generate_random_payload(data)
        }
    }
    
    fn generate_random_payload(&self, data: &mut Unstructured) -> Vec<u8> {
        let len = data.arbitrary::<usize>().unwrap_or(100) % 10000;
        (0..len).map(|_| data.arbitrary().unwrap_or_else(|_| thread_rng().gen())).collect()
    }
    
    fn generate_connect_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>> {
        let client_id = self.select_client_id(data);
        let keep_alive = data.arbitrary::<u16>().unwrap_or(60);
        let clean_session = data.arbitrary::<bool>().unwrap_or(true);
        
        // Create CONNECT packet manually to have more control
        let mut packet = BytesMut::new();
        
        // Fixed header
        packet.put_u8(0x10); // CONNECT packet type
        
        // Variable header
        let protocol_name = "MQTT";
        let protocol_level = 4u8; // MQTT 3.1.1
        let connect_flags = if clean_session { 0x02 } else { 0x00 };
        
        let variable_header_len = 2 + protocol_name.len() + 1 + 1 + 2; // Protocol name length + name + level + flags + keep alive
        let payload_len = 2 + client_id.len(); // Client ID length + client ID
        let remaining_length = variable_header_len + payload_len;
        
        self.encode_remaining_length(&mut packet, remaining_length);
        
        // Protocol name
        packet.put_u16(protocol_name.len() as u16);
        packet.put_slice(protocol_name.as_bytes());
        
        // Protocol level
        packet.put_u8(protocol_level);
        
        // Connect flags
        packet.put_u8(connect_flags);
        
        // Keep alive
        packet.put_u16(keep_alive);
        
        // Payload - Client ID
        packet.put_u16(client_id.len() as u16);
        packet.put_slice(client_id.as_bytes());
        
        Ok(packet.to_vec())
    }
    
    fn generate_publish_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>> {
        let topic = self.select_topic(data);
        let payload = self.select_payload(data);
        let qos = match data.arbitrary::<u8>().unwrap_or(0) % 3 {
            0 => QoS::AtMostOnce,
            1 => QoS::AtLeastOnce,
            _ => QoS::ExactlyOnce,
        };
        let retain = data.arbitrary::<bool>().unwrap_or(false);
        let dup = data.arbitrary::<bool>().unwrap_or(false);
        
        let mut packet = BytesMut::new();
        
        // Fixed header
        let mut flags = 0x30; // PUBLISH packet type
        if dup { flags |= 0x08; }
        flags |= (qos as u8) << 1;
        if retain { flags |= 0x01; }
        packet.put_u8(flags);
        
        // Calculate remaining length
        let mut remaining_length = 2 + topic.len() + payload.len(); // Topic length + topic + payload
        if qos != QoS::AtMostOnce {
            remaining_length += 2; // Packet identifier
        }
        
        self.encode_remaining_length(&mut packet, remaining_length);
        
        // Variable header - Topic
        packet.put_u16(topic.len() as u16);
        packet.put_slice(topic.as_bytes());
        
        // Packet identifier (for QoS > 0)
        if qos != QoS::AtMostOnce {
            packet.put_u16(data.arbitrary::<u16>().unwrap_or(1));
        }
        
        // Payload
        packet.put_slice(&payload);
        
        Ok(packet.to_vec())
    }
    
    fn generate_subscribe_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>> {
        let packet_id = data.arbitrary::<u16>().unwrap_or(1);
        let subscription_count = data.arbitrary::<usize>().unwrap_or(1) % 10 + 1;
        
        let mut packet = BytesMut::new();
        
        // Fixed header
        packet.put_u8(0x82); // SUBSCRIBE packet type with reserved flags
        
        // Calculate remaining length
        let mut remaining_length = 2; // Packet identifier
        let mut topics = Vec::new();
        
        for _ in 0..subscription_count {
            let topic = self.select_topic(data);
            remaining_length += 2 + topic.len() + 1; // Topic length + topic + QoS
            topics.push(topic);
        }
        
        self.encode_remaining_length(&mut packet, remaining_length);
        
        // Variable header - Packet identifier
        packet.put_u16(packet_id);
        
        // Payload - Topic filters
        for topic in topics {
            packet.put_u16(topic.len() as u16);
            packet.put_slice(topic.as_bytes());
            packet.put_u8(data.arbitrary::<u8>().unwrap_or(0) % 3); // QoS
        }
        
        Ok(packet.to_vec())
    }
    
    fn encode_remaining_length(&self, packet: &mut BytesMut, mut length: usize) {
        loop {
            let mut byte = (length % 128) as u8;
            length /= 128;
            if length > 0 {
                byte |= 0x80;
            }
            packet.put_u8(byte);
            if length == 0 {
                break;
            }
        }
    }
    
    fn apply_malformed_pattern(&self, base_packet: &[u8], pattern: &MalformedMQTTPattern, data: &mut Unstructured) -> Result<Vec<u8>> {
        let mut packet = base_packet.to_vec();
        
        match pattern {
            MalformedMQTTPattern::InvalidFixedHeader => {
                if !packet.is_empty() {
                    // Corrupt the packet type or reserved bits
                    packet[0] = data.arbitrary::<u8>().unwrap_or(0xFF);
                }
            }
            
            MalformedMQTTPattern::OversizedRemainingLength => {
                // Create an invalid remaining length encoding
                if packet.len() > 1 {
                    packet[1] = 0xFF; // Invalid remaining length
                    packet.insert(2, 0xFF);
                    packet.insert(3, 0xFF);
                    packet.insert(4, 0xFF);
                    packet.insert(5, 0x7F); // Should be max 4 bytes
                }
            }
            
            MalformedMQTTPattern::InvalidPacketType => {
                if !packet.is_empty() {
                    // Set invalid packet type (15 is reserved)
                    packet[0] = (packet[0] & 0x0F) | 0xF0;
                }
            }
            
            MalformedMQTTPattern::TruncatedPayload => {
                // Truncate packet but keep valid remaining length
                if packet.len() > 5 {
                    let truncate_at = packet.len() / 2;
                    packet.truncate(truncate_at);
                }
            }
            
            MalformedMQTTPattern::OversizedPayload => {
                // Add excessive data
                let extra_size = data.arbitrary::<usize>().unwrap_or(10000) % 100000;
                packet.extend(vec![0x41; extra_size]); // 'A' characters
            }
            
            MalformedMQTTPattern::InvalidQoS => {
                // For PUBLISH packets, set invalid QoS (3 is reserved)
                if !packet.is_empty() && (packet[0] & 0xF0) == 0x30 {
                    packet[0] = (packet[0] & 0xF9) | 0x06; // QoS = 3 (invalid)
                }
            }
            
            MalformedMQTTPattern::MalformedUtf8 => {
                // Inject invalid UTF-8 sequences
                self.inject_invalid_utf8(&mut packet, data);
            }
            
            MalformedMQTTPattern::InvalidTopicFilter => {
                // Inject invalid topic filters
                self.inject_invalid_topic_filter(&mut packet, data);
            }
            
            MalformedMQTTPattern::ExcessiveSubscriptions => {
                // Create packet with too many subscriptions
                if (packet[0] & 0xF0) == 0x80 { // SUBSCRIBE
                    self.inject_excessive_subscriptions(&mut packet, data);
                }
            }
            
            MalformedMQTTPattern::ProtocolViolation => {
                // Various protocol violations
                self.inject_protocol_violation(&mut packet, data);
            }
        }
        
        Ok(packet)
    }
    
    fn inject_invalid_utf8(&self, packet: &mut Vec<u8>, data: &mut Unstructured) {
        if packet.len() > 10 {
            let pos = 10 + data.arbitrary::<usize>().unwrap_or(1) % (packet.len() - 10);
            if pos < packet.len() {
                // Inject invalid UTF-8 byte sequence
                packet[pos] = 0xFF;
                if pos + 1 < packet.len() {
                    packet[pos + 1] = 0xFE;
                }
            }
        }
    }
    
    fn inject_invalid_topic_filter(&self, packet: &mut Vec<u8>, data: &mut Unstructured) {
        // Look for topic filter in SUBSCRIBE packet and make it invalid
        if packet.len() > 4 && (packet[0] & 0xF0) == 0x80 {
            // Find topic filters and corrupt them
            let mut pos = 4; // Skip fixed header and packet ID
            while pos + 2 < packet.len() {
                let topic_len = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
                if pos + 2 + topic_len < packet.len() {
                    // Inject null character in topic (invalid)
                    let corrupt_pos = pos + 2 + data.arbitrary::<usize>().unwrap_or(1) % topic_len.max(1);
                    if corrupt_pos < packet.len() {
                        packet[corrupt_pos] = 0x00;
                    }
                    pos += 2 + topic_len + 1; // Move to next topic
                } else {
                    break;
                }
            }
        }
    }
    
    fn inject_excessive_subscriptions(&self, packet: &mut Vec<u8>, data: &mut Unstructured) {
        // Add many more subscriptions to stress test the broker
        let additional_count = data.arbitrary::<usize>().unwrap_or(100) % 1000 + 100;
        
        for _ in 0..additional_count {
            let topic = format!("topic{}", thread_rng().gen::<u32>());
            packet.extend_from_slice(&(topic.len() as u16).to_be_bytes());
            packet.extend_from_slice(topic.as_bytes());
            packet.push(data.arbitrary::<u8>().unwrap_or(0) % 3); // QoS
        }
        
        // Update remaining length (this will be wrong, which is part of the test)
    }
    
    fn inject_protocol_violation(&self, packet: &mut Vec<u8>, data: &mut Unstructured) {
        let violation_type = data.arbitrary::<u8>().unwrap_or(0) % 4;
        
        match violation_type {
            0 => {
                // CONNECT with invalid protocol name
                if packet.len() > 10 && packet[0] == 0x10 {
                    // Change protocol name to something invalid
                    if packet[9] == b'M' && packet[10] == b'Q' {
                        packet[9] = b'X';
                        packet[10] = b'X';
                    }
                }
            }
            1 => {
                // Duplicate CONNECT packets (protocol violation)
                // This would be handled at the session level
            }
            2 => {
                // Invalid reserved flags
                if !packet.is_empty() {
                    packet[0] |= data.arbitrary::<u8>().unwrap_or(1) & 0x0F;
                }
            }
            3 => {
                // String length mismatches
                if packet.len() > 4 {
                    // Find string length fields and corrupt them
                    for i in 2..packet.len()-2 {
                        if i % 7 == 0 { // Arbitrary pattern to find potential length fields
                            packet[i] = data.arbitrary::<u8>().unwrap_or(0xFF);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

impl ProtocolFuzzer for MQTTFuzzer {
    fn generate_valid_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>> {
        let packet_type = data.arbitrary::<u8>().unwrap_or(0) % 4;
        
        match packet_type {
            0 => self.generate_connect_packet(data),
            1 => self.generate_publish_packet(data),
            2 => self.generate_subscribe_packet(data),
            _ => {
                // PINGREQ packet (simplest)
                Ok(vec![0xC0, 0x00])
            }
        }
    }
    
    fn generate_malformed_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>> {
        // Start with a valid packet
        let base_packet = self.generate_valid_packet(data)?;
        
        // Apply one or more malformed patterns
        let pattern_count = data.arbitrary::<usize>().unwrap_or(1) % 3 + 1;
        let mut packet = base_packet;
        
        for _ in 0..pattern_count {
            let pattern_idx = data.arbitrary::<usize>().unwrap_or(0) % self.malformed_patterns.len();
            let pattern = &self.malformed_patterns[pattern_idx];
            packet = self.apply_malformed_pattern(&packet, pattern, data)?;
        }
        
        Ok(packet)
    }
    
    fn mutate_packet(&self, packet: &[u8], data: &mut Unstructured) -> Result<Vec<u8>> {
        let mutation_type = data.arbitrary::<u8>().unwrap_or(0) % 5;
        
        match mutation_type {
            0 => Ok(common::bit_flip_mutation(packet, data)),
            1 => Ok(common::byte_insert_mutation(packet, data)),
            2 => Ok(common::byte_delete_mutation(packet, data)),
            3 => Ok(common::arithmetic_mutation(packet, data)),
            4 => {
                // MQTT-specific mutation
                let pattern_idx = data.arbitrary::<usize>().unwrap_or(0) % self.malformed_patterns.len();
                let pattern = &self.malformed_patterns[pattern_idx];
                self.apply_malformed_pattern(packet, pattern, data)
            }
            _ => Ok(packet.to_vec()),
        }
    }
    
    fn validate_packet(&self, packet: &[u8]) -> bool {
        if packet.is_empty() {
            return false;
        }
        
        // Basic MQTT packet validation
        let packet_type = (packet[0] & 0xF0) >> 4;
        
        // Check if packet type is valid (1-14)
        if packet_type == 0 || packet_type == 15 {
            return false;
        }
        
        // Check remaining length encoding
        if packet.len() < 2 {
            return false;
        }
        
        let mut pos = 1;
        let mut multiplier = 1;
        let mut remaining_length = 0;
        
        loop {
            if pos >= packet.len() {
                return false;
            }
            
            let byte = packet[pos];
            remaining_length += (byte & 0x7F) as usize * multiplier;
            
            if (byte & 0x80) == 0 {
                break;
            }
            
            multiplier *= 128;
            if multiplier > 128 * 128 * 128 {
                return false; // Invalid remaining length encoding
            }
            
            pos += 1;
            if pos - 1 > 4 {
                return false; // Too many bytes for remaining length
            }
        }
        
        // Check if actual remaining length matches
        let expected_total_length = pos + 1 + remaining_length;
        expected_total_length == packet.len()
    }
    
    fn extract_features(&self, packet: &[u8]) -> Vec<u64> {
        let mut features = Vec::new();
        
        if packet.is_empty() {
            features.push(0);
            return features;
        }
        
        // Extract packet type and flags
        let packet_type = (packet[0] & 0xF0) >> 4;
        let flags = packet[0] & 0x0F;
        
        features.push(packet_type as u64);
        features.push(flags as u64);
        features.push(packet.len() as u64);
        
        // Extract remaining length
        if packet.len() > 1 {
            let mut remaining_length = 0;
            let mut multiplier = 1;
            let mut pos = 1;
            
            while pos < packet.len() {
                let byte = packet[pos];
                remaining_length += (byte & 0x7F) as u64 * multiplier;
                
                if (byte & 0x80) == 0 {
                    break;
                }
                
                multiplier *= 128;
                pos += 1;
                
                if pos > 5 || multiplier > 128 * 128 * 128 {
                    break;
                }
            }
            
            features.push(remaining_length);
        }
        
        // Extract protocol-specific features based on packet type
        match packet_type {
            1 => { // CONNECT
                if packet.len() > 10 {
                    // Simple protocol name length extraction
                    if packet.len() >= 12 {
                        let protocol_name_len = u16::from_be_bytes([packet[10], packet[11]]) as u64;
                        features.push(protocol_name_len);
                    }
                }
            }
            3 => { // PUBLISH
                // Extract QoS level
                let qos = (flags >> 1) & 0x03;
                features.push(qos as u64);
                
                // Extract retain and dup flags
                features.push((flags & 0x01) as u64); // Retain
                features.push(((flags >> 3) & 0x01) as u64); // DUP
            }
            _ => {}
        }
        
        features
    }
    
    fn get_grammar_mutations(&self) -> Vec<Box<dyn Fn(&[u8], &mut Unstructured) -> Result<Vec<u8>> + Send + Sync>> {
        let mut mutations = Vec::new();
        
        // Packet type mutations
        mutations.push(Box::new(|packet: &[u8], data: &mut Unstructured| {
            let mut result = packet.to_vec();
            if !result.is_empty() {
                let new_type = data.arbitrary::<u8>().unwrap_or(1) % 15 + 1;
                result[0] = (result[0] & 0x0F) | (new_type << 4);
            }
            Ok(result)
        }) as Box<dyn Fn(&[u8], &mut Unstructured) -> Result<Vec<u8>> + Send + Sync>);
        
        // Remaining length mutations
        mutations.push(Box::new(|packet: &[u8], data: &mut Unstructured| {
            let mut result = packet.to_vec();
            if result.len() > 1 {
                result[1] = data.arbitrary::<u8>().unwrap_or(result[1]);
            }
            Ok(result)
        }) as Box<dyn Fn(&[u8], &mut Unstructured) -> Result<Vec<u8>> + Send + Sync>);
        
        // String field mutations
        mutations.push(Box::new(|packet: &[u8], data: &mut Unstructured| {
            let mut result = packet.to_vec();
            // Find and mutate string length fields
            for i in 2..result.len().saturating_sub(2) {
                if i % 10 == 0 { // Heuristic to find potential string length fields
                    let new_len = data.arbitrary::<u16>().unwrap_or(0);
                    let bytes = new_len.to_be_bytes();
                    result[i] = bytes[0];
                    if i + 1 < result.len() {
                        result[i + 1] = bytes[1];
                    }
                }
            }
            Ok(result)
        }) as Box<dyn Fn(&[u8], &mut Unstructured) -> Result<Vec<u8>> + Send + Sync>);
        
        mutations
    }
}