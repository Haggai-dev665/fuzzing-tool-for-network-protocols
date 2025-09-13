use super::{CoverageCollector, CoverageStats, ExecutionResult};
use crate::protocols::{create_protocol_fuzzer, ProtocolType};
use anyhow::Result;
use std::collections::{HashMap, HashSet};

/// Feature-based coverage collector that tracks protocol-specific features
/// and behaviors discovered during fuzzing
pub struct FeatureCoverageCollector {
    protocol_type: ProtocolType,
    
    /// Features discovered and their frequency
    feature_map: HashMap<String, u64>,
    
    /// Protocol-specific feature extractors
    feature_extractors: Vec<Box<dyn FeatureExtractor + Send + Sync>>,
    
    /// Total executions recorded
    total_executions: u64,
    
    /// Flag to track new feature discovery
    new_features_found: bool,
    
    /// Last known feature count
    last_feature_count: usize,
}

pub trait FeatureExtractor: Send + Sync {
    /// Extract features from input data
    fn extract_input_features(&self, input_data: &[u8]) -> Vec<String>;
    
    /// Extract features from execution result
    fn extract_execution_features(&self, execution_result: &ExecutionResult) -> Vec<String>;
    
    /// Get the name of this feature extractor
    fn name(&self) -> &str;
}

impl FeatureCoverageCollector {
    pub fn new(protocol_type: ProtocolType) -> Self {
        let feature_extractors = create_feature_extractors(protocol_type);
        
        Self {
            protocol_type,
            feature_map: HashMap::new(),
            feature_extractors,
            total_executions: 0,
            new_features_found: false,
            last_feature_count: 0,
        }
    }
    
    pub fn get_total_features(&self) -> usize {
        self.feature_map.len()
    }
    
    pub fn get_covered_features(&self) -> usize {
        self.feature_map.values().filter(|&&count| count > 0).count()
    }
    
    pub fn get_feature_frequency(&self) -> HashMap<String, u64> {
        self.feature_map.clone()
    }
    
    pub fn get_rare_features(&self) -> Vec<String> {
        let mut rare_features: Vec<_> = self.feature_map
            .iter()
            .filter(|(_, &count)| count <= 5) // Features seen 5 times or less
            .map(|(feature, _)| feature.clone())
            .collect();
        
        rare_features.sort();
        rare_features
    }
    
    pub fn calculate_entropy(&self) -> f64 {
        if self.feature_map.is_empty() {
            return 0.0;
        }
        
        let total_count: u64 = self.feature_map.values().sum();
        if total_count == 0 {
            return 0.0;
        }
        
        let mut entropy = 0.0;
        for &count in self.feature_map.values() {
            if count > 0 {
                let probability = count as f64 / total_count as f64;
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    fn extract_all_features(&self, input_data: &[u8], execution_result: &ExecutionResult) -> Vec<String> {
        let mut features = Vec::new();
        
        for extractor in &self.feature_extractors {
            features.extend(extractor.extract_input_features(input_data));
            features.extend(extractor.extract_execution_features(execution_result));
        }
        
        // Add protocol-specific features using the protocol fuzzer
        let protocol_fuzzer = create_protocol_fuzzer(self.protocol_type);
        let protocol_features = protocol_fuzzer.extract_features(input_data);
        
        for (i, feature) in protocol_features.iter().enumerate() {
            features.push(format!("protocol_feature_{}_{}", i, feature));
        }
        
        features
    }
}

impl CoverageCollector for FeatureCoverageCollector {
    fn record_execution(&mut self, input_data: &[u8], execution_result: &ExecutionResult) {
        self.total_executions += 1;
        
        let features = self.extract_all_features(input_data, execution_result);
        
        let mut new_features_discovered = false;
        for feature in features {
            let count = self.feature_map.entry(feature).or_insert(0);
            if *count == 0 {
                new_features_discovered = true;
            }
            *count += 1;
        }
        
        if new_features_discovered {
            self.new_features_found = true;
        }
    }
    
    fn get_coverage_stats(&self) -> CoverageStats {
        let total_features = self.get_total_features();
        let covered_features = self.get_covered_features();
        
        let coverage_percentage = if total_features > 0 {
            (covered_features as f64 / total_features as f64) * 100.0
        } else {
            0.0
        };
        
        CoverageStats {
            total_executions: self.total_executions,
            unique_paths: covered_features, // Use covered features as unique paths for feature coverage
            coverage_percentage,
            new_coverage_found: self.new_features_found,
        }
    }
    
    fn has_new_coverage(&self) -> bool {
        let current_count = self.feature_map.len();
        current_count > self.last_feature_count
    }
    
    fn export_coverage_data(&self) -> Result<Vec<u8>> {
        let data = serde_json::to_vec(&self.feature_map)?;
        Ok(data)
    }
    
    fn reset(&mut self) {
        self.feature_map.clear();
        self.total_executions = 0;
        self.new_features_found = false;
        self.last_feature_count = 0;
    }
}

// Generic feature extractor for common protocol patterns
struct GenericProtocolFeatureExtractor;

impl FeatureExtractor for GenericProtocolFeatureExtractor {
    fn extract_input_features(&self, input_data: &[u8]) -> Vec<String> {
        let mut features = Vec::new();
        
        if input_data.is_empty() {
            features.push("empty_input".to_string());
            return features;
        }
        
        // Size-based features
        features.push(format!("input_size_{}", categorize_size(input_data.len())));
        
        // Byte pattern features
        if input_data.len() >= 1 {
            features.push(format!("first_byte_{:02x}", input_data[0]));
        }
        
        if input_data.len() >= 2 {
            features.push(format!("first_two_bytes_{:04x}", 
                u16::from_be_bytes([input_data[0], input_data[1]])));
        }
        
        // Null byte presence
        if input_data.contains(&0) {
            features.push("contains_null_bytes".to_string());
        }
        
        // ASCII vs binary content
        if input_data.iter().all(|&b| b.is_ascii()) {
            features.push("ascii_content".to_string());
        } else {
            features.push("binary_content".to_string());
        }
        
        // Repeated byte patterns
        if has_repeated_bytes(input_data) {
            features.push("has_repeated_patterns".to_string());
        }
        
        features
    }
    
    fn extract_execution_features(&self, execution_result: &ExecutionResult) -> Vec<String> {
        let mut features = Vec::new();
        
        if execution_result.success {
            features.push("execution_success".to_string());
        } else {
            features.push("execution_failure".to_string());
        }
        
        // Timing features
        features.push(format!("timing_{}", categorize_timing(execution_result.execution_time_ms)));
        
        // Response features
        if let Some(response) = &execution_result.response_data {
            features.push(format!("response_size_{}", categorize_size(response.len())));
            
            if !response.is_empty() {
                features.push(format!("response_first_byte_{:02x}", response[0]));
            }
        } else {
            features.push("no_response".to_string());
        }
        
        // Error features
        if let Some(error) = &execution_result.error_message {
            features.push(format!("error_{}", categorize_error(error)));
        }
        
        features
    }
    
    fn name(&self) -> &str {
        "GenericProtocolFeatureExtractor"
    }
}

// DNS-specific feature extractor
struct DNSFeatureExtractor;

impl FeatureExtractor for DNSFeatureExtractor {
    fn extract_input_features(&self, input_data: &[u8]) -> Vec<String> {
        let mut features = Vec::new();
        
        if input_data.len() < 12 {
            features.push("dns_too_short".to_string());
            return features;
        }
        
        // DNS header analysis
        let flags = u16::from_be_bytes([input_data[2], input_data[3]]);
        
        // Query/Response bit
        if (flags & 0x8000) != 0 {
            features.push("dns_response".to_string());
        } else {
            features.push("dns_query".to_string());
        }
        
        // Opcode
        let opcode = (flags >> 11) & 0x0F;
        features.push(format!("dns_opcode_{}", opcode));
        
        // Flags
        if (flags & 0x0400) != 0 { features.push("dns_authoritative".to_string()); }
        if (flags & 0x0200) != 0 { features.push("dns_truncated".to_string()); }
        if (flags & 0x0100) != 0 { features.push("dns_recursion_desired".to_string()); }
        if (flags & 0x0080) != 0 { features.push("dns_recursion_available".to_string()); }
        
        // Response code
        let rcode = flags & 0x000F;
        features.push(format!("dns_rcode_{}", rcode));
        
        // Question count
        let qdcount = u16::from_be_bytes([input_data[4], input_data[5]]);
        features.push(format!("dns_questions_{}", categorize_count(qdcount)));
        
        // Answer count
        let ancount = u16::from_be_bytes([input_data[6], input_data[7]]);
        features.push(format!("dns_answers_{}", categorize_count(ancount)));
        
        features
    }
    
    fn extract_execution_features(&self, execution_result: &ExecutionResult) -> Vec<String> {
        let mut features = Vec::new();
        
        if let Some(response) = &execution_result.response_data {
            if response.len() >= 12 {
                // Analyze DNS response
                let flags = u16::from_be_bytes([response[2], response[3]]);
                let rcode = flags & 0x000F;
                
                features.push(format!("dns_response_rcode_{}", rcode));
                
                if (flags & 0x8000) != 0 {
                    features.push("valid_dns_response".to_string());
                } else {
                    features.push("invalid_dns_response".to_string());
                }
            }
        }
        
        features
    }
    
    fn name(&self) -> &str {
        "DNSFeatureExtractor"
    }
}

// MQTT-specific feature extractor
struct MQTTFeatureExtractor;

impl FeatureExtractor for MQTTFeatureExtractor {
    fn extract_input_features(&self, input_data: &[u8]) -> Vec<String> {
        let mut features = Vec::new();
        
        if input_data.is_empty() {
            features.push("mqtt_empty".to_string());
            return features;
        }
        
        // MQTT packet type
        let packet_type = (input_data[0] & 0xF0) >> 4;
        features.push(format!("mqtt_packet_type_{}", packet_type));
        
        // MQTT flags
        let flags = input_data[0] & 0x0F;
        features.push(format!("mqtt_flags_{:04b}", flags));
        
        // QoS level (for PUBLISH packets)
        if packet_type == 3 {
            let qos = (flags >> 1) & 0x03;
            features.push(format!("mqtt_qos_{}", qos));
            
            if (flags & 0x01) != 0 { features.push("mqtt_retain".to_string()); }
            if (flags & 0x08) != 0 { features.push("mqtt_dup".to_string()); }
        }
        
        // Remaining length analysis
        if input_data.len() > 1 {
            let remaining_length_bytes = self.count_remaining_length_bytes(&input_data[1..]);
            features.push(format!("mqtt_remaining_length_bytes_{}", remaining_length_bytes));
        }
        
        features
    }
    
    fn extract_execution_features(&self, execution_result: &ExecutionResult) -> Vec<String> {
        let mut features = Vec::new();
        
        if let Some(response) = &execution_result.response_data {
            if !response.is_empty() {
                let packet_type = (response[0] & 0xF0) >> 4;
                features.push(format!("mqtt_response_type_{}", packet_type));
                
                // Common MQTT response types
                match packet_type {
                    2 => features.push("mqtt_connack_received".to_string()),
                    4 => features.push("mqtt_puback_received".to_string()),
                    9 => features.push("mqtt_suback_received".to_string()),
                    13 => features.push("mqtt_pingresp_received".to_string()),
                    _ => features.push("mqtt_unknown_response".to_string()),
                }
            }
        }
        
        features
    }
    
    fn name(&self) -> &str {
        "MQTTFeatureExtractor"
    }
}

impl MQTTFeatureExtractor {
    fn count_remaining_length_bytes(&self, data: &[u8]) -> usize {
        let mut count = 0;
        for &byte in data.iter().take(4) {
            count += 1;
            if (byte & 0x80) == 0 {
                break;
            }
        }
        count
    }
}

// Helper functions
fn categorize_size(size: usize) -> &'static str {
    match size {
        0 => "empty",
        1..=10 => "tiny",
        11..=100 => "small",
        101..=1000 => "medium",
        1001..=10000 => "large",
        _ => "huge",
    }
}

fn categorize_timing(ms: u64) -> &'static str {
    match ms {
        0..=10 => "very_fast",
        11..=100 => "fast",
        101..=1000 => "medium",
        1001..=5000 => "slow",
        _ => "very_slow",
    }
}

fn categorize_count(count: u16) -> &'static str {
    match count {
        0 => "zero",
        1 => "one",
        2..=5 => "few",
        6..=20 => "some",
        21..=100 => "many",
        _ => "too_many",
    }
}

fn categorize_error(error: &str) -> String {
    let error_lower = error.to_lowercase();
    
    if error_lower.contains("connection") {
        "connection".to_string()
    } else if error_lower.contains("timeout") {
        "timeout".to_string()
    } else if error_lower.contains("parse") {
        "parse".to_string()
    } else if error_lower.contains("protocol") {
        "protocol".to_string()
    } else {
        "unknown".to_string()
    }
}

fn has_repeated_bytes(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    
    for window_size in 2..=4 {
        for i in 0..=(data.len() - window_size * 2) {
            let pattern = &data[i..i + window_size];
            for j in (i + window_size)..=(data.len() - window_size) {
                if &data[j..j + window_size] == pattern {
                    return true;
                }
            }
        }
    }
    
    false
}

fn create_feature_extractors(protocol_type: ProtocolType) -> Vec<Box<dyn FeatureExtractor + Send + Sync>> {
    let mut extractors: Vec<Box<dyn FeatureExtractor + Send + Sync>> = vec![
        Box::new(GenericProtocolFeatureExtractor),
    ];
    
    match protocol_type {
        ProtocolType::DNS => {
            extractors.push(Box::new(DNSFeatureExtractor));
        }
        ProtocolType::MQTT => {
            extractors.push(Box::new(MQTTFeatureExtractor));
        }
    }
    
    extractors
}