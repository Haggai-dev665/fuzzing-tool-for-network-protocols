use super::{CoverageCollector, CoverageStats, ExecutionResult};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

/// Edge-based coverage collector that tracks execution paths
/// through protocol parsing and handling logic
pub struct EdgeCoverageCollector {
    /// Map of edge hashes to hit counts
    edge_map: HashMap<u64, u64>,
    
    /// Unique execution paths discovered
    unique_paths: HashSet<Vec<u64>>,
    
    /// Path frequencies for diversity analysis
    path_frequencies: HashMap<Vec<u64>, u64>,
    
    /// Total executions recorded
    total_executions: u64,
    
    /// Flag to track if new coverage was found since last check
    new_coverage_found: bool,
    
    /// Last reported coverage count for new coverage detection
    last_coverage_count: usize,
}

impl EdgeCoverageCollector {
    pub fn new() -> Self {
        Self {
            edge_map: HashMap::new(),
            unique_paths: HashSet::new(),
            path_frequencies: HashMap::new(),
            total_executions: 0,
            new_coverage_found: false,
            last_coverage_count: 0,
        }
    }
    
    /// Extract execution edges from input data and execution result
    fn extract_edges(&self, input_data: &[u8], execution_result: &ExecutionResult) -> Vec<u64> {
        let mut edges = Vec::new();
        
        // Extract edges based on input characteristics
        edges.extend(self.extract_input_edges(input_data));
        
        // Extract edges based on execution behavior
        edges.extend(self.extract_execution_edges(execution_result));
        
        // Extract edges based on response patterns
        if let Some(response) = &execution_result.response_data {
            edges.extend(self.extract_response_edges(response));
        }
        
        edges
    }
    
    fn extract_input_edges(&self, input_data: &[u8]) -> Vec<u64> {
        let mut edges = Vec::new();
        
        if input_data.is_empty() {
            edges.push(self.hash_edge("empty_input", &[0]));
            return edges;
        }
        
        // Input size edges
        let size_category = match input_data.len() {
            0 => "empty",
            1..=10 => "tiny",
            11..=100 => "small",
            101..=1000 => "medium",
            1001..=10000 => "large",
            _ => "huge",
        };
        edges.push(self.hash_edge("input_size", size_category.as_bytes()));
        
        // Header pattern edges (first few bytes)
        if input_data.len() >= 1 {
            edges.push(self.hash_edge("first_byte", &[input_data[0]]));
        }
        
        if input_data.len() >= 2 {
            let header = u16::from_be_bytes([input_data[0], input_data[1]]);
            edges.push(self.hash_edge("header_u16", &header.to_be_bytes()));
        }
        
        if input_data.len() >= 4 {
            let header = u32::from_be_bytes([input_data[0], input_data[1], input_data[2], input_data[3]]);
            edges.push(self.hash_edge("header_u32", &header.to_be_bytes()));
        }
        
        // Byte value distribution edges
        let mut byte_counts = [0u16; 256];
        for &byte in input_data {
            byte_counts[byte as usize] = byte_counts[byte as usize].saturating_add(1);
        }
        
        // Most common byte
        let (most_common_byte, _) = byte_counts
            .iter()
            .enumerate()
            .max_by_key(|(_, &count)| count)
            .unwrap_or((0, &0));
        edges.push(self.hash_edge("most_common_byte", &[most_common_byte as u8]));
        
        // Entropy category
        let entropy = self.calculate_entropy(input_data);
        let entropy_category = match entropy {
            e if e < 1.0 => "very_low_entropy",
            e if e < 2.0 => "low_entropy",
            e if e < 4.0 => "medium_entropy",
            e if e < 6.0 => "high_entropy",
            _ => "very_high_entropy",
        };
        edges.push(self.hash_edge("entropy", entropy_category.as_bytes()));
        
        // Structural pattern edges
        if input_data.len() > 10 {
            // Look for repeated patterns
            let pattern_length = 4;
            for i in 0..=(input_data.len() - pattern_length * 2) {
                let pattern = &input_data[i..i + pattern_length];
                for j in (i + pattern_length)..=(input_data.len() - pattern_length) {
                    if &input_data[j..j + pattern_length] == pattern {
                        edges.push(self.hash_edge("repeated_pattern", pattern));
                        break;
                    }
                }
            }
        }
        
        edges
    }
    
    fn extract_execution_edges(&self, execution_result: &ExecutionResult) -> Vec<u64> {
        let mut edges = Vec::new();
        
        // Success/failure edge
        if execution_result.success {
            edges.push(self.hash_edge("execution", b"success"));
        } else {
            edges.push(self.hash_edge("execution", b"failure"));
        }
        
        // Execution time edges
        let time_category = match execution_result.execution_time_ms {
            0..=10 => "very_fast",
            11..=100 => "fast",
            101..=1000 => "medium",
            1001..=5000 => "slow",
            _ => "very_slow",
        };
        edges.push(self.hash_edge("execution_time", time_category.as_bytes()));
        
        // Error type edges
        if let Some(error) = &execution_result.error_message {
            let error_type = self.classify_error(error);
            edges.push(self.hash_edge("error_type", error_type.as_bytes()));
        }
        
        edges
    }
    
    fn extract_response_edges(&self, response_data: &[u8]) -> Vec<u64> {
        let mut edges = Vec::new();
        
        if response_data.is_empty() {
            edges.push(self.hash_edge("response", b"empty"));
            return edges;
        }
        
        // Response size edges
        let size_category = match response_data.len() {
            1..=10 => "tiny_response",
            11..=100 => "small_response",
            101..=1000 => "medium_response",
            1001..=10000 => "large_response",
            _ => "huge_response",
        };
        edges.push(self.hash_edge("response_size", size_category.as_bytes()));
        
        // Response header edges
        if response_data.len() >= 1 {
            edges.push(self.hash_edge("response_first_byte", &[response_data[0]]));
        }
        
        if response_data.len() >= 2 {
            let header = u16::from_be_bytes([response_data[0], response_data[1]]);
            edges.push(self.hash_edge("response_header", &header.to_be_bytes()));
        }
        
        // Response pattern edges
        if response_data.starts_with(b"HTTP") {
            edges.push(self.hash_edge("response_protocol", b"http"));
        } else if response_data.starts_with(&[0x00, 0x00]) {
            edges.push(self.hash_edge("response_protocol", b"binary"));
        } else if response_data.iter().all(|&b| b.is_ascii()) {
            edges.push(self.hash_edge("response_protocol", b"ascii"));
        } else {
            edges.push(self.hash_edge("response_protocol", b"binary"));
        }
        
        edges
    }
    
    fn hash_edge(&self, edge_type: &str, data: &[u8]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        edge_type.hash(&mut hasher);
        data.hash(&mut hasher);
        hasher.finish()
    }
    
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let length = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in counts.iter() {
            if count > 0 {
                let probability = count as f64 / length;
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    fn classify_error(&self, error_message: &str) -> String {
        let error_lower = error_message.to_lowercase();
        
        if error_lower.contains("connection") {
            "connection_error".to_string()
        } else if error_lower.contains("timeout") {
            "timeout_error".to_string()
        } else if error_lower.contains("parse") || error_lower.contains("invalid") {
            "parse_error".to_string()
        } else if error_lower.contains("network") {
            "network_error".to_string()
        } else if error_lower.contains("protocol") {
            "protocol_error".to_string()
        } else {
            "unknown_error".to_string()
        }
    }
    
    pub fn get_total_edges(&self) -> usize {
        self.edge_map.len()
    }
    
    pub fn get_covered_edges(&self) -> usize {
        self.edge_map.values().filter(|&&count| count > 0).count()
    }
    
    pub fn get_path_frequencies(&self) -> &HashMap<Vec<u64>, u64> {
        &self.path_frequencies
    }
}

impl CoverageCollector for EdgeCoverageCollector {
    fn record_execution(&mut self, input_data: &[u8], execution_result: &ExecutionResult) {
        self.total_executions += 1;
        
        // Extract execution edges
        let edges = self.extract_edges(input_data, execution_result);
        
        // Update edge coverage
        let mut new_edges_found = false;
        for edge in &edges {
            let count = self.edge_map.entry(*edge).or_insert(0);
            if *count == 0 {
                new_edges_found = true;
            }
            *count += 1;
        }
        
        // Track unique paths
        if !edges.is_empty() {
            if self.unique_paths.insert(edges.clone()) {
                new_edges_found = true;
            }
            
            // Update path frequency
            *self.path_frequencies.entry(edges).or_insert(0) += 1;
        }
        
        // Update new coverage flag
        if new_edges_found {
            self.new_coverage_found = true;
        }
    }
    
    fn get_coverage_stats(&self) -> CoverageStats {
        let total_edges = self.get_total_edges();
        let covered_edges = self.get_covered_edges();
        
        let coverage_percentage = if total_edges > 0 {
            (covered_edges as f64 / total_edges as f64) * 100.0
        } else {
            0.0
        };
        
        CoverageStats {
            total_executions: self.total_executions,
            unique_paths: self.unique_paths.len(),
            coverage_percentage,
            new_coverage_found: self.new_coverage_found,
        }
    }
    
    fn has_new_coverage(&self) -> bool {
        let current_count = self.unique_paths.len();
        current_count > self.last_coverage_count
    }
    
    fn export_coverage_data(&self) -> Result<Vec<u8>> {
        use std::io::Write;
        
        let mut data = Vec::new();
        
        // Write edge map
        data.write_all(&(self.edge_map.len() as u64).to_le_bytes())?;
        for (&edge, &count) in &self.edge_map {
            data.write_all(&edge.to_le_bytes())?;
            data.write_all(&count.to_le_bytes())?;
        }
        
        // Write unique paths count
        data.write_all(&(self.unique_paths.len() as u64).to_le_bytes())?;
        
        // Write total executions
        data.write_all(&self.total_executions.to_le_bytes())?;
        
        Ok(data)
    }
    
    fn reset(&mut self) {
        self.edge_map.clear();
        self.unique_paths.clear();
        self.path_frequencies.clear();
        self.total_executions = 0;
        self.new_coverage_found = false;
        self.last_coverage_count = 0;
    }
}

impl Default for EdgeCoverageCollector {
    fn default() -> Self {
        Self::new()
    }
}