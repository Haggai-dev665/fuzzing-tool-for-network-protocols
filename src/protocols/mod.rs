use anyhow::{anyhow, Result};
use arbitrary::{Arbitrary, Unstructured};
use serde::{Deserialize, Serialize};

pub mod dns;
pub mod mqtt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum ProtocolType {
    DNS,
    MQTT,
}

impl ProtocolType {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "dns" => Ok(ProtocolType::DNS),
            "mqtt" => Ok(ProtocolType::MQTT),
            _ => Err(anyhow!("Unsupported protocol: {}", s)),
        }
    }
    
    pub fn default_port(&self) -> u16 {
        match self {
            ProtocolType::DNS => 53,
            ProtocolType::MQTT => 1883,
        }
    }
    
    pub fn is_tcp(&self) -> bool {
        match self {
            ProtocolType::DNS => false, // DNS primarily uses UDP
            ProtocolType::MQTT => true,
        }
    }
}

/// Trait for protocol-specific packet generation and mutation
pub trait ProtocolFuzzer: Send + Sync {
    /// Generate a valid protocol packet
    fn generate_valid_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>>;
    
    /// Generate a malformed protocol packet for fuzzing
    fn generate_malformed_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>>;
    
    /// Mutate an existing packet
    fn mutate_packet(&self, packet: &[u8], data: &mut Unstructured) -> Result<Vec<u8>>;
    
    /// Validate if a packet is well-formed
    fn validate_packet(&self, packet: &[u8]) -> bool;
    
    /// Extract interesting features from packets for coverage guidance
    fn extract_features(&self, packet: &[u8]) -> Vec<u64>;
    
    /// Get grammar-based mutations
    fn get_grammar_mutations(&self) -> Vec<Box<dyn Fn(&[u8], &mut Unstructured) -> Result<Vec<u8>> + Send + Sync>>;
}

/// Factory function to create protocol fuzzer instances
pub fn create_protocol_fuzzer(protocol: ProtocolType) -> Box<dyn ProtocolFuzzer> {
    match protocol {
        ProtocolType::DNS => Box::new(dns::DNSFuzzer::new()),
        ProtocolType::MQTT => Box::new(mqtt::MQTTFuzzer::new()),
    }
}

/// Common protocol fuzzing utilities
pub mod common {
    use arbitrary::Unstructured;
    use rand::{thread_rng, Rng};
    
    /// Generate random bytes of specified length
    pub fn random_bytes(len: usize, data: &mut Unstructured) -> Vec<u8> {
        (0..len).map(|_| data.arbitrary().unwrap_or_else(|_| thread_rng().gen())).collect()
    }
    
    /// Introduce bit flips into data
    pub fn bit_flip_mutation(input: &[u8], data: &mut Unstructured) -> Vec<u8> {
        let mut output = input.to_vec();
        if !output.is_empty() {
            let flip_count = data.arbitrary::<usize>().unwrap_or(1) % 8 + 1;
            for _ in 0..flip_count {
                let byte_idx = data.arbitrary::<usize>().unwrap_or(0) % output.len();
                let bit_idx = data.arbitrary::<u8>().unwrap_or(0) % 8;
                output[byte_idx] ^= 1 << bit_idx;
            }
        }
        output
    }
    
    /// Byte insertion mutation
    pub fn byte_insert_mutation(input: &[u8], data: &mut Unstructured) -> Vec<u8> {
        let mut output = input.to_vec();
        let insert_pos = data.arbitrary::<usize>().unwrap_or(0) % (output.len() + 1);
        let insert_byte = data.arbitrary::<u8>().unwrap_or(0);
        output.insert(insert_pos, insert_byte);
        output
    }
    
    /// Byte deletion mutation
    pub fn byte_delete_mutation(input: &[u8], data: &mut Unstructured) -> Vec<u8> {
        let mut output = input.to_vec();
        if !output.is_empty() {
            let delete_pos = data.arbitrary::<usize>().unwrap_or(0) % output.len();
            output.remove(delete_pos);
        }
        output
    }
    
    /// Arithmetic mutation for integer fields
    pub fn arithmetic_mutation(input: &[u8], data: &mut Unstructured) -> Vec<u8> {
        let mut output = input.to_vec();
        if output.len() >= 2 {
            let pos = data.arbitrary::<usize>().unwrap_or(0) % (output.len() - 1);
            let value = u16::from_be_bytes([output[pos], output[pos + 1]]);
            let delta = data.arbitrary::<i16>().unwrap_or(1);
            let new_value = value.wrapping_add(delta as u16);
            let bytes = new_value.to_be_bytes();
            output[pos] = bytes[0];
            output[pos + 1] = bytes[1];
        }
        output
    }
}