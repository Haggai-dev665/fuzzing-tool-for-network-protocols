use super::{ProtocolFuzzer, common};
use anyhow::Result;
use arbitrary::{Arbitrary, Unstructured};
use bytes::{BufMut, BytesMut};
use dns_parser::{Builder, QueryType, QueryClass, Packet, ResponseCode};
use rand::{thread_rng, Rng};
use std::collections::HashMap;

pub struct DNSFuzzer {
    /// Pre-defined domain names for realistic fuzzing
    domain_corpus: Vec<String>,
    /// Query types to fuzz
    query_types: Vec<QueryType>,
    /// Common malformed patterns
    malformed_patterns: Vec<MalformedPattern>,
}

#[derive(Clone)]
enum MalformedPattern {
    InvalidHeader,
    TruncatedQuery,
    OversizedQuery,
    InvalidQType,
    InvalidQClass,
    PointerLoop,
    OversizedLabels,
    InvalidCompression,
}

impl DNSFuzzer {
    pub fn new() -> Self {
        Self {
            domain_corpus: vec![
                "example.com".to_string(),
                "google.com".to_string(),
                "github.com".to_string(),
                "localhost".to_string(),
                "test.local".to_string(),
                "subdomain.example.org".to_string(),
                "very-long-subdomain-name-that-might-cause-issues.example.com".to_string(),
                "192.168.1.1".to_string(), // PTR lookup
            ],
            query_types: vec![
                QueryType::A,
                QueryType::AAAA,
                QueryType::CNAME,
                QueryType::MX,
                QueryType::NS,
                QueryType::PTR,
                QueryType::SOA,
                QueryType::TXT,
                QueryType::SRV,
            ],
            malformed_patterns: vec![
                MalformedPattern::InvalidHeader,
                MalformedPattern::TruncatedQuery,
                MalformedPattern::OversizedQuery,
                MalformedPattern::InvalidQType,
                MalformedPattern::InvalidQClass,
                MalformedPattern::PointerLoop,
                MalformedPattern::OversizedLabels,
                MalformedPattern::InvalidCompression,
            ],
        }
    }
    
    fn generate_domain_name(&self, data: &mut Unstructured) -> String {
        if data.arbitrary::<bool>().unwrap_or(false) && !self.domain_corpus.is_empty() {
            // Use corpus domain
            let idx = data.arbitrary::<usize>().unwrap_or(0) % self.domain_corpus.len();
            self.domain_corpus[idx].clone()
        } else {
            // Generate random domain
            self.generate_random_domain(data)
        }
    }
    
    fn generate_random_domain(&self, data: &mut Unstructured) -> String {
        let label_count = data.arbitrary::<usize>().unwrap_or(2) % 5 + 1;
        let mut labels = Vec::new();
        
        for _ in 0..label_count {
            let label_len = data.arbitrary::<usize>().unwrap_or(3) % 63 + 1;
            let label: String = (0..label_len)
                .map(|_| {
                    let charset = b"abcdefghijklmnopqrstuvwxyz0123456789-";
                    let idx = data.arbitrary::<usize>().unwrap_or(0) % charset.len();
                    charset[idx] as char
                })
                .collect();
            labels.push(label);
        }
        
        labels.join(".")
    }
    
    fn generate_valid_dns_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>> {
        let mut builder = Builder::new_query(
            data.arbitrary::<u16>().unwrap_or(thread_rng().gen()), // Transaction ID
            false, // Not recursive
        );
        
        let domain = self.generate_domain_name(data);
        let query_type_idx = data.arbitrary::<usize>().unwrap_or(0) % self.query_types.len();
        let query_type = self.query_types[query_type_idx];
        
        builder.add_question(&domain, false, query_type, QueryClass::IN);
        
        builder.build().map_err(|_| anyhow::anyhow!("Failed to build DNS packet"))
    }
    
    fn apply_malformed_pattern(&self, base_packet: &[u8], pattern: &MalformedPattern, data: &mut Unstructured) -> Result<Vec<u8>> {
        let mut packet = base_packet.to_vec();
        
        match pattern {
            MalformedPattern::InvalidHeader => {
                // Corrupt header flags
                if packet.len() >= 12 {
                    packet[2] = data.arbitrary::<u8>().unwrap_or(0xFF);
                    packet[3] = data.arbitrary::<u8>().unwrap_or(0xFF);
                }
            }
            
            MalformedPattern::TruncatedQuery => {
                // Truncate the packet randomly
                if packet.len() > 12 {
                    let truncate_at = 12 + data.arbitrary::<usize>().unwrap_or(1) % (packet.len() - 12);
                    packet.truncate(truncate_at);
                }
            }
            
            MalformedPattern::OversizedQuery => {
                // Add excessive padding
                let padding_size = data.arbitrary::<usize>().unwrap_or(1000) % 10000 + 1000;
                packet.extend(vec![0; padding_size]);
            }
            
            MalformedPattern::InvalidQType => {
                // Find and corrupt QTYPE field
                if packet.len() >= 16 {
                    // Look for QTYPE field (2 bytes after domain name)
                    for i in 12..packet.len()-4 {
                        if packet[i] == 0 { // End of domain name
                            packet[i+1] = data.arbitrary::<u8>().unwrap_or(0xFF);
                            packet[i+2] = data.arbitrary::<u8>().unwrap_or(0xFF);
                            break;
                        }
                    }
                }
            }
            
            MalformedPattern::InvalidQClass => {
                // Find and corrupt QCLASS field
                if packet.len() >= 18 {
                    for i in 12..packet.len()-6 {
                        if packet[i] == 0 { // End of domain name
                            packet[i+3] = data.arbitrary::<u8>().unwrap_or(0xFF);
                            packet[i+4] = data.arbitrary::<u8>().unwrap_or(0xFF);
                            break;
                        }
                    }
                }
            }
            
            MalformedPattern::PointerLoop => {
                // Create compression pointer loops
                self.inject_pointer_loop(&mut packet, data);
            }
            
            MalformedPattern::OversizedLabels => {
                // Create labels that exceed the 63-byte limit
                self.inject_oversized_labels(&mut packet, data);
            }
            
            MalformedPattern::InvalidCompression => {
                // Create invalid compression pointers
                self.inject_invalid_compression(&mut packet, data);
            }
        }
        
        Ok(packet)
    }
    
    fn inject_pointer_loop(&self, packet: &mut Vec<u8>, data: &mut Unstructured) {
        if packet.len() > 12 {
            let pos = 12 + data.arbitrary::<usize>().unwrap_or(1) % (packet.len() - 12);
            if pos + 1 < packet.len() {
                // Create a compression pointer that points to itself
                packet[pos] = 0xC0; // Compression flag
                packet[pos + 1] = pos as u8;
            }
        }
    }
    
    fn inject_oversized_labels(&self, packet: &mut Vec<u8>, data: &mut Unstructured) {
        // Find the start of the domain name (after header)
        if packet.len() > 12 {
            let oversized_label_len = data.arbitrary::<u8>().unwrap_or(64).max(64); // > 63 bytes
            let mut new_packet = packet[..12].to_vec();
            
            // Add oversized label
            new_packet.push(oversized_label_len);
            new_packet.extend(vec![b'A'; oversized_label_len as usize]);
            new_packet.push(0); // End of domain
            
            // Add QTYPE and QCLASS
            new_packet.extend_from_slice(&[0, 1, 0, 1]); // A record, IN class
            
            *packet = new_packet;
        }
    }
    
    fn inject_invalid_compression(&self, packet: &mut Vec<u8>, data: &mut Unstructured) {
        if packet.len() > 14 {
            let pos = 12 + data.arbitrary::<usize>().unwrap_or(1) % (packet.len() - 14);
            if pos + 1 < packet.len() {
                // Create a compression pointer that points beyond packet end
                packet[pos] = 0xC0;
                packet[pos + 1] = data.arbitrary::<u8>().unwrap_or(0xFF);
            }
        }
    }
}

impl ProtocolFuzzer for DNSFuzzer {
    fn generate_valid_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>> {
        self.generate_valid_dns_packet(data)
    }
    
    fn generate_malformed_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>> {
        // Start with a valid packet
        let base_packet = self.generate_valid_dns_packet(data)?;
        
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
                // DNS-specific mutation
                let pattern_idx = data.arbitrary::<usize>().unwrap_or(0) % self.malformed_patterns.len();
                let pattern = &self.malformed_patterns[pattern_idx];
                self.apply_malformed_pattern(packet, pattern, data)
            }
            _ => Ok(packet.to_vec()),
        }
    }
    
    fn validate_packet(&self, packet: &[u8]) -> bool {
        match Packet::parse(packet) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    
    fn extract_features(&self, packet: &[u8]) -> Vec<u64> {
        let mut features = Vec::new();
        
        if packet.len() < 12 {
            features.push(0); // Too short
            return features;
        }
        
        // Extract header features
        let transaction_id = u16::from_be_bytes([packet[0], packet[1]]);
        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        
        features.push(transaction_id as u64);
        features.push(flags as u64);
        features.push(qdcount as u64);
        features.push(ancount as u64);
        features.push(packet.len() as u64);
        
        // Extract query type if present
        if let Ok(parsed) = Packet::parse(packet) {
            for question in parsed.questions {
                features.push(question.qtype as u64);
                features.push(question.qclass as u64);
            }
        }
        
        features
    }
    
    fn get_grammar_mutations(&self) -> Vec<Box<dyn Fn(&[u8], &mut Unstructured) -> Result<Vec<u8>> + Send + Sync>> {
        let mut mutations = Vec::new();
        
        // Domain name mutations
        mutations.push(Box::new(|packet: &[u8], data: &mut Unstructured| {
            let mut result = packet.to_vec();
            if result.len() > 12 {
                // Find and mutate domain name
                let domain_start = 12;
                let mut pos = domain_start;
                while pos < result.len() && result[pos] != 0 {
                    let label_len = result[pos] as usize;
                    if label_len > 0 && label_len < 64 && pos + label_len < result.len() {
                        // Mutate label length
                        result[pos] = data.arbitrary::<u8>().unwrap_or(label_len as u8);
                        pos += label_len + 1;
                    } else {
                        break;
                    }
                }
            }
            Ok(result)
        }) as Box<dyn Fn(&[u8], &mut Unstructured) -> Result<Vec<u8>> + Send + Sync>);
        
        // Header flag mutations
        mutations.push(Box::new(|packet: &[u8], data: &mut Unstructured| {
            let mut result = packet.to_vec();
            if result.len() >= 4 {
                result[2] ^= data.arbitrary::<u8>().unwrap_or(1);
                result[3] ^= data.arbitrary::<u8>().unwrap_or(1);
            }
            Ok(result)
        }) as Box<dyn Fn(&[u8], &mut Unstructured) -> Result<Vec<u8>> + Send + Sync>);
        
        mutations
    }
}