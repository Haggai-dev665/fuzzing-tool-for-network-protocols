use anyhow::Result;
use arbitrary::Unstructured;
use libafl::{
    bolts::{rands::Rand, Named},
    corpus::Testcase,
    inputs::{BytesInput, HasBytesVec, Input},
    mutators::{MutationResult, Mutator},
    state::HasRand,
    Error as LibAFLError,
};
use std::sync::Arc;

use crate::protocols::{ProtocolFuzzer, ProtocolType};

pub struct ProtocolMutator {
    protocol_fuzzer: Arc<dyn ProtocolFuzzer>,
    mutation_strategies: Vec<MutationStrategy>,
    name: String,
}

#[derive(Clone)]
enum MutationStrategy {
    ProtocolSpecific,
    GrammarBased,
    FieldMutation,
    StructuralMutation,
    HybridMutation,
}

impl ProtocolMutator {
    pub fn new(protocol_type: ProtocolType, protocol_fuzzer: Arc<dyn ProtocolFuzzer>) -> Self {
        let name = format!("{:?}ProtocolMutator", protocol_type);
        
        let mutation_strategies = vec![
            MutationStrategy::ProtocolSpecific,
            MutationStrategy::GrammarBased,
            MutationStrategy::FieldMutation,
            MutationStrategy::StructuralMutation,
            MutationStrategy::HybridMutation,
        ];
        
        Self {
            protocol_fuzzer,
            mutation_strategies,
            name,
        }
    }
    
    fn apply_protocol_specific_mutation<S>(&self, input: &mut BytesInput, state: &mut S) -> Result<MutationResult>
    where
        S: HasRand,
    {
        let current_data = input.bytes().to_vec();
        
        // Use the protocol fuzzer's mutation capabilities
        let mut seed_data = vec![0u8; 1024];
        let rand_val = state.rand_mut().next() as usize;
        for i in 0..seed_data.len() {
            seed_data[i] = ((rand_val + i) % 256) as u8;
        }
        
        let mut unstructured = Unstructured::new(&seed_data);
        
        // Apply protocol-specific mutation
        match self.protocol_fuzzer.mutate_packet(&current_data, &mut unstructured) {
            Ok(mutated_data) => {
                if mutated_data != current_data {
                    input.bytes_mut().clear();
                    input.bytes_mut().extend_from_slice(&mutated_data);
                    Ok(MutationResult::Mutated)
                } else {
                    Ok(MutationResult::Skipped)
                }
            }
            Err(_) => Ok(MutationResult::Skipped),
        }
    }
    
    fn apply_grammar_based_mutation<S>(&self, input: &mut BytesInput, state: &mut S) -> Result<MutationResult>
    where
        S: HasRand,
    {
        let current_data = input.bytes().to_vec();
        let grammar_mutations = self.protocol_fuzzer.get_grammar_mutations();
        
        if grammar_mutations.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        
        // Select a random grammar mutation
        let mutation_idx = state.rand_mut().next() as usize % grammar_mutations.len();
        let mutation_fn = &grammar_mutations[mutation_idx];
        
        // Prepare Unstructured data for the mutation
        let mut seed_data = vec![0u8; 512];
        let rand_val = state.rand_mut().next() as usize;
        for i in 0..seed_data.len() {
            seed_data[i] = ((rand_val + i) % 256) as u8;
        }
        
        let mut unstructured = Unstructured::new(&seed_data);
        
        // Apply the grammar-based mutation
        match mutation_fn(&current_data, &mut unstructured) {
            Ok(mutated_data) => {
                if mutated_data != current_data {
                    input.bytes_mut().clear();
                    input.bytes_mut().extend_from_slice(&mutated_data);
                    Ok(MutationResult::Mutated)
                } else {
                    Ok(MutationResult::Skipped)
                }
            }
            Err(_) => Ok(MutationResult::Skipped),
        }
    }
    
    fn apply_field_mutation<S>(&self, input: &mut BytesInput, state: &mut S) -> Result<MutationResult>
    where
        S: HasRand,
    {
        let data = input.bytes_mut();
        
        if data.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        
        // Field-level mutations: modify specific protocol fields
        let field_mutations = vec![
            // Length field corruption
            |data: &mut [u8], rand: &mut dyn Rand| {
                if data.len() >= 2 {
                    let pos = rand.next() as usize % (data.len() - 1);
                    let new_len = rand.next() as u16;
                    let bytes = new_len.to_be_bytes();
                    data[pos] = bytes[0];
                    data[pos + 1] = bytes[1];
                }
            },
            // Flag field manipulation
            |data: &mut [u8], rand: &mut dyn Rand| {
                if !data.is_empty() {
                    let pos = rand.next() as usize % data.len();
                    data[pos] ^= 1 << (rand.next() % 8) as u8;
                }
            },
            // Identifier field corruption
            |data: &mut [u8], rand: &mut dyn Rand| {
                if data.len() >= 4 {
                    let pos = rand.next() as usize % (data.len() - 3);
                    let new_id = rand.next() as u32;
                    let bytes = new_id.to_be_bytes();
                    for (i, byte) in bytes.iter().enumerate() {
                        data[pos + i] = *byte;
                    }
                }
            },
        ];
        
        // Select and apply a random field mutation
        let mutation_idx = state.rand_mut().next() as usize % field_mutations.len();
        field_mutations[mutation_idx](data, state.rand_mut());
        
        Ok(MutationResult::Mutated)
    }
    
    fn apply_structural_mutation<S>(&self, input: &mut BytesInput, state: &mut S) -> Result<MutationResult>
    where
        S: HasRand,
    {
        let data = input.bytes_mut();
        
        if data.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        
        let mutation_type = state.rand_mut().next() % 4;
        
        match mutation_type {
            0 => {
                // Insert random bytes
                let insert_pos = state.rand_mut().next() as usize % (data.len() + 1);
                let insert_count = (state.rand_mut().next() % 16) as usize + 1;
                let mut new_bytes = Vec::with_capacity(insert_count);
                
                for _ in 0..insert_count {
                    new_bytes.push(state.rand_mut().next() as u8);
                }
                
                data.splice(insert_pos..insert_pos, new_bytes);
            }
            1 => {
                // Delete bytes
                if data.len() > 1 {
                    let delete_start = state.rand_mut().next() as usize % data.len();
                    let max_delete = (data.len() - delete_start).min(16);
                    let delete_count = (state.rand_mut().next() as usize % max_delete) + 1;
                    let delete_end = (delete_start + delete_count).min(data.len());
                    
                    data.drain(delete_start..delete_end);
                }
            }
            2 => {
                // Duplicate a section
                if data.len() > 4 {
                    let src_start = state.rand_mut().next() as usize % (data.len() - 4);
                    let src_len = ((state.rand_mut().next() % 32) as usize + 1).min(data.len() - src_start);
                    let src_end = src_start + src_len;
                    
                    let section = data[src_start..src_end].to_vec();
                    let insert_pos = state.rand_mut().next() as usize % (data.len() + 1);
                    
                    data.splice(insert_pos..insert_pos, section);
                }
            }
            3 => {
                // Swap two sections
                if data.len() > 8 {
                    let section1_start = state.rand_mut().next() as usize % (data.len() / 2);
                    let section1_len = ((state.rand_mut().next() % 16) as usize + 1).min(data.len() / 4);
                    let section1_end = (section1_start + section1_len).min(data.len());
                    
                    let section2_start = (data.len() / 2) + (state.rand_mut().next() as usize % (data.len() / 2));
                    let section2_len = section1_len.min(data.len() - section2_start);
                    let section2_end = (section2_start + section2_len).min(data.len());
                    
                    if section1_end <= section2_start {
                        let section1 = data[section1_start..section1_end].to_vec();
                        let section2 = data[section2_start..section2_end].to_vec();
                        
                        // Replace sections
                        for (i, &byte) in section2.iter().enumerate() {
                            if section1_start + i < data.len() {
                                data[section1_start + i] = byte;
                            }
                        }
                        
                        for (i, &byte) in section1.iter().enumerate() {
                            if section2_start + i < data.len() {
                                data[section2_start + i] = byte;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        
        Ok(MutationResult::Mutated)
    }
    
    fn apply_hybrid_mutation<S>(&self, input: &mut BytesInput, state: &mut S) -> Result<MutationResult>
    where
        S: HasRand,
    {
        // Apply multiple mutations in sequence
        let mutation_count = (state.rand_mut().next() % 3) as usize + 1;
        let mut mutated = false;
        
        for _ in 0..mutation_count {
            let strategy_idx = state.rand_mut().next() as usize % (self.mutation_strategies.len() - 1); // Exclude hybrid to avoid recursion
            
            let result = match &self.mutation_strategies[strategy_idx] {
                MutationStrategy::ProtocolSpecific => self.apply_protocol_specific_mutation(input, state)?,
                MutationStrategy::GrammarBased => self.apply_grammar_based_mutation(input, state)?,
                MutationStrategy::FieldMutation => self.apply_field_mutation(input, state)?,
                MutationStrategy::StructuralMutation => self.apply_structural_mutation(input, state)?,
                MutationStrategy::HybridMutation => MutationResult::Skipped, // Skip to avoid recursion
            };
            
            if result == MutationResult::Mutated {
                mutated = true;
            }
        }
        
        Ok(if mutated { MutationResult::Mutated } else { MutationResult::Skipped })
    }
}

impl<S> Mutator<BytesInput, S> for ProtocolMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput, _stage_idx: i32) -> Result<MutationResult, LibAFLError> {
        // Select a random mutation strategy
        let strategy_idx = state.rand_mut().next() as usize % self.mutation_strategies.len();
        let strategy = &self.mutation_strategies[strategy_idx];
        
        let result = match strategy {
            MutationStrategy::ProtocolSpecific => self.apply_protocol_specific_mutation(input, state),
            MutationStrategy::GrammarBased => self.apply_grammar_based_mutation(input, state),
            MutationStrategy::FieldMutation => self.apply_field_mutation(input, state),
            MutationStrategy::StructuralMutation => self.apply_structural_mutation(input, state),
            MutationStrategy::HybridMutation => self.apply_hybrid_mutation(input, state),
        };
        
        result.map_err(|e| LibAFLError::unknown(format!("Mutation failed: {}", e)))
    }
}

impl Named for ProtocolMutator {
    fn name(&self) -> &str {
        &self.name
    }
}

/// Factory function to create protocol-specific mutators
pub fn create_protocol_mutators(protocol_type: ProtocolType) -> Vec<Box<dyn Mutator<BytesInput, impl HasRand> + Send + Sync>> {
    let protocol_fuzzer = Arc::new(crate::protocols::create_protocol_fuzzer(protocol_type));
    
    // Create multiple instances with different mutation strategies
    vec![
        Box::new(ProtocolMutator::new(protocol_type, protocol_fuzzer.clone())),
        // Additional specialized mutators could be added here
    ]
}

/// Bit flip mutator optimized for protocol fuzzing
pub struct ProtocolBitFlipMutator {
    name: String,
}

impl ProtocolBitFlipMutator {
    pub fn new() -> Self {
        Self {
            name: "ProtocolBitFlip".to_string(),
        }
    }
}

impl<S> Mutator<BytesInput, S> for ProtocolBitFlipMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput, _stage_idx: i32) -> Result<MutationResult, LibAFLError> {
        let data = input.bytes_mut();
        
        if data.is_empty() {
            return Ok(MutationResult::Skipped);
        }
        
        // Focus bit flips on protocol-critical areas
        let flip_locations = vec![
            // Header area (first 16 bytes)
            0..16.min(data.len()),
            // Length fields (every 2 bytes)
            (0..data.len()).step_by(2).collect::<Vec<_>>(),
            // Random locations
            vec![state.rand_mut().next() as usize % data.len()],
        ];
        
        let location_set_idx = state.rand_mut().next() as usize % flip_locations.len();
        let locations = &flip_locations[location_set_idx];
        
        for &pos in locations.iter().take(8) { // Limit to 8 flips
            if pos < data.len() {
                let bit_pos = state.rand_mut().next() % 8;
                data[pos] ^= 1 << bit_pos;
            }
        }
        
        Ok(MutationResult::Mutated)
    }
}

impl Named for ProtocolBitFlipMutator {
    fn name(&self) -> &str {
        &self.name
    }
}