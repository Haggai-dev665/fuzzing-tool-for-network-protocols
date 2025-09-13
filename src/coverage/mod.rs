use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::protocols::ProtocolType;

pub mod edge_coverage;
pub mod feature_coverage;

pub use edge_coverage::EdgeCoverageCollector;
pub use feature_coverage::FeatureCoverageCollector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub timestamp: u64,
    pub protocol: ProtocolType,
    pub total_executions: u64,
    pub unique_paths: usize,
    pub edge_coverage: EdgeCoverageData,
    pub feature_coverage: FeatureCoverageData,
    pub coverage_metrics: CoverageMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeCoverageData {
    pub total_edges: usize,
    pub covered_edges: usize,
    pub coverage_percentage: f64,
    pub new_edges_per_execution: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureCoverageData {
    pub total_features: usize,
    pub covered_features: usize,
    pub feature_frequency: HashMap<String, u64>,
    pub rare_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMetrics {
    pub path_diversity: f64,
    pub feature_entropy: f64,
    pub discovery_rate: f64,
    pub coverage_growth_rate: f64,
}

pub trait CoverageCollector: Send + Sync {
    /// Record execution and update coverage information
    fn record_execution(&mut self, input_data: &[u8], execution_result: &ExecutionResult);
    
    /// Get current coverage statistics
    fn get_coverage_stats(&self) -> CoverageStats;
    
    /// Check if new coverage was discovered
    fn has_new_coverage(&self) -> bool;
    
    /// Export coverage data for analysis
    fn export_coverage_data(&self) -> Result<Vec<u8>>;
    
    /// Reset coverage counters
    fn reset(&mut self);
}

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub success: bool,
    pub response_data: Option<Vec<u8>>,
    pub execution_time_ms: u64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageStats {
    pub total_executions: u64,
    pub unique_paths: usize,
    pub coverage_percentage: f64,
    pub new_coverage_found: bool,
}

pub struct CompositeCoverageCollector {
    edge_collector: EdgeCoverageCollector,
    feature_collector: FeatureCoverageCollector,
    protocol_type: ProtocolType,
    execution_count: u64,
    coverage_history: Vec<CoverageSnapshot>,
}

#[derive(Debug, Clone)]
struct CoverageSnapshot {
    timestamp: u64,
    execution_count: u64,
    edge_coverage: f64,
    feature_coverage: f64,
}

impl CompositeCoverageCollector {
    pub fn new(protocol_type: ProtocolType) -> Self {
        Self {
            edge_collector: EdgeCoverageCollector::new(),
            feature_collector: FeatureCoverageCollector::new(protocol_type),
            protocol_type,
            execution_count: 0,
            coverage_history: Vec::new(),
        }
    }
    
    pub fn generate_report(&self) -> CoverageReport {
        let edge_stats = self.edge_collector.get_coverage_stats();
        let feature_stats = self.feature_collector.get_coverage_stats();
        
        let edge_coverage = EdgeCoverageData {
            total_edges: self.edge_collector.get_total_edges(),
            covered_edges: self.edge_collector.get_covered_edges(),
            coverage_percentage: edge_stats.coverage_percentage,
            new_edges_per_execution: self.calculate_edge_discovery_rate(),
        };
        
        let feature_coverage = FeatureCoverageData {
            total_features: self.feature_collector.get_total_features(),
            covered_features: self.feature_collector.get_covered_features(),
            feature_frequency: self.feature_collector.get_feature_frequency(),
            rare_features: self.feature_collector.get_rare_features(),
        };
        
        let coverage_metrics = self.calculate_metrics();
        
        CoverageReport {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            protocol: self.protocol_type,
            total_executions: self.execution_count,
            unique_paths: edge_stats.unique_paths,
            edge_coverage,
            feature_coverage,
            coverage_metrics,
        }
    }
    
    pub async fn save_report(&self, output_dir: &PathBuf) -> Result<()> {
        std::fs::create_dir_all(output_dir)?;
        
        let report = self.generate_report();
        
        // Save JSON report
        let json_report = serde_json::to_string_pretty(&report)?;
        let json_file = output_dir.join("coverage_report.json");
        std::fs::write(json_file, json_report)?;
        
        // Save human-readable report
        let text_report = self.generate_text_report(&report);
        let text_file = output_dir.join("coverage_report.txt");
        std::fs::write(text_file, text_report)?;
        
        // Save detailed coverage data
        let edge_data = self.edge_collector.export_coverage_data()?;
        let edge_file = output_dir.join("edge_coverage.bin");
        std::fs::write(edge_file, edge_data)?;
        
        let feature_data = self.feature_collector.export_coverage_data()?;
        let feature_file = output_dir.join("feature_coverage.bin");
        std::fs::write(feature_file, feature_data)?;
        
        log::info!("Coverage report saved to {:?}", output_dir);
        Ok(())
    }
    
    fn calculate_edge_discovery_rate(&self) -> Vec<f64> {
        // Calculate new edges discovered per execution window
        let window_size = 100;
        let mut rates = Vec::new();
        
        for window in self.coverage_history.windows(window_size) {
            if window.len() >= 2 {
                let start_coverage = window.first().unwrap().edge_coverage;
                let end_coverage = window.last().unwrap().edge_coverage;
                let rate = (end_coverage - start_coverage) / window_size as f64;
                rates.push(rate.max(0.0));
            }
        }
        
        rates
    }
    
    fn calculate_metrics(&self) -> CoverageMetrics {
        let path_diversity = self.calculate_path_diversity();
        let feature_entropy = self.feature_collector.calculate_entropy();
        let discovery_rate = self.calculate_discovery_rate();
        let coverage_growth_rate = self.calculate_coverage_growth_rate();
        
        CoverageMetrics {
            path_diversity,
            feature_entropy,
            discovery_rate,
            coverage_growth_rate,
        }
    }
    
    fn calculate_path_diversity(&self) -> f64 {
        // Shannon entropy of path frequencies
        let path_counts = self.edge_collector.get_path_frequencies();
        let total_paths = path_counts.values().sum::<u64>() as f64;
        
        if total_paths == 0.0 {
            return 0.0;
        }
        
        let mut entropy = 0.0;
        for &count in path_counts.values() {
            let probability = count as f64 / total_paths;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    fn calculate_discovery_rate(&self) -> f64 {
        if self.coverage_history.len() < 2 {
            return 0.0;
        }
        
        let recent_snapshots = &self.coverage_history[self.coverage_history.len().saturating_sub(100)..];
        
        if recent_snapshots.len() < 2 {
            return 0.0;
        }
        
        let start = recent_snapshots.first().unwrap();
        let end = recent_snapshots.last().unwrap();
        
        let coverage_increase = end.edge_coverage - start.edge_coverage;
        let execution_delta = end.execution_count - start.execution_count;
        
        if execution_delta > 0 {
            coverage_increase / execution_delta as f64
        } else {
            0.0
        }
    }
    
    fn calculate_coverage_growth_rate(&self) -> f64 {
        if self.coverage_history.len() < 10 {
            return 0.0;
        }
        
        // Calculate exponential moving average of coverage growth
        let mut ema = 0.0;
        let alpha = 0.1; // Smoothing factor
        
        for window in self.coverage_history.windows(2) {
            let growth = window[1].edge_coverage - window[0].edge_coverage;
            ema = alpha * growth + (1.0 - alpha) * ema;
        }
        
        ema
    }
    
    fn generate_text_report(&self, report: &CoverageReport) -> String {
        let mut text = String::new();
        
        text.push_str("NETWORK PROTOCOL FUZZING - COVERAGE REPORT\n");
        text.push_str("==========================================\n\n");
        
        text.push_str(&format!("Protocol: {:?}\n", report.protocol));
        text.push_str(&format!("Total Executions: {}\n", report.total_executions));
        text.push_str(&format!("Unique Paths: {}\n\n", report.unique_paths));
        
        text.push_str("EDGE COVERAGE:\n");
        text.push_str("--------------\n");
        text.push_str(&format!("Total Edges: {}\n", report.edge_coverage.total_edges));
        text.push_str(&format!("Covered Edges: {}\n", report.edge_coverage.covered_edges));
        text.push_str(&format!("Coverage Percentage: {:.2}%\n\n", report.edge_coverage.coverage_percentage));
        
        text.push_str("FEATURE COVERAGE:\n");
        text.push_str("-----------------\n");
        text.push_str(&format!("Total Features: {}\n", report.feature_coverage.total_features));
        text.push_str(&format!("Covered Features: {}\n", report.feature_coverage.covered_features));
        
        if !report.feature_coverage.rare_features.is_empty() {
            text.push_str("\nRare Features Discovered:\n");
            for feature in &report.feature_coverage.rare_features {
                text.push_str(&format!("  - {}\n", feature));
            }
        }
        
        text.push('\n');
        text.push_str("COVERAGE METRICS:\n");
        text.push_str("-----------------\n");
        text.push_str(&format!("Path Diversity: {:.4}\n", report.coverage_metrics.path_diversity));
        text.push_str(&format!("Feature Entropy: {:.4}\n", report.coverage_metrics.feature_entropy));
        text.push_str(&format!("Discovery Rate: {:.6}\n", report.coverage_metrics.discovery_rate));
        text.push_str(&format!("Coverage Growth Rate: {:.6}\n", report.coverage_metrics.coverage_growth_rate));
        
        text
    }
    
    fn take_snapshot(&mut self) {
        let edge_stats = self.edge_collector.get_coverage_stats();
        let feature_stats = self.feature_collector.get_coverage_stats();
        
        let snapshot = CoverageSnapshot {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            execution_count: self.execution_count,
            edge_coverage: edge_stats.coverage_percentage,
            feature_coverage: feature_stats.coverage_percentage,
        };
        
        self.coverage_history.push(snapshot);
        
        // Keep only recent history to prevent unbounded growth
        if self.coverage_history.len() > 10000 {
            self.coverage_history.drain(0..1000);
        }
    }
}

impl CoverageCollector for CompositeCoverageCollector {
    fn record_execution(&mut self, input_data: &[u8], execution_result: &ExecutionResult) {
        self.execution_count += 1;
        
        // Record coverage in both collectors
        self.edge_collector.record_execution(input_data, execution_result);
        self.feature_collector.record_execution(input_data, execution_result);
        
        // Take periodic snapshots for metrics calculation
        if self.execution_count % 50 == 0 {
            self.take_snapshot();
        }
    }
    
    fn get_coverage_stats(&self) -> CoverageStats {
        let edge_stats = self.edge_collector.get_coverage_stats();
        let feature_stats = self.feature_collector.get_coverage_stats();
        
        CoverageStats {
            total_executions: self.execution_count,
            unique_paths: edge_stats.unique_paths,
            coverage_percentage: (edge_stats.coverage_percentage + feature_stats.coverage_percentage) / 2.0,
            new_coverage_found: edge_stats.new_coverage_found || feature_stats.new_coverage_found,
        }
    }
    
    fn has_new_coverage(&self) -> bool {
        self.edge_collector.has_new_coverage() || self.feature_collector.has_new_coverage()
    }
    
    fn export_coverage_data(&self) -> Result<Vec<u8>> {
        let report = self.generate_report();
        let data = serde_json::to_vec(&report)?;
        Ok(data)
    }
    
    fn reset(&mut self) {
        self.edge_collector.reset();
        self.feature_collector.reset();
        self.execution_count = 0;
        self.coverage_history.clear();
    }
}