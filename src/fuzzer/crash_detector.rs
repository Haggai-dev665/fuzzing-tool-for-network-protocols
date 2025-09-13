use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use crate::protocols::ProtocolType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashInfo {
    pub id: String,
    pub timestamp: u64,
    pub protocol: ProtocolType,
    pub input_data: Vec<u8>,
    pub input_hash: String,
    pub error_message: Option<String>,
    pub execution_time: Duration,
    pub crash_type: CrashType,
    pub severity: CrashSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CrashType {
    ConnectionRefused,
    ConnectionTimeout,
    ExecutionTimeout,
    NetworkError,
    ProtocolViolation,
    MalformedResponse,
    ServerCrash,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CrashSeverity {
    Low,      // Minor protocol violations, expected errors
    Medium,   // Timeouts, connection issues
    High,     // Server crashes, malformed responses
    Critical, // Security vulnerabilities, buffer overflows
}

pub struct CrashDetector {
    crashes: Vec<CrashInfo>,
    crash_hashes: HashSet<String>,
    protocol_stats: HashMap<ProtocolType, ProtocolCrashStats>,
    last_crash_count: usize,
}

#[derive(Debug, Default)]
struct ProtocolCrashStats {
    total_crashes: usize,
    unique_crashes: usize,
    crash_types: HashMap<CrashType, usize>,
    severity_counts: HashMap<CrashSeverity, usize>,
}

impl CrashDetector {
    pub fn new() -> Self {
        Self {
            crashes: Vec::new(),
            crash_hashes: HashSet::new(),
            protocol_stats: HashMap::new(),
            last_crash_count: 0,
        }
    }
    
    pub fn record_crash(
        &mut self,
        input_data: Vec<u8>,
        error_message: Option<String>,
        execution_time: Duration,
        protocol: ProtocolType,
    ) {
        // Calculate hash of input data to detect unique crashes
        let input_hash = self.calculate_hash(&input_data);
        
        // Skip if we've already seen this exact crash
        if self.crash_hashes.contains(&input_hash) {
            return;
        }
        
        // Classify the crash
        let crash_type = self.classify_crash(&error_message, execution_time);
        let severity = self.determine_severity(&crash_type, &error_message, &input_data);
        
        let crash = CrashInfo {
            id: Uuid::new_v4().to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            protocol,
            input_data,
            input_hash: input_hash.clone(),
            error_message,
            execution_time,
            crash_type: crash_type.clone(),
            severity: severity.clone(),
        };
        
        // Record the crash
        let crash_type_clone = crash_type.clone();
        let severity_clone = severity.clone();
        let input_data_len = crash.input_data.len();
        
        self.crashes.push(crash);
        self.crash_hashes.insert(input_hash);
        
        // Update statistics
        let stats = self.protocol_stats.entry(protocol).or_default();
        stats.total_crashes += 1;
        stats.unique_crashes = self.crash_hashes.len();
        *stats.crash_types.entry(crash_type_clone.clone()).or_insert(0) += 1;
        *stats.severity_counts.entry(severity_clone.clone()).or_insert(0) += 1;
        
        log::warn!(
            "New crash recorded: Protocol={:?}, Type={:?}, Severity={:?}, InputSize={}",
            protocol, crash_type_clone, severity_clone, input_data_len
        );
    }
    
    pub fn has_new_crashes(&self) -> bool {
        self.crashes.len() > self.last_crash_count
    }
    
    pub fn crash_count(&mut self) -> usize {
        self.last_crash_count = self.crashes.len();
        self.crashes.len()
    }
    
    pub fn get_crashes(&self) -> &[CrashInfo] {
        &self.crashes
    }
    
    pub fn get_high_severity_crashes(&self) -> Vec<&CrashInfo> {
        self.crashes
            .iter()
            .filter(|crash| crash.severity >= CrashSeverity::High)
            .collect()
    }
    
    pub fn get_crashes_by_type(&self, crash_type: &CrashType) -> Vec<&CrashInfo> {
        self.crashes
            .iter()
            .filter(|crash| &crash.crash_type == crash_type)
            .collect()
    }
    
    pub async fn save_crashes(&self, output_dir: &PathBuf) -> Result<()> {
        let crashes_dir = output_dir.join("crashes");
        std::fs::create_dir_all(&crashes_dir)?;
        
        // Save individual crash files
        for (idx, crash) in self.crashes.iter().enumerate() {
            // Save input data
            let input_filename = crashes_dir.join(format!("crash_{:04}_input.bin", idx));
            std::fs::write(&input_filename, &crash.input_data)?;
            
            // Save crash metadata
            let metadata_filename = crashes_dir.join(format!("crash_{:04}_metadata.json", idx));
            let metadata_json = serde_json::to_string_pretty(crash)?;
            std::fs::write(&metadata_filename, metadata_json)?;
        }
        
        // Save crash summary
        let summary = self.generate_crash_summary();
        let summary_filename = output_dir.join("crash_summary.json");
        std::fs::write(summary_filename, serde_json::to_string_pretty(&summary)?)?;
        
        // Save detailed report
        let report = self.generate_detailed_report();
        let report_filename = output_dir.join("crash_report.txt");
        std::fs::write(report_filename, report)?;
        
        log::info!("Saved {} crashes to {:?}", self.crashes.len(), crashes_dir);
        Ok(())
    }
    
    fn calculate_hash(&self, data: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }
    
    fn classify_crash(&self, error_message: &Option<String>, execution_time: Duration) -> CrashType {
        if let Some(error) = error_message {
            let error_lower = error.to_lowercase();
            
            if error_lower.contains("connection refused") || error_lower.contains("connection reset") {
                CrashType::ConnectionRefused
            } else if error_lower.contains("connection timeout") || error_lower.contains("connection timed out") {
                CrashType::ConnectionTimeout
            } else if error_lower.contains("network") || error_lower.contains("socket") {
                CrashType::NetworkError
            } else if error_lower.contains("protocol") || error_lower.contains("invalid") {
                CrashType::ProtocolViolation
            } else if error_lower.contains("malformed") || error_lower.contains("parse") {
                CrashType::MalformedResponse
            } else {
                CrashType::Unknown
            }
        } else if execution_time > Duration::from_secs(5) {
            CrashType::ExecutionTimeout
        } else {
            CrashType::ServerCrash
        }
    }
    
    fn determine_severity(
        &self,
        crash_type: &CrashType,
        error_message: &Option<String>,
        input_data: &[u8]
    ) -> CrashSeverity {
        match crash_type {
            CrashType::ServerCrash => {
                // Server crashes are always high severity
                if input_data.len() > 10000 {
                    CrashSeverity::Critical // Large inputs causing crashes might indicate buffer overflows
                } else {
                    CrashSeverity::High
                }
            }
            
            CrashType::MalformedResponse => CrashSeverity::High,
            
            CrashType::ProtocolViolation => {
                if let Some(error) = error_message {
                    if error.to_lowercase().contains("security") || 
                       error.to_lowercase().contains("overflow") ||
                       error.to_lowercase().contains("memory") {
                        CrashSeverity::Critical
                    } else {
                        CrashSeverity::Medium
                    }
                } else {
                    CrashSeverity::Medium
                }
            }
            
            CrashType::ConnectionTimeout | 
            CrashType::ExecutionTimeout |
            CrashType::NetworkError => CrashSeverity::Medium,
            
            CrashType::ConnectionRefused => CrashSeverity::Low,
            
            CrashType::Unknown => {
                // Unknown crashes get medium severity by default
                // but could be upgraded based on input characteristics
                if input_data.len() > 50000 {
                    CrashSeverity::High // Very large inputs
                } else {
                    CrashSeverity::Medium
                }
            }
        }
    }
    
    fn generate_crash_summary(&self) -> serde_json::Value {
        use serde_json::json;
        
        let total_crashes = self.crashes.len();
        let unique_crashes = self.crash_hashes.len();
        
        let mut severity_counts = HashMap::new();
        let mut type_counts = HashMap::new();
        let mut protocol_counts = HashMap::new();
        
        for crash in &self.crashes {
            *severity_counts.entry(&crash.severity).or_insert(0) += 1;
            *type_counts.entry(&crash.crash_type).or_insert(0) += 1;
            *protocol_counts.entry(crash.protocol).or_insert(0) += 1;
        }
        
        json!({
            "summary": {
                "total_crashes": total_crashes,
                "unique_crashes": unique_crashes,
                "protocols_tested": protocol_counts.len(),
            },
            "severity_breakdown": severity_counts,
            "crash_type_breakdown": type_counts,
            "protocol_breakdown": protocol_counts,
            "high_severity_crashes": self.get_high_severity_crashes().len(),
        })
    }
    
    fn generate_detailed_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str("NETWORK PROTOCOL FUZZING - CRASH REPORT\n");
        report.push_str("==========================================\n\n");
        
        report.push_str(&format!("Total Crashes Found: {}\n", self.crashes.len()));
        report.push_str(&format!("Unique Crashes: {}\n\n", self.crash_hashes.len()));
        
        // Severity breakdown
        report.push_str("SEVERITY BREAKDOWN:\n");
        report.push_str("-------------------\n");
        let mut severity_counts = HashMap::new();
        for crash in &self.crashes {
            *severity_counts.entry(&crash.severity).or_insert(0) += 1;
        }
        
        for (severity, count) in &severity_counts {
            report.push_str(&format!("{:?}: {}\n", severity, count));
        }
        report.push('\n');
        
        // Crash type breakdown
        report.push_str("CRASH TYPE BREAKDOWN:\n");
        report.push_str("---------------------\n");
        let mut type_counts = HashMap::new();
        for crash in &self.crashes {
            *type_counts.entry(&crash.crash_type).or_insert(0) += 1;
        }
        
        for (crash_type, count) in &type_counts {
            report.push_str(&format!("{:?}: {}\n", crash_type, count));
        }
        report.push('\n');
        
        // High severity crashes details
        let high_severity = self.get_high_severity_crashes();
        if !high_severity.is_empty() {
            report.push_str("HIGH SEVERITY CRASHES:\n");
            report.push_str("======================\n");
            
            for (idx, crash) in high_severity.iter().enumerate() {
                report.push_str(&format!("#{}: {} ({:?})\n", idx + 1, crash.id, crash.severity));
                report.push_str(&format!("  Protocol: {:?}\n", crash.protocol));
                report.push_str(&format!("  Type: {:?}\n", crash.crash_type));
                report.push_str(&format!("  Input Size: {} bytes\n", crash.input_data.len()));
                report.push_str(&format!("  Execution Time: {:?}\n", crash.execution_time));
                
                if let Some(error) = &crash.error_message {
                    report.push_str(&format!("  Error: {}\n", error));
                }
                
                report.push('\n');
            }
        }
        
        // Protocol statistics
        report.push_str("PROTOCOL STATISTICS:\n");
        report.push_str("====================\n");
        for (protocol, stats) in &self.protocol_stats {
            report.push_str(&format!("{:?}:\n", protocol));
            report.push_str(&format!("  Total Crashes: {}\n", stats.total_crashes));
            report.push_str(&format!("  Unique Crashes: {}\n", stats.unique_crashes));
            
            if !stats.crash_types.is_empty() {
                report.push_str("  Crash Types:\n");
                for (crash_type, count) in &stats.crash_types {
                    report.push_str(&format!("    {:?}: {}\n", crash_type, count));
                }
            }
            
            report.push('\n');
        }
        
        report
    }
}

impl Default for CrashDetector {
    fn default() -> Self {
        Self::new()
    }
}