use anyhow::Result;
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub mod network;
pub mod reporting;
pub mod logging;

pub use network::*;
pub use reporting::*;
pub use logging::*;

/// Generate a unique session ID for the fuzzing session
pub fn generate_session_id() -> String {
    Uuid::new_v4().to_string()
}

/// Get current timestamp in seconds since epoch
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Create a directory with timestamp for organizing results
pub fn create_timestamped_dir(base_path: &str, prefix: &str) -> Result<PathBuf> {
    let timestamp = current_timestamp();
    let dir_name = format!("{}_{}", prefix, timestamp);
    let full_path = PathBuf::from(base_path).join(dir_name);
    
    fs::create_dir_all(&full_path)?;
    Ok(full_path)
}

/// Sanitize a string to be safe for use as a filename
pub fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect()
}

/// Calculate file hash for deduplication
pub fn calculate_file_hash(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Format byte size in human-readable format
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: f64 = 1024.0;
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= THRESHOLD && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// Format duration in human-readable format
pub fn format_duration(seconds: f64) -> String {
    if seconds < 1.0 {
        format!("{:.0} ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.2} s", seconds)
    } else if seconds < 3600.0 {
        let minutes = seconds / 60.0;
        format!("{:.1} min", minutes)
    } else {
        let hours = seconds / 3600.0;
        format!("{:.1} h", hours)
    }
}

/// Extract interesting strings from binary data
pub fn extract_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    
    for &byte in data {
        if byte.is_ascii_graphic() || byte == b' ' {
            current_string.push(byte);
        } else {
            if current_string.len() >= min_length {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    strings.push(s);
                }
            }
            current_string.clear();
        }
    }
    
    // Handle string at end of data
    if current_string.len() >= min_length {
        if let Ok(s) = String::from_utf8(current_string) {
            strings.push(s);
        }
    }
    
    strings
}

/// Hexdump utility for debugging
pub fn hexdump(data: &[u8], max_bytes: Option<usize>) -> String {
    let limit = max_bytes.unwrap_or(data.len()).min(data.len());
    let mut result = String::new();
    
    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        // Offset
        result.push_str(&format!("{:08x}  ", i * 16));
        
        // Hex bytes
        for (j, &byte) in chunk.iter().enumerate() {
            if j == 8 {
                result.push(' '); // Extra space in the middle
            }
            result.push_str(&format!("{:02x} ", byte));
        }
        
        // Pad if necessary
        for j in chunk.len()..16 {
            if j == 8 {
                result.push(' ');
            }
            result.push_str("   ");
        }
        
        result.push_str(" |");
        
        // ASCII representation
        for &byte in chunk {
            if byte.is_ascii_graphic() {
                result.push(byte as char);
            } else {
                result.push('.');
            }
        }
        
        result.push_str("|\n");
    }
    
    if limit < data.len() {
        result.push_str(&format!("... ({} more bytes)\n", data.len() - limit));
    }
    
    result
}

/// Statistics collection helper
#[derive(Debug, Default, Clone)]
pub struct Statistics {
    pub count: u64,
    pub sum: f64,
    pub sum_squared: f64,
    pub min: f64,
    pub max: f64,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            count: 0,
            sum: 0.0,
            sum_squared: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }
    
    pub fn add(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        self.sum_squared += value * value;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }
    
    pub fn mean(&self) -> f64 {
        if self.count > 0 {
            self.sum / self.count as f64
        } else {
            0.0
        }
    }
    
    pub fn variance(&self) -> f64 {
        if self.count > 1 {
            let mean = self.mean();
            (self.sum_squared - self.count as f64 * mean * mean) / (self.count - 1) as f64
        } else {
            0.0
        }
    }
    
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }
    
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Simple rate limiter for network operations
pub struct RateLimiter {
    tokens: f64,
    capacity: f64,
    refill_rate: f64, // tokens per second
    last_refill: std::time::Instant,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: std::time::Instant::now(),
        }
    }
    
    pub fn try_acquire(&mut self, tokens: f64) -> bool {
        self.refill();
        
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }
    
    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        
        let new_tokens = elapsed * self.refill_rate;
        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_refill = now;
    }
}

/// Configuration file helpers
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingConfig {
    pub target: TargetConfig,
    pub fuzzing: FuzzingSettings,
    pub coverage: CoverageConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingSettings {
    pub iterations: u64,
    pub workers: usize,
    pub mutation_rate: f64,
    pub seed_corpus: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageConfig {
    pub enabled: bool,
    pub output_dir: PathBuf,
    pub collection_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub results_dir: PathBuf,
    pub save_interesting: bool,
    pub save_crashes: bool,
    pub verbose: bool,
}

impl Default for FuzzingConfig {
    fn default() -> Self {
        Self {
            target: TargetConfig {
                host: "127.0.0.1".to_string(),
                port: 53,
                protocol: "dns".to_string(),
                timeout_ms: 5000,
            },
            fuzzing: FuzzingSettings {
                iterations: 10000,
                workers: 4,
                mutation_rate: 0.1,
                seed_corpus: None,
            },
            coverage: CoverageConfig {
                enabled: true,
                output_dir: PathBuf::from("./coverage"),
                collection_interval: 100,
            },
            output: OutputConfig {
                results_dir: PathBuf::from("./results"),
                save_interesting: true,
                save_crashes: true,
                verbose: false,
            },
        }
    }
}

impl FuzzingConfig {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: FuzzingConfig = toml::from_str(&content)?;
        Ok(config)
    }
    
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
    }
    
    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0.5), "500 ms");
        assert_eq!(format_duration(1.5), "1.50 s");
        assert_eq!(format_duration(65.0), "1.1 min");
        assert_eq!(format_duration(3700.0), "1.0 h");
    }
    
    #[test]
    fn test_statistics() {
        let mut stats = Statistics::new();
        stats.add(1.0);
        stats.add(2.0);
        stats.add(3.0);
        
        assert_eq!(stats.count, 3);
        assert_eq!(stats.mean(), 2.0);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 3.0);
    }
    
    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(10.0, 5.0);
        
        // Should be able to acquire tokens initially
        assert!(limiter.try_acquire(5.0));
        assert!(limiter.try_acquire(5.0));
        
        // Should be out of tokens now
        assert!(!limiter.try_acquire(1.0));
    }
}