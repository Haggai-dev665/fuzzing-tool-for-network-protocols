use anyhow::Result;
use arbitrary::Unstructured;
use log::{debug, error, info, warn};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, net::UdpSocket, time::timeout};

use crate::protocols::{create_protocol_fuzzer, ProtocolFuzzer, ProtocolType};
use crate::coverage::{CompositeCoverageCollector, CoverageCollector, ExecutionResult};

mod crash_detector;
pub use crash_detector::CrashDetector;

pub struct FuzzingEngine {
    protocol_type: ProtocolType,
    target_host: String,
    target_port: u16,
    worker_count: usize,
    coverage_enabled: bool,
    coverage_dir: Option<PathBuf>,
    verbose: bool,
    protocol_fuzzer: Box<dyn ProtocolFuzzer>,
    crash_detector: Arc<Mutex<CrashDetector>>,
    coverage_collector: CompositeCoverageCollector,
}

impl FuzzingEngine {
    pub fn new(protocol_type: ProtocolType, target_host: String, target_port: u16, worker_count: usize) -> Self {
        let protocol_fuzzer = create_protocol_fuzzer(protocol_type);
        let crash_detector = Arc::new(Mutex::new(CrashDetector::new()));
        let coverage_collector = CompositeCoverageCollector::new(protocol_type);
        
        Self {
            protocol_type,
            target_host,
            target_port,
            worker_count,
            coverage_enabled: false,
            coverage_dir: None,
            verbose: false,
            protocol_fuzzer,
            crash_detector,
            coverage_collector,
        }
    }
    
    pub fn enable_coverage(&mut self, coverage_dir: PathBuf) -> Result<()> {
        std::fs::create_dir_all(&coverage_dir)?;
        self.coverage_dir = Some(coverage_dir);
        self.coverage_enabled = true;
        Ok(())
    }
    
    pub fn enable_verbose_logging(&mut self) {
        self.verbose = true;
    }
    
    pub async fn run_fuzzing_campaign(&mut self, iterations: u64) -> Result<()> {
        info!("Starting fuzzing campaign with {} iterations", iterations);
        info!("Target: {}:{} ({})", self.target_host, self.target_port, 
              if self.protocol_type.is_tcp() { "TCP" } else { "UDP" });
        
        // Test target connectivity first
        self.test_target_connectivity().await?;
        
        // Seed the initial test cases
        let mut test_cases = self.generate_initial_test_cases().await?;
        
        let start_time = Instant::now();
        let mut last_stats_time = start_time;
        let mut total_executions = 0u64;
        let mut crashes_found = 0u64;
        
        info!("Fuzzing campaign started!");
        
        // Main fuzzing loop - simplified without LibAFL for now
        for iteration in 0..iterations {
            // Select a test case to mutate
            let base_case_idx = (iteration as usize) % test_cases.len();
            let base_case = test_cases[base_case_idx].clone();
            
            // Mutate the test case
            let mutated_case = self.mutate_test_case(&base_case).await?;
            
            // Execute the test case
            let execution_result = self.execute_test_case(&mutated_case).await?;
            
            // Record execution for coverage
            self.coverage_collector.record_execution(&mutated_case, &execution_result);
            
            total_executions += 1;
            
            // Check for crashes
            if !execution_result.success {
                if let Ok(mut detector) = self.crash_detector.lock() {
                    detector.record_crash(
                        mutated_case.clone(),
                        execution_result.error_message.clone(),
                        Duration::from_millis(execution_result.execution_time_ms),
                        self.protocol_type,
                    );
                    crashes_found = detector.crash_count() as u64;
                }
            }
            
            // Add interesting test cases to corpus
            if self.is_interesting(&execution_result) {
                test_cases.push(mutated_case);
                
                // Keep corpus size manageable
                if test_cases.len() > 1000 {
                    test_cases.remove(0);
                }
            }
            
            // Print stats every 1000 iterations or 30 seconds
            if iteration % 1000 == 0 || last_stats_time.elapsed() > Duration::from_secs(30) {
                let elapsed = start_time.elapsed();
                let exec_per_sec = total_executions as f64 / elapsed.as_secs_f64();
                let coverage_stats = self.coverage_collector.get_coverage_stats();
                
                info!(
                    "Stats - Iter: {}/{}, Execs: {}, Crashes: {}, Exec/sec: {:.2}, Coverage: {:.2}%, Corpus: {}",
                    iteration + 1,
                    iterations,
                    total_executions,
                    crashes_found,
                    exec_per_sec,
                    coverage_stats.coverage_percentage,
                    test_cases.len()
                );
                
                last_stats_time = Instant::now();
            }
            
            // Yield control to allow other async tasks
            if iteration % 100 == 0 {
                tokio::task::yield_now().await;
            }
        }
        
        let total_time = start_time.elapsed();
        let final_exec_per_sec = total_executions as f64 / total_time.as_secs_f64();
        
        info!("Fuzzing campaign completed!");
        info!("Final stats:");
        info!("  Total executions: {}", total_executions);
        info!("  Total crashes found: {}", crashes_found);
        info!("  Average exec/sec: {:.2}", final_exec_per_sec);
        info!("  Final corpus size: {}", test_cases.len());
        info!("  Total time: {:.2}s", total_time.as_secs_f64());
        
        // Save final results
        self.save_results(total_executions, crashes_found).await?;
        
        Ok(())
    }
    
    async fn test_target_connectivity(&self) -> Result<()> {
        info!("Testing target connectivity...");
        
        if self.protocol_type.is_tcp() {
            match timeout(
                Duration::from_secs(5),
                TcpStream::connect(format!("{}:{}", self.target_host, self.target_port))
            ).await {
                Ok(Ok(_)) => info!("TCP connection to target successful"),
                Ok(Err(e)) => warn!("TCP connection failed: {}", e),
                Err(_) => warn!("TCP connection timed out"),
            }
        } else {
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(socket) => {
                    let test_data = b"test";
                    match timeout(
                        Duration::from_secs(5),
                        socket.send_to(test_data, format!("{}:{}", self.target_host, self.target_port))
                    ).await {
                        Ok(Ok(_)) => info!("UDP test packet sent successfully"),
                        Ok(Err(e)) => warn!("UDP test packet failed: {}", e),
                        Err(_) => warn!("UDP test packet timed out"),
                    }
                }
                Err(e) => warn!("Failed to create UDP socket: {}", e),
            }
        }
        
        Ok(())
    }
    
    async fn generate_initial_test_cases(&self) -> Result<Vec<Vec<u8>>> {
        info!("Generating initial test cases...");
        
        let mut test_cases = Vec::new();
        const INITIAL_CASES: usize = 50;
        
        for i in 0..INITIAL_CASES {
            // Generate some seed data
            let mut seed_data = vec![0u8; 1024];
            for j in 0..seed_data.len() {
                seed_data[j] = ((i + j) % 256) as u8;
            }
            
            let mut unstructured = Unstructured::new(&seed_data);
            
            // Generate both valid and malformed packets
            if let Ok(packet) = self.protocol_fuzzer.generate_valid_packet(&mut unstructured) {
                test_cases.push(packet);
            }
            
            if let Ok(packet) = self.protocol_fuzzer.generate_malformed_packet(&mut unstructured) {
                test_cases.push(packet);
            }
        }
        
        info!("Generated {} initial test cases", test_cases.len());
        Ok(test_cases)
    }
    
    async fn mutate_test_case(&self, base_case: &[u8]) -> Result<Vec<u8>> {
        // Simple mutation strategy
        let mut seed_data = vec![0u8; 512];
        let rand_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as usize;
            
        for i in 0..seed_data.len() {
            seed_data[i] = ((rand_seed + i) % 256) as u8;
        }
        
        let mut unstructured = Unstructured::new(&seed_data);
        
        // Try protocol-specific mutation first
        if let Ok(mutated) = self.protocol_fuzzer.mutate_packet(base_case, &mut unstructured) {
            return Ok(mutated);
        }
        
        // Fallback to simple bit flip
        let mut mutated = base_case.to_vec();
        if !mutated.is_empty() {
            let byte_idx = rand_seed % mutated.len();
            let bit_idx = (rand_seed / mutated.len()) % 8;
            mutated[byte_idx] ^= 1 << bit_idx;
        }
        
        Ok(mutated)
    }
    
    async fn execute_test_case(&self, test_case: &[u8]) -> Result<ExecutionResult> {
        let start_time = Instant::now();
        
        if self.protocol_type.is_tcp() {
            self.execute_tcp_test_case(test_case, start_time).await
        } else {
            self.execute_udp_test_case(test_case, start_time).await
        }
    }
    
    async fn execute_tcp_test_case(&self, test_case: &[u8], start_time: Instant) -> Result<ExecutionResult> {
        match timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("{}:{}", self.target_host, self.target_port))
        ).await {
            Ok(Ok(mut stream)) => {
                use tokio::io::AsyncWriteExt;
                match stream.write_all(test_case).await {
                    Ok(_) => {
                        // Try to read response
                        use tokio::io::AsyncReadExt;
                        let mut buffer = vec![0u8; 4096];
                        let response_result = timeout(
                            Duration::from_secs(2),
                            stream.read(&mut buffer)
                        ).await;
                        
                        let execution_time_ms = start_time.elapsed().as_millis() as u64;
                        
                        match response_result {
                            Ok(Ok(bytes_read)) => {
                                buffer.truncate(bytes_read);
                                Ok(ExecutionResult {
                                    success: true,
                                    response_data: Some(buffer),
                                    execution_time_ms,
                                    error_message: None,
                                })
                            }
                            Ok(Err(e)) => Ok(ExecutionResult {
                                success: false,
                                response_data: None,
                                execution_time_ms,
                                error_message: Some(format!("Read error: {}", e)),
                            }),
                            Err(_) => Ok(ExecutionResult {
                                success: true,
                                response_data: None,
                                execution_time_ms,
                                error_message: Some("Read timeout".to_string()),
                            }),
                        }
                    }
                    Err(e) => Ok(ExecutionResult {
                        success: false,
                        response_data: None,
                        execution_time_ms: start_time.elapsed().as_millis() as u64,
                        error_message: Some(format!("Write error: {}", e)),
                    }),
                }
            }
            Ok(Err(e)) => Ok(ExecutionResult {
                success: false,
                response_data: None,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                error_message: Some(format!("Connection error: {}", e)),
            }),
            Err(_) => Ok(ExecutionResult {
                success: false,
                response_data: None,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                error_message: Some("Connection timeout".to_string()),
            }),
        }
    }
    
    async fn execute_udp_test_case(&self, test_case: &[u8], start_time: Instant) -> Result<ExecutionResult> {
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => {
                let target_addr = format!("{}:{}", self.target_host, self.target_port);
                
                match socket.send_to(test_case, &target_addr).await {
                    Ok(_) => {
                        // Try to receive response
                        let mut buffer = vec![0u8; 4096];
                        let response_result = timeout(
                            Duration::from_secs(2),
                            socket.recv_from(&mut buffer)
                        ).await;
                        
                        let execution_time_ms = start_time.elapsed().as_millis() as u64;
                        
                        match response_result {
                            Ok(Ok((bytes_received, _addr))) => {
                                buffer.truncate(bytes_received);
                                Ok(ExecutionResult {
                                    success: true,
                                    response_data: Some(buffer),
                                    execution_time_ms,
                                    error_message: None,
                                })
                            }
                            Ok(Err(e)) => Ok(ExecutionResult {
                                success: false,
                                response_data: None,
                                execution_time_ms,
                                error_message: Some(format!("UDP error: {}", e)),
                            }),
                            Err(_) => Ok(ExecutionResult {
                                success: true, // Timeout is normal for UDP
                                response_data: None,
                                execution_time_ms,
                                error_message: Some("UDP timeout".to_string()),
                            }),
                        }
                    }
                    Err(e) => Ok(ExecutionResult {
                        success: false,
                        response_data: None,
                        execution_time_ms: start_time.elapsed().as_millis() as u64,
                        error_message: Some(format!("Send error: {}", e)),
                    }),
                }
            }
            Err(e) => Ok(ExecutionResult {
                success: false,
                response_data: None,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                error_message: Some(format!("Socket error: {}", e)),
            }),
        }
    }
    
    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        // Consider test cases interesting if they produce responses or unique errors
        result.response_data.is_some() || 
        (result.error_message.is_some() && result.error_message.as_ref().unwrap() != "UDP timeout")
    }
    
    async fn save_results(&self, total_executions: u64, crashes_found: u64) -> Result<()> {
        info!("Saving fuzzing results...");
        
        // Create results directory
        let results_dir = PathBuf::from("./fuzzing_results");
        std::fs::create_dir_all(&results_dir)?;
        
        // Save crash information
        if let Ok(detector) = self.crash_detector.lock() {
            detector.save_crashes(&results_dir).await?;
        }
        
        // Save coverage report if enabled
        if self.coverage_enabled {
            if let Some(coverage_dir) = &self.coverage_dir {
                self.coverage_collector.save_report(coverage_dir).await?;
            }
        }
        
        // Save summary report
        let summary = format!(
            "Network Protocol Fuzzer Results\n\
             ================================\n\
             Protocol: {:?}\n\
             Target: {}:{}\n\
             Total Executions: {}\n\
             Crashes Found: {}\n\
             Workers: {}\n\
             Coverage Enabled: {}\n",
            self.protocol_type,
            self.target_host,
            self.target_port,
            total_executions,
            crashes_found,
            self.worker_count,
            self.coverage_enabled
        );
        
        let summary_file = results_dir.join("summary.txt");
        std::fs::write(summary_file, summary)?;
        
        info!("Results saved to {:?}", results_dir);
        Ok(())
    }
}

// Public functions for CLI commands
pub async fn generate_test_cases(protocol: ProtocolType, count: usize, output: PathBuf) -> Result<()> {
    info!("Generating {} test cases for {:?} protocol", count, protocol);
    
    std::fs::create_dir_all(&output)?;
    let protocol_fuzzer = create_protocol_fuzzer(protocol);
    
    for i in 0..count {
        // Generate seed data
        let mut seed_data = vec![0u8; 1024];
        for j in 0..seed_data.len() {
            seed_data[j] = ((i + j) % 256) as u8;
        }
        
        let mut unstructured = Unstructured::new(&seed_data);
        
        // Generate both valid and malformed packets
        let packets = vec![
            protocol_fuzzer.generate_valid_packet(&mut unstructured),
            protocol_fuzzer.generate_malformed_packet(&mut unstructured),
        ];
        
        for (packet_idx, packet_result) in packets.into_iter().enumerate() {
            if let Ok(packet) = packet_result {
                let filename = output.join(format!("testcase_{:06}_{}.bin", i, packet_idx));
                std::fs::write(filename, packet)?;
            }
        }
    }
    
    info!("Test cases generated in {:?}", output);
    Ok(())
}

pub async fn validate_protocol_parser(protocol: ProtocolType, test_dir: PathBuf) -> Result<()> {
    info!("Validating {:?} protocol parser with test cases from {:?}", protocol, test_dir);
    
    let protocol_fuzzer = create_protocol_fuzzer(protocol);
    let mut valid_count = 0;
    let mut invalid_count = 0;
    let mut total_count = 0;
    
    // Read all test case files
    for entry in std::fs::read_dir(test_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.extension().map_or(false, |ext| ext == "bin") {
            if let Ok(packet_data) = std::fs::read(&path) {
                total_count += 1;
                
                if protocol_fuzzer.validate_packet(&packet_data) {
                    valid_count += 1;
                    debug!("Valid packet: {:?}", path.file_name());
                } else {
                    invalid_count += 1;
                    debug!("Invalid packet: {:?}", path.file_name());
                }
            }
        }
    }
    
    info!("Validation results:");
    info!("  Total packets: {}", total_count);
    info!("  Valid packets: {}", valid_count);
    info!("  Invalid packets: {}", invalid_count);
    info!("  Validation rate: {:.2}%", 
          if total_count > 0 { (valid_count as f64 / total_count as f64) * 100.0 } else { 0.0 });
    
    Ok(())
}