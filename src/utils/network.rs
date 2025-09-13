use anyhow::Result;
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
};

/// Network connectivity checker
pub struct ConnectivityChecker {
    timeout_duration: Duration,
}

impl ConnectivityChecker {
    pub fn new(timeout_duration: Duration) -> Self {
        Self { timeout_duration }
    }
    
    /// Test TCP connectivity to a target
    pub async fn test_tcp(&self, host: &str, port: u16) -> Result<ConnectivityResult> {
        let start = std::time::Instant::now();
        
        let result = timeout(
            self.timeout_duration,
            TcpStream::connect(format!("{}:{}", host, port))
        ).await;
        
        let elapsed = start.elapsed();
        
        match result {
            Ok(Ok(_stream)) => Ok(ConnectivityResult {
                success: true,
                response_time: elapsed,
                error_message: None,
            }),
            Ok(Err(e)) => Ok(ConnectivityResult {
                success: false,
                response_time: elapsed,
                error_message: Some(format!("Connection failed: {}", e)),
            }),
            Err(_) => Ok(ConnectivityResult {
                success: false,
                response_time: elapsed,
                error_message: Some("Connection timeout".to_string()),
            }),
        }
    }
    
    /// Test UDP connectivity to a target (sends a probe packet)
    pub async fn test_udp(&self, host: &str, port: u16, probe_data: &[u8]) -> Result<ConnectivityResult> {
        let start = std::time::Instant::now();
        
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let target = format!("{}:{}", host, port);
        
        let result = timeout(
            self.timeout_duration,
            async {
                socket.send_to(probe_data, &target).await?;
                
                // Try to receive a response
                let mut buffer = vec![0u8; 1024];
                let (bytes_received, _) = socket.recv_from(&mut buffer).await?;
                
                Ok::<usize, tokio::io::Error>(bytes_received)
            }
        ).await;
        
        let elapsed = start.elapsed();
        
        match result {
            Ok(Ok(bytes_received)) => Ok(ConnectivityResult {
                success: true,
                response_time: elapsed,
                error_message: Some(format!("Received {} bytes", bytes_received)),
            }),
            Ok(Err(e)) => Ok(ConnectivityResult {
                success: false,
                response_time: elapsed,
                error_message: Some(format!("UDP error: {}", e)),
            }),
            Err(_) => Ok(ConnectivityResult {
                success: false,
                response_time: elapsed,
                error_message: Some("UDP timeout (may be normal)".to_string()),
            }),
        }
    }
    
    /// Resolve hostname to IP addresses
    pub async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let socket_addrs: Vec<SocketAddr> = format!("{}:0", hostname).to_socket_addrs()?.collect();
        let ip_addrs: Vec<IpAddr> = socket_addrs.into_iter().map(|addr| addr.ip()).collect();
        Ok(ip_addrs)
    }
    
    /// Test connectivity to multiple targets
    pub async fn test_multiple_targets(&self, targets: &[(String, u16, bool)]) -> Vec<(String, u16, ConnectivityResult)> {
        let mut results = Vec::new();
        
        for (host, port, is_tcp) in targets {
            let result = if *is_tcp {
                self.test_tcp(host, *port).await
            } else {
                // Use a simple probe for UDP
                let probe = b"test";
                self.test_udp(host, *port, probe).await
            };
            
            let connectivity_result = result.unwrap_or_else(|e| ConnectivityResult {
                success: false,
                response_time: Duration::from_secs(0),
                error_message: Some(format!("Test failed: {}", e)),
            });
            
            results.push((host.clone(), *port, connectivity_result));
        }
        
        results
    }
}

#[derive(Debug, Clone)]
pub struct ConnectivityResult {
    pub success: bool,
    pub response_time: Duration,
    pub error_message: Option<String>,
}

/// Network packet analyzer for protocol detection
pub struct PacketAnalyzer;

impl PacketAnalyzer {
    pub fn new() -> Self {
        Self
    }
    
    /// Analyze a packet and try to determine its protocol
    pub fn analyze_packet(&self, data: &[u8]) -> PacketAnalysis {
        let mut analysis = PacketAnalysis {
            likely_protocol: None,
            confidence: 0.0,
            features: Vec::new(),
            anomalies: Vec::new(),
        };
        
        if data.is_empty() {
            analysis.anomalies.push("Empty packet".to_string());
            return analysis;
        }
        
        // Try to detect common protocols
        if let Some((protocol, confidence)) = self.detect_protocol(data) {
            analysis.likely_protocol = Some(protocol);
            analysis.confidence = confidence;
        }
        
        // Extract general features
        analysis.features.extend(self.extract_general_features(data));
        
        // Detect anomalies
        analysis.anomalies.extend(self.detect_anomalies(data));
        
        analysis
    }
    
    fn detect_protocol(&self, data: &[u8]) -> Option<(String, f64)> {
        // DNS detection
        if data.len() >= 12 && self.looks_like_dns(data) {
            return Some(("DNS".to_string(), 0.8));
        }
        
        // MQTT detection
        if data.len() >= 2 && self.looks_like_mqtt(data) {
            return Some(("MQTT".to_string(), 0.7));
        }
        
        // HTTP detection
        if data.starts_with(b"GET ") || data.starts_with(b"POST ") || data.starts_with(b"HTTP/") {
            return Some(("HTTP".to_string(), 0.9));
        }
        
        // TLS/SSL detection
        if data.len() >= 6 && data[0] == 0x16 && data[1] == 0x03 {
            return Some(("TLS".to_string(), 0.8));
        }
        
        None
    }
    
    fn looks_like_dns(&self, data: &[u8]) -> bool {
        if data.len() < 12 {
            return false;
        }
        
        // Check basic DNS structure
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);
        let nscount = u16::from_be_bytes([data[8], data[9]]);
        let arcount = u16::from_be_bytes([data[10], data[11]]);
        
        // Basic sanity checks
        let opcode = (flags >> 11) & 0x0F;
        let rcode = flags & 0x0F;
        
        // Reasonable limits
        opcode <= 5 && rcode <= 9 && qdcount <= 100 && ancount <= 100 && nscount <= 100 && arcount <= 100
    }
    
    fn looks_like_mqtt(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        
        let packet_type = (data[0] & 0xF0) >> 4;
        
        // Valid MQTT packet types are 1-14
        if packet_type == 0 || packet_type == 15 {
            return false;
        }
        
        // Check remaining length encoding
        if data.len() > 1 {
            let mut pos = 1;
            let mut multiplier = 1;
            
            loop {
                if pos >= data.len() {
                    return false;
                }
                
                let byte = data[pos];
                
                if (byte & 0x80) == 0 {
                    break;
                }
                
                multiplier *= 128;
                if multiplier > 128 * 128 * 128 {
                    return false; // Invalid remaining length
                }
                
                pos += 1;
                if pos > 4 {
                    return false; // Too many bytes for remaining length
                }
            }
        }
        
        true
    }
    
    fn extract_general_features(&self, data: &[u8]) -> Vec<String> {
        let mut features = Vec::new();
        
        features.push(format!("size:{}", data.len()));
        
        if !data.is_empty() {
            features.push(format!("first_byte:0x{:02x}", data[0]));
        }
        
        // Calculate entropy
        let entropy = self.calculate_entropy(data);
        features.push(format!("entropy:{:.2}", entropy));
        
        // Check for null bytes
        if data.contains(&0) {
            features.push("contains_nulls".to_string());
        }
        
        // Check ASCII content
        if data.iter().all(|&b| b.is_ascii()) {
            features.push("ascii_content".to_string());
        }
        
        features
    }
    
    fn detect_anomalies(&self, data: &[u8]) -> Vec<String> {
        let mut anomalies = Vec::new();
        
        // Size anomalies
        if data.len() > 65536 {
            anomalies.push("Unusually large packet".to_string());
        }
        
        // Pattern anomalies
        if data.len() > 100 {
            let repeated_byte_count = self.count_repeated_bytes(data);
            if repeated_byte_count > data.len() / 2 {
                anomalies.push("High repeated byte count".to_string());
            }
        }
        
        // Entropy anomalies
        let entropy = self.calculate_entropy(data);
        if entropy < 1.0 {
            anomalies.push("Very low entropy".to_string());
        } else if entropy > 7.5 {
            anomalies.push("Very high entropy".to_string());
        }
        
        anomalies
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
    
    fn count_repeated_bytes(&self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        
        let mut count = 0;
        let mut prev_byte = data[0];
        let mut current_run = 1;
        
        for &byte in &data[1..] {
            if byte == prev_byte {
                current_run += 1;
            } else {
                if current_run > 1 {
                    count += current_run;
                }
                current_run = 1;
                prev_byte = byte;
            }
        }
        
        if current_run > 1 {
            count += current_run;
        }
        
        count
    }
}

#[derive(Debug, Clone)]
pub struct PacketAnalysis {
    pub likely_protocol: Option<String>,
    pub confidence: f64,
    pub features: Vec<String>,
    pub anomalies: Vec<String>,
}

/// Network load generator for stress testing
pub struct LoadGenerator {
    concurrent_connections: usize,
    request_rate: f64, // requests per second
}

impl LoadGenerator {
    pub fn new(concurrent_connections: usize, request_rate: f64) -> Self {
        Self {
            concurrent_connections,
            request_rate,
        }
    }
    
    /// Generate load against a TCP target
    pub async fn generate_tcp_load(
        &self,
        host: &str,
        port: u16,
        payload: &[u8],
        duration: Duration,
    ) -> Result<LoadTestResult> {
        let start_time = std::time::Instant::now();
        let mut handles = Vec::new();
        let mut results = Vec::new();
        
        let requests_per_worker = (self.request_rate / self.concurrent_connections as f64).max(1.0);
        let delay_between_requests = Duration::from_secs_f64(1.0 / requests_per_worker);
        
        for _ in 0..self.concurrent_connections {
            let host = host.to_string();
            let payload = payload.to_vec();
            let worker_duration = duration;
            
            let handle = tokio::spawn(async move {
                let mut worker_results = Vec::new();
                let worker_start = std::time::Instant::now();
                
                while worker_start.elapsed() < worker_duration {
                    let request_start = std::time::Instant::now();
                    
                    let result = match TcpStream::connect(format!("{}:{}", host, port)).await {
                        Ok(mut stream) => {
                            use tokio::io::AsyncWriteExt;
                            match stream.write_all(&payload).await {
                                Ok(_) => RequestResult {
                                    success: true,
                                    response_time: request_start.elapsed(),
                                    error: None,
                                },
                                Err(e) => RequestResult {
                                    success: false,
                                    response_time: request_start.elapsed(),
                                    error: Some(format!("Write error: {}", e)),
                                },
                            }
                        }
                        Err(e) => RequestResult {
                            success: false,
                            response_time: request_start.elapsed(),
                            error: Some(format!("Connection error: {}", e)),
                        },
                    };
                    
                    worker_results.push(result);
                    
                    // Rate limiting
                    tokio::time::sleep(delay_between_requests).await;
                }
                
                worker_results
            });
            
            handles.push(handle);
        }
        
        // Collect results from all workers
        for handle in handles {
            if let Ok(worker_results) = handle.await {
                results.extend(worker_results);
            }
        }
        
        let total_time = start_time.elapsed();
        
        Ok(LoadTestResult {
            total_requests: results.len(),
            successful_requests: results.iter().filter(|r| r.success).count(),
            failed_requests: results.iter().filter(|r| !r.success).count(),
            total_time,
            average_response_time: self.calculate_average_response_time(&results),
            requests_per_second: results.len() as f64 / total_time.as_secs_f64(),
        })
    }
    
    fn calculate_average_response_time(&self, results: &[RequestResult]) -> Duration {
        if results.is_empty() {
            return Duration::from_secs(0);
        }
        
        let total_nanos: u128 = results.iter()
            .map(|r| r.response_time.as_nanos())
            .sum();
        
        Duration::from_nanos((total_nanos / results.len() as u128) as u64)
    }
}

#[derive(Debug, Clone)]
pub struct RequestResult {
    pub success: bool,
    pub response_time: Duration,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LoadTestResult {
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub total_time: Duration,
    pub average_response_time: Duration,
    pub requests_per_second: f64,
}

impl Default for PacketAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}