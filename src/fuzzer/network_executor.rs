use anyhow::Result;
use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{BytesInput, Input},
    observers::{Observer, ObserversTuple},
    Error as LibAFLError,
};
use log::{debug, error, warn};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
    runtime::Runtime,
};

use crate::protocols::ProtocolType;
use super::crash_detector::CrashDetector;

pub struct NetworkExecutor<OT> {
    protocol_type: ProtocolType,
    target_host: String,
    target_port: u16,
    crash_detector: Arc<Mutex<CrashDetector>>,
    observers: OT,
    runtime: Runtime,
    execution_timeout: Duration,
    connection_timeout: Duration,
}

impl<OT> NetworkExecutor<OT>
where
    OT: ObserversTuple<BytesInput>,
{
    pub fn new(
        protocol_type: ProtocolType,
        target_host: String,
        target_port: u16,
        crash_detector: Arc<Mutex<CrashDetector>>,
        observers: OT,
    ) -> Result<Self> {
        let runtime = Runtime::new()?;
        
        Ok(Self {
            protocol_type,
            target_host,
            target_port,
            crash_detector,
            observers,
            runtime,
            execution_timeout: Duration::from_secs(5),
            connection_timeout: Duration::from_secs(2),
        })
    }
    
    async fn execute_tcp_test(&self, input_data: &[u8]) -> Result<NetworkExecutionResult> {
        let start_time = Instant::now();
        
        // Try to connect to the target
        let stream = match timeout(
            self.connection_timeout,
            TcpStream::connect(format!("{}:{}", self.target_host, self.target_port))
        ).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!("TCP connection failed: {}", e);
                return Ok(NetworkExecutionResult {
                    exit_kind: ExitKind::Ok,
                    response_data: None,
                    execution_time: start_time.elapsed(),
                    connection_successful: false,
                    error_message: Some(format!("Connection failed: {}", e)),
                });
            }
            Err(_) => {
                debug!("TCP connection timed out");
                return Ok(NetworkExecutionResult {
                    exit_kind: ExitKind::Timeout,
                    response_data: None,
                    execution_time: start_time.elapsed(),
                    connection_successful: false,
                    error_message: Some("Connection timeout".to_string()),
                });
            }
        };
        
        // Send the fuzzed data
        let send_result = timeout(
            self.execution_timeout,
            async {
                use tokio::io::AsyncWriteExt;
                let mut stream = stream;
                stream.write_all(input_data).await?;
                stream.flush().await?;
                
                // Try to read response
                use tokio::io::AsyncReadExt;
                let mut buffer = vec![0u8; 4096];
                let bytes_read = stream.read(&mut buffer).await?;
                buffer.truncate(bytes_read);
                
                Ok::<Vec<u8>, tokio::io::Error>(buffer)
            }
        ).await;
        
        let execution_time = start_time.elapsed();
        
        match send_result {
            Ok(Ok(response)) => {
                debug!("TCP execution successful, response length: {}", response.len());
                Ok(NetworkExecutionResult {
                    exit_kind: ExitKind::Ok,
                    response_data: Some(response),
                    execution_time,
                    connection_successful: true,
                    error_message: None,
                })
            }
            Ok(Err(e)) => {
                warn!("TCP execution error: {}", e);
                Ok(NetworkExecutionResult {
                    exit_kind: ExitKind::Crash,
                    response_data: None,
                    execution_time,
                    connection_successful: true,
                    error_message: Some(format!("Execution error: {}", e)),
                })
            }
            Err(_) => {
                debug!("TCP execution timed out");
                Ok(NetworkExecutionResult {
                    exit_kind: ExitKind::Timeout,
                    response_data: None,
                    execution_time,
                    connection_successful: true,
                    error_message: Some("Execution timeout".to_string()),
                })
            }
        }
    }
    
    async fn execute_udp_test(&self, input_data: &[u8]) -> Result<NetworkExecutionResult> {
        let start_time = Instant::now();
        
        // Create UDP socket
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(e) => {
                error!("Failed to create UDP socket: {}", e);
                return Ok(NetworkExecutionResult {
                    exit_kind: ExitKind::Crash,
                    response_data: None,
                    execution_time: start_time.elapsed(),
                    connection_successful: false,
                    error_message: Some(format!("Socket creation failed: {}", e)),
                });
            }
        };
        
        let target_addr = format!("{}:{}", self.target_host, self.target_port);
        
        // Send the fuzzed data and try to receive response
        let send_recv_result = timeout(
            self.execution_timeout,
            async {
                // Send data
                socket.send_to(input_data, &target_addr).await?;
                
                // Try to receive response
                let mut buffer = vec![0u8; 4096];
                let (bytes_received, _addr) = socket.recv_from(&mut buffer).await?;
                buffer.truncate(bytes_received);
                
                Ok::<Vec<u8>, tokio::io::Error>(buffer)
            }
        ).await;
        
        let execution_time = start_time.elapsed();
        
        match send_recv_result {
            Ok(Ok(response)) => {
                debug!("UDP execution successful, response length: {}", response.len());
                Ok(NetworkExecutionResult {
                    exit_kind: ExitKind::Ok,
                    response_data: Some(response),
                    execution_time,
                    connection_successful: true,
                    error_message: None,
                })
            }
            Ok(Err(e)) => {
                // For UDP, many errors are expected (no response, connection refused, etc.)
                debug!("UDP execution error (may be normal): {}", e);
                Ok(NetworkExecutionResult {
                    exit_kind: ExitKind::Ok, // Don't treat UDP errors as crashes by default
                    response_data: None,
                    execution_time,
                    connection_successful: true,
                    error_message: Some(format!("UDP error: {}", e)),
                })
            }
            Err(_) => {
                debug!("UDP execution timed out");
                Ok(NetworkExecutionResult {
                    exit_kind: ExitKind::Timeout,
                    response_data: None,
                    execution_time,
                    connection_successful: true,
                    error_message: Some("UDP timeout".to_string()),
                })
            }
        }
    }
    
    fn analyze_response(&self, result: &NetworkExecutionResult, input_data: &[u8]) -> ExitKind {
        // Protocol-specific response analysis
        match self.protocol_type {
            ProtocolType::DNS => self.analyze_dns_response(result, input_data),
            ProtocolType::MQTT => self.analyze_mqtt_response(result, input_data),
        }
    }
    
    fn analyze_dns_response(&self, result: &NetworkExecutionResult, input_data: &[u8]) -> ExitKind {
        if let Some(response) = &result.response_data {
            // Check for DNS response indicators
            if response.len() >= 12 {
                // Check if it looks like a DNS response
                let transaction_id = u16::from_be_bytes([response[0], response[1]]);
                let flags = u16::from_be_bytes([response[2], response[3]]);
                
                // Check QR bit (should be 1 for response)
                if (flags & 0x8000) != 0 {
                    debug!("Received valid DNS response (Transaction ID: {})", transaction_id);
                    return ExitKind::Ok;
                }
            }
            
            // If we got data but it doesn't look like a valid DNS response,
            // it might indicate a crash or malformed handling
            warn!("Received malformed DNS response");
            return ExitKind::Crash;
        }
        
        // For UDP DNS, no response is often normal
        result.exit_kind
    }
    
    fn analyze_mqtt_response(&self, result: &NetworkExecutionResult, input_data: &[u8]) -> ExitKind {
        if let Some(response) = &result.response_data {
            if !response.is_empty() {
                // Check if response looks like valid MQTT packet
                let packet_type = (response[0] & 0xF0) >> 4;
                
                match packet_type {
                    2 => debug!("MQTT CONNACK received"),
                    4 => debug!("MQTT PUBACK received"),
                    5 => debug!("MQTT PUBREC received"),
                    6 => debug!("MQTT PUBREL received"),
                    7 => debug!("MQTT PUBCOMP received"),
                    9 => debug!("MQTT SUBACK received"),
                    11 => debug!("MQTT UNSUBACK received"),
                    13 => debug!("MQTT PINGRESP received"),
                    _ => {
                        warn!("Unknown MQTT packet type in response: {}", packet_type);
                        return ExitKind::Crash;
                    }
                }
                
                return ExitKind::Ok;
            }
        }
        
        // Analyze the original exit kind
        match result.exit_kind {
            ExitKind::Crash => {
                // Connection was successful but execution failed - potential crash
                if result.connection_successful {
                    warn!("MQTT execution crash detected");
                    ExitKind::Crash
                } else {
                    ExitKind::Ok // Connection failure is not necessarily a crash
                }
            }
            other => other,
        }
    }
    
    fn record_crash(&self, input_data: &[u8], result: &NetworkExecutionResult) {
        if let Ok(mut detector) = self.crash_detector.lock() {
            detector.record_crash(
                input_data.to_vec(),
                result.error_message.clone(),
                result.execution_time,
                self.protocol_type,
            );
        }
    }
    
    fn update_coverage(&mut self, input_data: &[u8], result: &NetworkExecutionResult) {
        // Extract features for coverage guidance
        let features = match crate::protocols::create_protocol_fuzzer(self.protocol_type).extract_features(input_data) {
            features if !features.is_empty() => features,
            _ => vec![input_data.len() as u64], // Fallback to input length
        };
        
        // Update coverage map based on extracted features
        // This is a simplified coverage mechanism
        for (i, feature) in features.iter().enumerate() {
            let map_index = (feature % 65536) as usize;
            
            // Update observers (this is a simplified approach)
            if let Some(observer) = self.observers.match_name::<libafl::observers::HitcountsMapObserver<libafl::observers::StdMapObserver<u8>>>("coverage") {
                unsafe {
                    let map = observer.map_mut();
                    if map_index < map.len() {
                        map[map_index] = map[map_index].saturating_add(1);
                    }
                }
            }
        }
    }
}

impl<OT> Executor<BytesInput> for NetworkExecutor<OT>
where
    OT: ObserversTuple<BytesInput>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut dyn libafl::fuzzer::Fuzzer<BytesInput, Self>,
        _state: &mut dyn libafl::state::HasMetadata,
        _mgr: &mut dyn libafl::events::EventFirer<BytesInput>,
        input: &BytesInput,
    ) -> Result<ExitKind, LibAFLError> {
        let input_data = input.bytes();
        
        debug!("Executing network test with {} bytes", input_data.len());
        
        // Execute the network test
        let result = self.runtime.block_on(async {
            if self.protocol_type.is_tcp() {
                self.execute_tcp_test(input_data).await
            } else {
                self.execute_udp_test(input_data).await
            }
        }).map_err(|e| LibAFLError::unknown(format!("Network execution failed: {}", e)))?;
        
        // Analyze the response for protocol-specific behavior
        let final_exit_kind = self.analyze_response(&result, input_data);
        
        // Record crashes if detected
        if final_exit_kind == ExitKind::Crash {
            self.record_crash(input_data, &result);
        }
        
        // Update coverage information
        self.update_coverage(input_data, &result);
        
        Ok(final_exit_kind)
    }
}

impl<OT> HasObservers<BytesInput> for NetworkExecutor<OT>
where
    OT: ObserversTuple<BytesInput>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }
    
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

#[derive(Debug)]
struct NetworkExecutionResult {
    exit_kind: ExitKind,
    response_data: Option<Vec<u8>>,
    execution_time: Duration,
    connection_successful: bool,
    error_message: Option<String>,
}