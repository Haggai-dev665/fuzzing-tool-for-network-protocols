# 🔍 Network Protocol Fuzzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Build Status](https://img.shields.io/github/workflow/status/Haggai-dev665/fuzzing-tool-for-network-protocols/CI)](https://github.com/Haggai-dev665/fuzzing-tool-for-network-protocols/actions)

An advanced fuzzing tool specifically designed for network protocols like DNS and MQTT, featuring coverage-guided fuzzing, grammar-based input generation, and comprehensive vulnerability detection. Perfect for security researchers, IoT developers, and network security auditors.

## 🚀 Features

### 🎯 Protocol Support
- **DNS Fuzzing**: Complete DNS packet fuzzing with support for all record types
- **MQTT Fuzzing**: MQTT 3.1.1 protocol fuzzing targeting IoT devices
- **Extensible Architecture**: Easy to add new protocol support

### 🧠 Advanced Fuzzing Techniques
- **Grammar-Based Generation**: Protocol-aware packet generation
- **Coverage-Guided Fuzzing**: Intelligent test case evolution
- **Mutation Strategies**: Multiple sophisticated mutation algorithms
- **Parallel Execution**: Multi-threaded fuzzing for maximum performance

### 🔬 Security Analysis
- **Crash Detection**: Automatic vulnerability discovery
- **Severity Classification**: Intelligent crash impact assessment
- **Coverage Analysis**: Detailed code path exploration
- **Real-time Monitoring**: Live fuzzing session statistics

### 📊 Comprehensive Reporting
- **HTML Reports**: Beautiful, interactive vulnerability reports
- **Crash Reproduction**: Detailed crash reproduction instructions
- **Coverage Metrics**: In-depth coverage analysis
- **Performance Statistics**: Execution rate and efficiency metrics

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Network Protocol Fuzzer                    │
├─────────────────┬───────────────┬─────────────────┬─────────────┤
│   CLI Interface │  Core Engine  │   Protocols     │  Reporting  │
│                 │               │                 │             │
│ ┌─────────────┐ │ ┌───────────┐ │ ┌─────────────┐ │ ┌─────────┐ │
│ │   Commands  │ │ │  Fuzzing  │ │ │     DNS     │ │ │  HTML   │ │
│ │   - fuzz    │ │ │   Engine  │ │ │   Fuzzer    │ │ │ Reports │ │
│ │   - generate│ │ │           │ │ │             │ │ │         │ │
│ │   - validate│ │ │ ┌───────┐ │ │ │ ┌─────────┐ │ │ │ ┌─────┐ │ │
│ └─────────────┘ │ │ │Crash  │ │ │ │ │Grammar  │ │ │ │ │Crash│ │ │
│                 │ │ │Detect │ │ │ │ │ Rules   │ │ │ │ │Data │ │ │
│ ┌─────────────┐ │ │ └───────┘ │ │ │ └─────────┘ │ │ │ └─────┘ │ │
│ │ Parameters  │ │ │           │ │ │             │ │ │         │ │
│ │  - target   │ │ │ ┌───────┐ │ │ │ ┌─────────┐ │ │ │ ┌─────┐ │ │
│ │  - protocol │ │ │ │Coverage│ │ │ │ │Mutations│ │ │ │ │Stats│ │ │
│ │  - workers  │ │ │ │Tracker│ │ │ │ │         │ │ │ │ │     │ │ │
│ └─────────────┘ │ │ └───────┘ │ │ │ └─────────┘ │ │ │ └─────┘ │ │
└─────────────────┼───────────────┼─────────────────┼─────────────┤
                  │               │ ┌─────────────┐ │             │
                  │ ┌───────────┐ │ │    MQTT     │ │ ┌─────────┐ │
                  │ │  Network  │ │ │   Fuzzer    │ │ │Coverage │ │
                  │ │ Executor  │ │ │             │ │ │Analysis │ │
                  │ │           │ │ │ ┌─────────┐ │ │ │         │ │
                  │ │ ┌───────┐ │ │ │ │Packet   │ │ │ │ ┌─────┐ │ │
                  │ │ │TCP/UDP│ │ │ │ │Types    │ │ │ │ │Edge │ │ │
                  │ │ │Handler│ │ │ │ │         │ │ │ │ │Track│ │ │
                  │ │ └───────┘ │ │ │ └─────────┘ │ │ │ └─────┘ │ │
                  │ │           │ │ │             │ │ │         │ │
                  │ │ ┌───────┐ │ │ │ ┌─────────┐ │ │ │ ┌─────┐ │ │
                  │ │ │Timeout│ │ │ │ │IoT      │ │ │ │ │Path │ │ │
                  │ │ │Manager│ │ │ │ │Targets  │ │ │ │ │Trace│ │ │
                  │ │ └───────┘ │ │ │ └─────────┘ │ │ │ └─────┘ │ │
                  │ └───────────┘ │ └─────────────┘ │ └─────────┘ │
                  └───────────────┴─────────────────┴─────────────┘
```

## 🛠️ Installation

### Prerequisites
- Rust 1.70+ ([Install Rust](https://rustup.rs/))
- Git

### Build from Source
```bash
# Clone the repository
git clone https://github.com/Haggai-dev665/fuzzing-tool-for-network-protocols.git
cd fuzzing-tool-for-network-protocols

# Build in release mode for best performance
cargo build --release

# The binary will be available at ./target/release/protocol-fuzzer
```

### Quick Install (from Cargo)
```bash
cargo install --git https://github.com/Haggai-dev665/fuzzing-tool-for-network-protocols.git
```

## 📖 Usage

### Basic DNS Fuzzing
```bash
# Fuzz a local DNS server
./target/release/protocol-fuzzer fuzz \
    --protocol dns \
    --target 127.0.0.1 \
    --port 53 \
    --iterations 10000 \
    --workers 4 \
    --coverage-dir ./coverage \
    --verbose

# Example output:
# [2024-01-15 10:30:45.123] [INFO] Starting fuzzing campaign with 10000 iterations
# [2024-01-15 10:30:45.150] [INFO] Target: 127.0.0.1:53 (UDP)
# [2024-01-15 10:30:45.200] [INFO] UDP test packet sent successfully
# [2024-01-15 10:30:46.100] [INFO] Generated 100 initial test cases
# [2024-01-15 10:30:46.110] [INFO] Fuzzing campaign started!
# [2024-01-15 10:31:46.250] [INFO] Stats - Iter: 1001/10000, Execs: 1001, Crashes: 0, Exec/sec: 16.68, Coverage: 23.45%, Corpus: 45
```

### MQTT IoT Device Fuzzing
```bash
# Target an IoT MQTT broker
./target/release/protocol-fuzzer fuzz \
    --protocol mqtt \
    --target 192.168.1.100 \
    --port 1883 \
    --iterations 50000 \
    --workers 8

# Example discovering a crash:
# [2024-01-15 10:35:12.445] [WARN] 🐛 CRASH DISCOVERED! ID: a7b3c9d2 | Input size: 234 bytes | Error: Connection reset by peer
```

### Generate Test Cases
```bash
# Generate DNS test cases for manual analysis
./target/release/protocol-fuzzer generate \
    --protocol dns \
    --count 1000 \
    --output ./test_cases

# Generate MQTT test cases
./target/release/protocol-fuzzer generate \
    --protocol mqtt \
    --count 500 \
    --output ./mqtt_tests
```

### Validate Protocol Parsers
```bash
# Test your own DNS parser implementation
./target/release/protocol-fuzzer validate \
    --protocol dns \
    --test-dir ./test_cases

# Example output:
# [2024-01-15 10:40:15.123] [INFO] Validation results:
# [2024-01-15 10:40:15.123] [INFO]   Total packets: 1000
# [2024-01-15 10:40:15.123] [INFO]   Valid packets: 847
# [2024-01-15 10:40:15.123] [INFO]   Invalid packets: 153
# [2024-01-15 10:40:15.123] [INFO]   Validation rate: 84.70%
```

## 🎯 Protocol-Specific Features

### DNS Fuzzing Capabilities
- **Query Types**: Support for all DNS record types (A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, SRV)
- **Malformed Packets**: Invalid headers, truncated queries, oversized queries
- **Compression Attacks**: Pointer loops, invalid compression, oversized labels
- **Grammar Mutations**: Domain name mutations, header flag manipulation

### MQTT Fuzzing Capabilities
- **Packet Types**: CONNECT, PUBLISH, SUBSCRIBE, UNSUBSCRIBE, PINGREQ, and more
- **QoS Levels**: Testing all Quality of Service levels (0, 1, 2)
- **Topic Fuzzing**: Malformed topic names, invalid UTF-8, excessive subscriptions
- **Protocol Violations**: Invalid remaining lengths, malformed headers, state violations

## 📊 Understanding Results

### Crash Reports
When crashes are discovered, detailed reports are generated:

```
fuzzing_results/
├── crashes/
│   ├── crash_0001_input.bin      # Raw input that caused crash
│   ├── crash_0001_metadata.json  # Crash details and classification
│   ├── crash_0002_input.bin
│   └── crash_0002_metadata.json
├── coverage_report.json          # Coverage analysis
├── crash_summary.json            # High-level crash statistics
└── summary.txt                   # Human-readable summary
```

### Crash Severity Levels
- **🔴 Critical**: Memory corruption, buffer overflows, security vulnerabilities
- **🟠 High**: Server crashes, service disruption, protocol violations
- **🟡 Medium**: Timeouts, connection issues, malformed responses
- **🟢 Low**: Minor protocol deviations, expected error conditions

## 🛡️ Security and Ethics

### Responsible Disclosure
- Always obtain proper authorization before testing
- Follow responsible disclosure practices for discovered vulnerabilities
- Respect rate limits and avoid causing service disruption

### Legal Considerations
- Only test systems you own or have explicit permission to test
- Comply with local laws and regulations regarding security testing
- Consider the impact on production systems

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-protocol`
3. **Add your protocol support**:
   ```rust
   // src/protocols/your_protocol.rs
   impl ProtocolFuzzer for YourProtocolFuzzer {
       fn generate_valid_packet(&self, data: &mut Unstructured) -> Result<Vec<u8>> {
           // Implementation
       }
       // ... other methods
   }
   ```
4. **Add tests and documentation**
5. **Submit a pull request**

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **LibAFL Team**: For inspiration and fuzzing techniques
- **Rust Community**: For excellent networking and async libraries
- **Security Researchers**: For responsible disclosure practices and methodologies
- **IoT Community**: For highlighting the need for better protocol security testing

---

**⚠️ Disclaimer**: This tool is intended for legitimate security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.