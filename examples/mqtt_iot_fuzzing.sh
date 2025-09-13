#!/bin/bash

# MQTT IoT Fuzzing Example Script
# This script demonstrates how to discover and fuzz IoT MQTT brokers

set -e

echo "🌐 MQTT IoT Fuzzing Example Script"
echo "=================================="

# Configuration
FUZZER_BINARY="./target/release/protocol-fuzzer"
OUTPUT_DIR="./mqtt_iot_results"
NETWORK_RANGE="192.168.1.0/24"  # Adjust to your network
MQTT_PORT=1883

# Check if fuzzer binary exists
if [ ! -f "$FUZZER_BINARY" ]; then
    echo "❌ Fuzzer binary not found. Please build first:"
    echo "   cargo build --release"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "🔍 Discovering MQTT brokers on network: $NETWORK_RANGE"

# Discover MQTT brokers (requires nmap)
if command -v nmap &> /dev/null; then
    echo "📡 Scanning for MQTT services..."
    nmap -p $MQTT_PORT --open $NETWORK_RANGE | grep -E "Nmap scan report|$MQTT_PORT/tcp open" > "$OUTPUT_DIR/discovered_brokers.txt" || true
    
    # Extract IP addresses
    grep "Nmap scan report" "$OUTPUT_DIR/discovered_brokers.txt" | awk '{print $5}' > "$OUTPUT_DIR/mqtt_targets.txt" || true
    
    BROKER_COUNT=$(wc -l < "$OUTPUT_DIR/mqtt_targets.txt" 2>/dev/null || echo "0")
    echo "🎯 Found $BROKER_COUNT potential MQTT brokers"
else
    echo "⚠️  nmap not found. Using default target 127.0.0.1"
    echo "127.0.0.1" > "$OUTPUT_DIR/mqtt_targets.txt"
    BROKER_COUNT=1
fi

if [ "$BROKER_COUNT" -eq 0 ]; then
    echo "❌ No MQTT brokers discovered. Exiting."
    exit 1
fi

echo ""
echo "🚀 Starting MQTT fuzzing campaign..."

# Fuzz each discovered broker
while IFS= read -r target; do
    if [ -n "$target" ]; then
        echo "🎯 Fuzzing MQTT broker: $target"
        
        TARGET_DIR="$OUTPUT_DIR/target_$target"
        mkdir -p "$TARGET_DIR"
        
        $FUZZER_BINARY fuzz \
            --protocol mqtt \
            --target "$target" \
            --port $MQTT_PORT \
            --iterations 5000 \
            --workers 4 \
            --coverage-dir "$TARGET_DIR/coverage" \
            --verbose
        
        echo "✅ Completed fuzzing $target"
        echo ""
    fi
done < "$OUTPUT_DIR/mqtt_targets.txt"

echo "🎉 MQTT IoT fuzzing campaign completed!"
echo "📁 Results saved to: $OUTPUT_DIR"

# Generate summary
echo "📊 Fuzzing Summary" > "$OUTPUT_DIR/campaign_summary.txt"
echo "==================" >> "$OUTPUT_DIR/campaign_summary.txt"
echo "Targets tested: $BROKER_COUNT" >> "$OUTPUT_DIR/campaign_summary.txt"
echo "Date: $(date)" >> "$OUTPUT_DIR/campaign_summary.txt"
echo "" >> "$OUTPUT_DIR/campaign_summary.txt"

# Check for crashes across all targets
TOTAL_CRASHES=0
for target_dir in "$OUTPUT_DIR"/target_*/crashes; do
    if [ -d "$target_dir" ] && [ "$(ls -A $target_dir)" ]; then
        CRASH_COUNT=$(ls -1 "$target_dir"/*.bin 2>/dev/null | wc -l || echo "0")
        TOTAL_CRASHES=$((TOTAL_CRASHES + CRASH_COUNT))
        TARGET_IP=$(basename $(dirname "$target_dir") | sed 's/target_//')
        echo "Target $TARGET_IP: $CRASH_COUNT crashes" >> "$OUTPUT_DIR/campaign_summary.txt"
    fi
done

echo "Total crashes found: $TOTAL_CRASHES" >> "$OUTPUT_DIR/campaign_summary.txt"

if [ "$TOTAL_CRASHES" -gt 0 ]; then
    echo "⚠️  $TOTAL_CRASHES crashes detected across all targets!"
    echo "🔍 Review individual target directories for details"
else
    echo "✅ No crashes detected in any IoT devices"
fi

echo ""
echo "📋 Campaign summary: $OUTPUT_DIR/campaign_summary.txt"