#!/bin/bash

# DNS Fuzzing Example Script
# This script demonstrates how to fuzz different DNS servers

set -e

echo "🔍 DNS Fuzzing Example Script"
echo "=============================="

# Configuration
FUZZER_BINARY="./target/release/protocol-fuzzer"
OUTPUT_DIR="./dns_fuzzing_results"
TEST_DURATION=300  # 5 minutes

# Check if fuzzer binary exists
if [ ! -f "$FUZZER_BINARY" ]; then
    echo "❌ Fuzzer binary not found. Please build first:"
    echo "   cargo build --release"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "📊 Starting DNS fuzzing campaign..."
echo "Duration: $TEST_DURATION seconds"
echo "Output: $OUTPUT_DIR"
echo ""

# Start DNS fuzzing
$FUZZER_BINARY fuzz \
    --protocol dns \
    --target 127.0.0.1 \
    --port 53 \
    --iterations 10000 \
    --workers 4 \
    --coverage-dir "$OUTPUT_DIR/coverage" \
    --verbose

echo ""
echo "✅ DNS fuzzing completed!"
echo "📁 Results saved to: $OUTPUT_DIR"

# Check for crashes
if [ -d "$OUTPUT_DIR/crashes" ] && [ "$(ls -A $OUTPUT_DIR/crashes)" ]; then
    echo "⚠️  Crashes detected! Check the crash reports:"
    ls -la "$OUTPUT_DIR/crashes/"
else
    echo "✅ No crashes detected during fuzzing session"
fi

echo ""
echo "📈 Coverage report available at: $OUTPUT_DIR/coverage/coverage_report.json"
echo "📋 Summary report: $OUTPUT_DIR/summary.txt"