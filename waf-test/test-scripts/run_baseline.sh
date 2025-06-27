#!/bin/bash

echo "=== SafeLine WAF Baseline Performance Test ==="
echo "Started at: $(date)"
echo ""

# Create results directory with timestamp
RESULTS_DIR="/results/baseline_$(date +%Y%m%d_%H%M%S)"
mkdir -p $RESULTS_DIR

# Test 1: Direct access to vulnerable app (baseline)
echo "Test 1: Direct access performance (bypassing WAF)"
echo "================================================"
ab -n 10000 -c 100 -g $RESULTS_DIR/direct_access.tsv http://vulnerable-app/ > $RESULTS_DIR/direct_access.txt 2>&1
echo "Completed direct access test"
echo ""

# Test 2: Through WAF (no attacks)
echo "Test 2: Access through WAF (legitimate traffic)"
echo "=============================================="
ab -n 10000 -c 100 -g $RESULTS_DIR/waf_access.tsv http://safeline-tengine/ > $RESULTS_DIR/waf_access.txt 2>&1
echo "Completed WAF access test"
echo ""

# Test 3: High concurrency test with Vegeta
echo "Test 3: High concurrency test (1000 RPS for 60s)"
echo "==============================================="
echo "GET http://safeline-tengine/" > /tmp/targets.txt
vegeta attack -duration=60s -rate=1000 -targets=/tmp/targets.txt | \
  vegeta report -type=text,json -output=$RESULTS_DIR/vegeta_report > $RESULTS_DIR/vegeta_summary.txt
echo "Completed high concurrency test"
echo ""

# Test 4: Latency comparison
echo "Test 4: Latency comparison test"
echo "==============================="
# Direct access latency
echo "Direct access latency:"
for i in {1..100}; do
  curl -o /dev/null -s -w "%{time_total}\n" http://vulnerable-app/
done > $RESULTS_DIR/direct_latency.txt

# WAF latency
echo "WAF latency:"
for i in {1..100}; do
  curl -o /dev/null -s -w "%{time_total}\n" http://safeline-tengine/
done > $RESULTS_DIR/waf_latency.txt

# Calculate statistics
echo "Calculating latency statistics..."
python3 - <<EOF
import statistics

with open('$RESULTS_DIR/direct_latency.txt', 'r') as f:
    direct_times = [float(line.strip()) * 1000 for line in f if line.strip()]

with open('$RESULTS_DIR/waf_latency.txt', 'r') as f:
    waf_times = [float(line.strip()) * 1000 for line in f if line.strip()]

print(f"\nDirect Access Latency (ms):")
print(f"  Mean: {statistics.mean(direct_times):.2f}")
print(f"  Median: {statistics.median(direct_times):.2f}")
print(f"  95th percentile: {sorted(direct_times)[int(0.95 * len(direct_times))]:.2f}")

print(f"\nWAF Latency (ms):")
print(f"  Mean: {statistics.mean(waf_times):.2f}")
print(f"  Median: {statistics.median(waf_times):.2f}")
print(f"  95th percentile: {sorted(waf_times)[int(0.95 * len(waf_times))]:.2f}")

print(f"\nLatency Overhead:")
overhead = ((statistics.mean(waf_times) - statistics.mean(direct_times)) / statistics.mean(direct_times)) * 100
print(f"  Average overhead: {overhead:.1f}%")
EOF

echo ""
echo "=== Baseline Performance Test Completed ==="
echo "Results saved to: $RESULTS_DIR"
echo "Completed at: $(date)"