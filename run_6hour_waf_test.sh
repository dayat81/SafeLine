#!/bin/bash

# 6-hour continuous WAF load test script
# This script runs Locust for 6 hours with moderate load to test SafeLine WAF

echo "=========================================="
echo "Starting 6-hour WAF Load Test"
echo "Target: http://192.168.18.177"
echo "Duration: 6 hours (21600 seconds)"
echo "Start time: $(date)"
echo "=========================================="

# Create results directory
RESULTS_DIR="waf_test_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

# Log file
LOG_FILE="$RESULTS_DIR/waf_test_6hr.log"

# Run Locust test
# Parameters:
# - 50 concurrent users (moderate load)
# - Spawn rate: 2 users per second
# - Duration: 6 hours (21600 seconds)
# - CSV output for detailed statistics
# - HTML report at the end

echo "Starting Locust with 50 users for 6 hours..." | tee -a "$LOG_FILE"
echo "Results will be saved to: $RESULTS_DIR" | tee -a "$LOG_FILE"

locust -f waf_load_test.py \
    --host http://192.168.18.177 \
    --headless \
    --users 50 \
    --spawn-rate 2 \
    --run-time 6h \
    --csv "$RESULTS_DIR/waf_test" \
    --html "$RESULTS_DIR/waf_test_report.html" \
    --logfile "$LOG_FILE" \
    --loglevel INFO

echo "=========================================="
echo "Test completed at: $(date)"
echo "Results saved in: $RESULTS_DIR"
echo "=========================================="

# Generate summary
echo -e "\n=== Test Summary ===" >> "$LOG_FILE"
echo "End time: $(date)" >> "$LOG_FILE"
if [ -f "$RESULTS_DIR/waf_test_stats.csv" ]; then
    echo -e "\nFinal statistics:" >> "$LOG_FILE"
    tail -20 "$RESULTS_DIR/waf_test_stats.csv" >> "$LOG_FILE"
fi

echo "Test complete. Check $RESULTS_DIR for detailed results."