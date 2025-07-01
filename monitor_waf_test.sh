#!/bin/bash

# Monitor the 6-hour WAF test progress

echo "Monitoring WAF Load Test Progress"
echo "================================="

# Find the latest results directory
RESULTS_DIR=$(ls -dt waf_test_results_* 2>/dev/null | head -1)

if [ -z "$RESULTS_DIR" ]; then
    echo "No test results directory found. Is the test running?"
    exit 1
fi

echo "Monitoring results in: $RESULTS_DIR"
echo ""

# Check if process is running
if pgrep -f "locust.*waf_load_test.py" > /dev/null; then
    echo "✓ Test is running"
    
    # Get process info
    ps aux | grep -E "locust.*waf_load_test.py" | grep -v grep | awk '{print "PID:", $2, "CPU:", $3"%", "MEM:", $4"%"}'
    
    # Calculate elapsed time
    START_TIME=$(stat -c %Y "$RESULTS_DIR" 2>/dev/null || stat -f %B "$RESULTS_DIR" 2>/dev/null)
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    ELAPSED_MIN=$((ELAPSED / 60))
    REMAINING_MIN=$((360 - ELAPSED_MIN))
    
    echo ""
    echo "Time elapsed: $ELAPSED_MIN minutes"
    echo "Time remaining: $REMAINING_MIN minutes (out of 360)"
    echo "Progress: $((ELAPSED_MIN * 100 / 360))%"
else
    echo "✗ Test is not running"
fi

echo ""
echo "Latest log entries:"
echo "-------------------"
if [ -f "$RESULTS_DIR/waf_test_6hr.log" ]; then
    tail -10 "$RESULTS_DIR/waf_test_6hr.log"
fi

# Check for CSV stats
if [ -f "$RESULTS_DIR/waf_test_stats.csv" ]; then
    echo ""
    echo "Current Statistics Summary:"
    echo "--------------------------"
    # Get header and last line
    head -1 "$RESULTS_DIR/waf_test_stats.csv"
    tail -1 "$RESULTS_DIR/waf_test_stats.csv"
fi

echo ""
echo "Press Ctrl+C to stop monitoring"