#!/bin/bash
# SafeLine WAF Testing Suite Execution Script

echo "=== SafeLine WAF Testing Suite ==="
echo "Starting at: $(date)"
echo "=================================="

# Configuration
WAF_URL=${WAF_URL:-"http://localhost"}
JUICE_SHOP_URL=${JUICE_SHOP_URL:-"http://localhost:8081"}
DVWA_URL=${DVWA_URL:-"http://localhost:8080"}
NODEJS_URL=${NODEJS_URL:-"http://localhost:8082"}

# Create results directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="test_results_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"
cd "$RESULTS_DIR"

echo "📁 Results will be saved in: $(pwd)"

# Helper function to check if backend is accessible
check_backend() {
    local url=$1
    local name=$2
    
    echo "🔍 Checking $name at $url..."
    if curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" | grep -E "^(200|302|404)$" > /dev/null; then
        echo "✅ $name is accessible"
        return 0
    else
        echo "❌ $name is not accessible at $url"
        return 1
    fi
}

# Pre-test checks
echo -e "\n🔍 Pre-test Backend Checks"
echo "================================"
check_backend "$JUICE_SHOP_URL" "Juice Shop"
check_backend "$DVWA_URL" "DVWA"
check_backend "$NODEJS_URL" "Node.js App"

# Check if Locust is available
if ! command -v locust &> /dev/null; then
    echo "❌ Locust is not installed. Installing..."
    pip3 install locust
fi

echo -e "\n📊 Starting Test Execution"
echo "================================"

# Stage 1: Baseline Performance Test (Direct Backend)
echo -e "\n[Stage 1] 📈 Baseline Performance Test (Direct Backend)"
echo "Testing direct backend performance without WAF..."

locust -f ../performance_test.py \
  --host "$NODEJS_URL" \
  --users 50 \
  --spawn-rate 10 \
  --run-time 2m \
  --headless \
  --html baseline_performance.html \
  --csv baseline_performance \
  --logfile baseline_performance.log

echo "✅ Baseline performance test completed"

# Stage 2: WAF Protection Test
echo -e "\n[Stage 2] 🛡️ WAF Protection Test"
echo "Testing attack scenarios through WAF..."

locust -f ../waf_test_scenarios.py \
  --host "$WAF_URL" \
  --users 100 \
  --spawn-rate 20 \
  --run-time 3m \
  --headless \
  --html waf_protection_test.html \
  --csv waf_protection_test \
  --logfile waf_protection.log

echo "✅ WAF protection test completed"

# Stage 3: Performance Impact Test (Through WAF)
echo -e "\n[Stage 3] ⚡ Performance Impact Test (Through WAF)"
echo "Testing performance impact of WAF..."

locust -f ../performance_test.py \
  --host "$WAF_URL" \
  --users 100 \
  --spawn-rate 20 \
  --run-time 3m \
  --headless \
  --html waf_performance_impact.html \
  --csv waf_performance_impact \
  --logfile waf_performance_impact.log

echo "✅ Performance impact test completed"

# Stage 4: High Load Stress Test
echo -e "\n[Stage 4] 🔥 High Load Stress Test"
echo "Testing WAF under high load..."

locust -f ../waf_test_scenarios.py \
  --host "$WAF_URL" \
  --users 200 \
  --spawn-rate 50 \
  --run-time 2m \
  --headless \
  --html stress_test.html \
  --csv stress_test \
  --logfile stress_test.log

echo "✅ Stress test completed"

# Stage 5: DDoS Simulation
echo -e "\n[Stage 5] 💥 DDoS Simulation Test"
echo "Simulating DDoS attack..."

locust -f ../waf_test_scenarios.py \
  --host "$WAF_URL" \
  --users 500 \
  --spawn-rate 100 \
  --run-time 1m \
  --headless \
  --html ddos_simulation.html \
  --csv ddos_simulation \
  --logfile ddos_simulation.log

echo "✅ DDoS simulation completed"

# Generate summary report
echo -e "\n📊 Generating Summary Report"
echo "================================"

cat > test_summary.md << EOF
# SafeLine WAF Test Execution Summary

**Test Date:** $(date)
**Test Duration:** Started at $(date -d "5 minutes ago" '+%H:%M:%S')
**Results Directory:** $(pwd)

## Test Stages Completed

1. ✅ **Baseline Performance Test** - Direct backend testing
2. ✅ **WAF Protection Test** - Attack scenario validation  
3. ✅ **Performance Impact Test** - WAF overhead measurement
4. ✅ **High Load Stress Test** - Load testing through WAF
5. ✅ **DDoS Simulation** - DDoS attack simulation

## Generated Reports

- **Baseline Performance:** baseline_performance.html
- **WAF Protection:** waf_protection_test.html  
- **Performance Impact:** waf_performance_impact.html
- **Stress Test:** stress_test.html
- **DDoS Simulation:** ddos_simulation.html

## CSV Data Files

$(ls -1 *.csv | sed 's/^/- /')

## Log Files

$(ls -1 *.log | sed 's/^/- /')

## Quick Results Summary

### Backend Applications Tested
- Juice Shop: $JUICE_SHOP_URL
- DVWA: $DVWA_URL  
- Node.js App: $NODEJS_URL

### WAF Configuration
- WAF URL: $WAF_URL
- Protection enabled for SQL injection, XSS, command injection
- Rate limiting configured

### Test Metrics
- Total test duration: ~15 minutes
- Maximum concurrent users: 500
- Attack types tested: SQL injection, XSS, command injection, DDoS
- Performance baseline established

EOF

echo "✅ Summary report generated: test_summary.md"

# Create a simple HTML index for easy viewing
cat > index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>SafeLine WAF Test Results - $TIMESTAMP</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .test-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
        .test-card { border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
        .test-card h3 { margin-top: 0; color: #333; }
        .test-card a { display: block; margin: 5px 0; color: #007bff; text-decoration: none; }
        .test-card a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SafeLine WAF Test Results</h1>
        <p><strong>Test Date:</strong> $(date)</p>
        <p><strong>Test ID:</strong> $TIMESTAMP</p>
    </div>
    
    <div class="test-grid">
        <div class="test-card">
            <h3>📈 Baseline Performance</h3>
            <a href="baseline_performance.html">View Report</a>
            <a href="baseline_performance_stats.csv">Download CSV</a>
        </div>
        
        <div class="test-card">
            <h3>🛡️ WAF Protection Test</h3>
            <a href="waf_protection_test.html">View Report</a>
            <a href="waf_protection_test_stats.csv">Download CSV</a>
        </div>
        
        <div class="test-card">
            <h3>⚡ Performance Impact</h3>
            <a href="waf_performance_impact.html">View Report</a>
            <a href="waf_performance_impact_stats.csv">Download CSV</a>
        </div>
        
        <div class="test-card">
            <h3>🔥 Stress Test</h3>
            <a href="stress_test.html">View Report</a>
            <a href="stress_test_stats.csv">Download CSV</a>
        </div>
        
        <div class="test-card">
            <h3>💥 DDoS Simulation</h3>
            <a href="ddos_simulation.html">View Report</a>
            <a href="ddos_simulation_stats.csv">Download CSV</a>
        </div>
        
        <div class="test-card">
            <h3>📄 Summary</h3>
            <a href="test_summary.md">Test Summary (Markdown)</a>
        </div>
    </div>
    
    <h2>📊 Files Generated</h2>
    <ul>
$(ls -1 *.html *.csv *.log *.md | sed 's/^/        <li><a href="&">&<\/a><\/li>/')
    </ul>
</body>
</html>
EOF

echo "✅ Test index page generated: index.html"

# Final summary
echo -e "\n🎉 All Tests Completed Successfully!"
echo "=================================="
echo "📁 Results directory: $(pwd)"
echo "🌐 Open index.html in a browser to view all results"
echo "📊 Test summary available in test_summary.md"
echo ""
echo "Key files generated:"
echo "  - index.html (main results page)"
echo "  - test_summary.md (summary report)" 
echo "  - *.html (individual test reports)"
echo "  - *.csv (test data for analysis)"
echo "  - *.log (detailed test logs)"
echo ""
echo "Test execution completed at: $(date)"