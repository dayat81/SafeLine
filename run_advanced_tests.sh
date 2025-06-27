#!/bin/bash

# Advanced SafeLine WAF Testing Execution Script
# Orchestrates high-throughput penetration testing and monitoring

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
TARGET_URL="http://localhost"
TEST_DURATION=300  # 5 minutes default
TARGET_RPS=1000
MAX_CONCURRENT=500
OUTPUT_DIR="./test_results"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET_URL="$2"
            shift 2
            ;;
        --duration)
            TEST_DURATION="$2"
            shift 2
            ;;
        --rps)
            TARGET_RPS="$2"
            shift 2
            ;;
        --concurrent)
            MAX_CONCURRENT="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --target URL        Target URL (default: http://localhost)"
            echo "  --duration SECONDS  Test duration in seconds (default: 300)"
            echo "  --rps NUMBER        Target requests per second (default: 1000)"
            echo "  --concurrent NUMBER Max concurrent connections (default: 500)"
            echo "  --output DIR        Output directory (default: ./test_results)"
            echo "  --help              Show this help"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Verify environment
verify_environment() {
    log "Verifying test environment..."
    
    # Check if SafeLine is running
    if ! curl -k -s -f https://localhost:9443/api/open/health >/dev/null 2>&1; then
        log_error "SafeLine management service is not accessible"
        log "Please run: sudo ./deploy_advanced_safeline.sh"
        exit 1
    fi
    
    # Check if target is accessible
    if ! curl -s -f "$TARGET_URL" >/dev/null 2>&1; then
        log_error "Target URL is not accessible: $TARGET_URL"
        exit 1
    fi
    
    # Check if Prometheus is running
    if ! curl -s -f http://localhost:9090/api/v1/label/__name__/values >/dev/null 2>&1; then
        log_error "Prometheus is not accessible"
        exit 1
    fi
    
    # Check if Python dependencies are available
    if ! python3 -c "import aiohttp, pandas, matplotlib" 2>/dev/null; then
        log_error "Required Python dependencies not found"
        log "Installing dependencies..."
        pip3 install aiohttp pandas matplotlib seaborn psutil docker requests
    fi
    
    log_success "Environment verification completed"
}

# Prepare test environment
prepare_test() {
    log "Preparing test environment..."
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Ensure load tester container is ready
    if ! docker ps | grep -q "advanced-load-tester"; then
        log_error "Load tester container not found"
        exit 1
    fi
    
    # Copy test scripts to container
    docker cp ./testing_framework/. advanced-load-tester:/app/
    docker exec advanced-load-tester pip install aiohttp pandas numpy matplotlib seaborn psutil docker requests beautifulsoup4
    
    log_success "Test environment prepared"
}

# Start monitoring
start_monitoring() {
    log "Starting real-time monitoring..."
    
    # Start monitoring in background
    python3 testing_framework/load_test_monitor.py > "$OUTPUT_DIR/monitor.log" 2>&1 &
    MONITOR_PID=$!
    
    # Wait for monitor to initialize
    sleep 10
    
    log_success "Monitoring started (PID: $MONITOR_PID)"
    echo $MONITOR_PID > "$OUTPUT_DIR/monitor.pid"
}

# Execute penetration tests
execute_pentest() {
    log "Executing advanced penetration testing campaign..."
    log "Parameters:"
    log "  Target: $TARGET_URL"
    log "  Duration: $TEST_DURATION seconds"
    log "  Target RPS: $TARGET_RPS"
    log "  Max Concurrent: $MAX_CONCURRENT"
    
    # Start timestamp
    echo "$(date -Iseconds)" > "$OUTPUT_DIR/test_start.timestamp"
    
    # Execute in load tester container
    docker exec advanced-load-tester python3 /app/advanced_pentest_engine.py \
        --target "$TARGET_URL" \
        --rps "$TARGET_RPS" \
        --duration "$TEST_DURATION" \
        --concurrent "$MAX_CONCURRENT" \
        --output "pentest_results_$(date +%Y%m%d_%H%M%S).json"
    
    # End timestamp
    echo "$(date -Iseconds)" > "$OUTPUT_DIR/test_end.timestamp"
    
    log_success "Penetration testing completed"
}

# Stop monitoring
stop_monitoring() {
    log "Stopping monitoring..."
    
    if [ -f "$OUTPUT_DIR/monitor.pid" ]; then
        MONITOR_PID=$(cat "$OUTPUT_DIR/monitor.pid")
        if kill -0 $MONITOR_PID 2>/dev/null; then
            kill -INT $MONITOR_PID
            sleep 5
            if kill -0 $MONITOR_PID 2>/dev/null; then
                kill -KILL $MONITOR_PID
            fi
        fi
        rm -f "$OUTPUT_DIR/monitor.pid"
    fi
    
    log_success "Monitoring stopped"
}

# Collect results
collect_results() {
    log "Collecting test results..."
    
    # Copy results from containers
    docker cp advanced-load-tester:/results/. "$OUTPUT_DIR/"
    
    # Generate timestamp report
    if [ -f "$OUTPUT_DIR/test_start.timestamp" ] && [ -f "$OUTPUT_DIR/test_end.timestamp" ]; then
        start_time=$(cat "$OUTPUT_DIR/test_start.timestamp")
        end_time=$(cat "$OUTPUT_DIR/test_end.timestamp")
        
        cat > "$OUTPUT_DIR/test_summary.txt" << EOF
=== SafeLine Advanced Penetration Test Summary ===

Test Configuration:
  Target URL: $TARGET_URL
  Duration: $TEST_DURATION seconds
  Target RPS: $TARGET_RPS
  Max Concurrent: $MAX_CONCURRENT

Test Timeline:
  Start Time: $start_time
  End Time: $end_time
  
Results Location: $OUTPUT_DIR
EOF
    fi
    
    log_success "Results collected in: $OUTPUT_DIR"
}

# Generate final report
generate_report() {
    log "Generating comprehensive test report..."
    
    # Create report generation script
    cat > "$OUTPUT_DIR/generate_final_report.py" << 'EOF'
#!/usr/bin/env python3

import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import glob
import os

def generate_comprehensive_report():
    print("=== SafeLine WAF Advanced Test Report ===")
    
    # Find result files
    result_files = glob.glob("/results/*pentest_results*.json")
    monitor_files = glob.glob("/results/*monitor*.json")
    
    if result_files:
        with open(result_files[0], 'r') as f:
            pentest_data = json.load(f)
        
        results = pentest_data.get('results', [])
        metadata = pentest_data.get('metadata', {})
        
        print(f"\nTest Execution Summary:")
        print(f"  Total Attacks: {len(results):,}")
        print(f"  Target URL: {metadata.get('target_url', 'Unknown')}")
        print(f"  Target RPS: {metadata.get('max_rps', 'Unknown')}")
        
        # Analysis
        if results:
            df = pd.DataFrame(results)
            
            blocked_count = df['blocked'].sum()
            total_count = len(df)
            detection_rate = (blocked_count / total_count * 100) if total_count > 0 else 0
            
            avg_response_time = df['response_time'].mean() * 1000  # Convert to ms
            
            print(f"\nSecurity Analysis:")
            print(f"  Detection Rate: {detection_rate:.1f}%")
            print(f"  Blocked Attacks: {blocked_count:,}")
            print(f"  Bypassed Attacks: {total_count - blocked_count:,}")
            
            print(f"\nPerformance Analysis:")
            print(f"  Average Response Time: {avg_response_time:.2f}ms")
            print(f"  P95 Response Time: {df['response_time'].quantile(0.95)*1000:.2f}ms")
            print(f"  P99 Response Time: {df['response_time'].quantile(0.99)*1000:.2f}ms")
            
            # Attack type breakdown
            attack_breakdown = df.groupby('attack_type')['blocked'].agg(['count', 'sum', 'mean'])
            attack_breakdown['detection_rate'] = attack_breakdown['mean'] * 100
            
            print(f"\nAttack Type Analysis:")
            for attack_type, stats in attack_breakdown.iterrows():
                print(f"  {attack_type}:")
                print(f"    Total: {stats['count']}")
                print(f"    Blocked: {stats['sum']}")
                print(f"    Detection Rate: {stats['detection_rate']:.1f}%")
            
            # Status code distribution
            status_dist = df['status_code'].value_counts()
            print(f"\nStatus Code Distribution:")
            for status, count in status_dist.head(10).items():
                print(f"  {status}: {count:,}")
    
    print(f"\nTest completed at: {datetime.now()}")
    print(f"Full results available in: /results/")

if __name__ == "__main__":
    generate_comprehensive_report()
EOF
    
    # Execute report generation in container
    docker cp "$OUTPUT_DIR/generate_final_report.py" advanced-load-tester:/app/
    docker exec advanced-load-tester python3 /app/generate_final_report.py
    
    log_success "Comprehensive report generated"
}

# Cleanup function
cleanup() {
    log "Cleaning up..."
    stop_monitoring
}

# Set trap for cleanup
trap cleanup EXIT

# Main execution
main() {
    log "=== SafeLine Advanced Penetration Testing ==="
    log "Starting comprehensive WAF testing campaign"
    
    verify_environment
    prepare_test
    start_monitoring
    
    log "Test will run for $TEST_DURATION seconds at $TARGET_RPS RPS"
    log "Starting in 10 seconds... (Ctrl+C to cancel)"
    sleep 10
    
    execute_pentest
    
    log "Waiting for monitoring to collect final metrics..."
    sleep 30
    
    stop_monitoring
    collect_results
    generate_report
    
    log_success "=== Advanced Testing Campaign Completed ==="
    log_success "Results available in: $OUTPUT_DIR"
    log_success "View monitoring dashboard: http://localhost:3000"
    log_success "View Prometheus metrics: http://localhost:9090"
}

# Execute main function
main "$@"