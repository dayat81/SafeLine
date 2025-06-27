# SafeLine WAF Performance and Security Test Plan

## Overview
This test plan demonstrates SafeLine WAF's security capabilities and performance capacity using a three-container architecture designed for comprehensive security testing and benchmarking.

## Architecture

```
┌─────────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│   Attack Source     │────▶│   SafeLine WAF   │────▶│  Vulnerable App    │
│   (Pentester)       │     │                  │     │    (Target)        │
└─────────────────────┘     └──────────────────┘     └────────────────────┘
   Container 1                 Container 2              Container 3
   - Kali Linux               - SafeLine Services     - DVWA/WebGoat
   - Attack Tools             - Detection Engine      - Vulnerable APIs
   - Load Testing             - Management UI         - Test Endpoints
```

## Container Specifications

### Container 1: Security Pentest & Load Testing
**Image**: Custom Kali Linux with performance tools
**Purpose**: Generate attack traffic and measure throughput
**Tools**:
- OWASP ZAP
- Burp Suite Community
- SQLMap
- Nikto
- Apache Bench (ab)
- JMeter
- Vegeta (high-throughput HTTP load testing)
- Custom attack scripts

**Resources**:
- CPU: 4 cores minimum
- RAM: 8GB
- Network: Bridge mode with rate limiting disabled

### Container 2: SafeLine WAF
**Image**: SafeLine official image
**Purpose**: Protect vulnerable application and demonstrate detection capabilities
**Configuration**:
- All protection modules enabled
- Real-time detection mode
- Full logging enabled
- Performance metrics collection

**Resources**:
- CPU: 4 cores minimum
- RAM: 8GB
- Storage: 20GB for logs

### Container 3: Vulnerable Web Application
**Image**: DVWA (Damn Vulnerable Web Application) + Custom APIs
**Purpose**: Provide realistic attack surface
**Components**:
- DVWA for web vulnerabilities
- Vulnerable REST APIs
- File upload endpoints
- SQL injection points
- XSS vulnerable forms

**Resources**:
- CPU: 2 cores
- RAM: 4GB

## Docker Compose Configuration

```yaml
version: '3.8'

services:
  pentester:
    build:
      context: ./pentester
      dockerfile: Dockerfile
    container_name: waf-pentester
    networks:
      - waf-test
    volumes:
      - ./test-results:/results
    depends_on:
      - safeline
    command: tail -f /dev/null

  safeline:
    image: safeline/safeline:latest
    container_name: waf-safeline
    ports:
      - "9443:9443"  # Management UI
      - "80:80"      # HTTP traffic
      - "443:443"    # HTTPS traffic
    networks:
      - waf-test
    environment:
      - MGT_PORT=9443
      - POSTGRES_PASSWORD=safeline123
    volumes:
      - ./safeline-data:/app/data
      - ./safeline-logs:/app/logs
    depends_on:
      - vulnerable-app

  vulnerable-app:
    build:
      context: ./vulnerable-app
      dockerfile: Dockerfile
    container_name: waf-target
    networks:
      - waf-test
    environment:
      - DVWA_SECURITY_LEVEL=low
    ports:
      - "8080:80"  # Direct access for baseline testing

networks:
  waf-test:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

## Test Scenarios

### Phase 1: Baseline Performance Testing
**Objective**: Establish performance baseline without attacks

1. **Direct Performance Test** (bypassing WAF)
   ```bash
   # From pentester container
   ab -n 10000 -c 100 http://vulnerable-app/
   vegeta attack -duration=30s -rate=1000 -targets=targets.txt | vegeta report
   ```

2. **WAF Performance Test** (through WAF)
   ```bash
   # Configure SafeLine to proxy to vulnerable-app
   ab -n 10000 -c 100 http://safeline/
   vegeta attack -duration=30s -rate=1000 -targets=targets-waf.txt | vegeta report
   ```

3. **Metrics to Collect**:
   - Requests per second
   - Response time (p50, p95, p99)
   - CPU/Memory usage
   - Connection handling

### Phase 2: Security Detection Testing
**Objective**: Validate WAF detection capabilities

1. **SQL Injection Testing**
   ```bash
   # Basic SQL injection
   sqlmap -u "http://safeline/vulnerabilities/sqli/?id=1" --batch --risk=3 --level=5
   
   # Time-based blind SQL injection
   sqlmap -u "http://safeline/api/user" --data="username=admin" --technique=T
   ```

2. **XSS Testing**
   ```bash
   # Reflected XSS
   python3 xss_fuzzer.py -u "http://safeline/vulnerabilities/xss_r/" -p "name"
   
   # Stored XSS
   curl -X POST http://safeline/comment -d "comment=<script>alert('XSS')</script>"
   ```

3. **Path Traversal & LFI**
   ```bash
   # Directory traversal
   nikto -h http://safeline -Plugins "traversal"
   
   # Local file inclusion
   curl "http://safeline/page?file=../../../../etc/passwd"
   ```

4. **Command Injection**
   ```bash
   # OS command injection
   curl -X POST http://safeline/ping -d "host=127.0.0.1;cat /etc/passwd"
   ```

5. **XXE Injection**
   ```bash
   # XML External Entity
   curl -X POST http://safeline/upload -H "Content-Type: text/xml" \
     -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
   ```

### Phase 3: Advanced Attack Scenarios
**Objective**: Test sophisticated attack patterns

1. **Rate Limiting & DDoS Protection**
   ```bash
   # Slowloris attack
   slowhttptest -c 500 -H -i 10 -r 200 -t GET -u http://safeline/ -x 24 -p 3

   # HTTP flood
   hping3 -S --flood -V -p 80 safeline
   ```

2. **Web Shell Upload**
   ```bash
   # Attempt to upload PHP shell
   curl -X POST -F "file=@webshell.php" http://safeline/upload
   curl -X POST -F "file=@webshell.php.jpg" http://safeline/upload
   ```

3. **Bot Detection**
   ```bash
   # Automated scanning
   nikto -h http://safeline -Format json -o nikto-results.json
   
   # Credential stuffing simulation
   hydra -L users.txt -P passwords.txt http://safeline/login
   ```

4. **Protocol Violations**
   ```bash
   # Malformed HTTP requests
   python3 http_fuzzer.py --target safeline --port 80 --malformed
   ```

### Phase 4: High-Throughput Attack Testing
**Objective**: Test WAF performance under attack load

1. **Mixed Attack Traffic**
   ```bash
   # Generate legitimate traffic
   vegeta attack -duration=60s -rate=500 -targets=legitimate.txt > legitimate.bin &
   
   # Simultaneous attack traffic
   python3 multi_attack.py --target safeline --threads 50 --duration 60
   ```

2. **Performance Metrics During Attack**:
   - Detection accuracy
   - False positive rate
   - Response time degradation
   - Resource utilization

## Step-by-Step Testing Process

### Setup Phase

1. **Build Test Environment**
   ```bash
   # Clone test repository
   git clone https://github.com/yourusername/safeline-test
   cd safeline-test
   
   # Build containers
   docker-compose build
   
   # Start services
   docker-compose up -d
   
   # Wait for services to initialize
   sleep 30
   ```

2. **Configure SafeLine**
   ```bash
   # Access SafeLine management UI
   # https://localhost:9443
   # Default credentials: admin/admin
   
   # Configure upstream to vulnerable-app
   # Enable all protection modules
   ```

3. **Verify Setup**
   ```bash
   # Test direct access to vulnerable app
   curl http://localhost:8080
   
   # Test access through WAF
   curl http://localhost
   ```

### Execution Phase

1. **Run Baseline Tests**
   ```bash
   docker exec -it waf-pentester bash
   cd /tests
   ./run_baseline.sh
   ```

2. **Run Security Tests**
   ```bash
   # Execute test suites
   ./run_security_tests.sh --output /results/security
   
   # Monitor WAF logs
   docker exec -it waf-safeline tail -f /app/logs/detection.log
   ```

3. **Run Performance Tests**
   ```bash
   # High-throughput testing
   ./run_performance_tests.sh --duration 300 --rate 5000
   ```

4. **Collect Results**
   ```bash
   # Generate report
   python3 generate_report.py --input /results --output waf_test_report.html
   ```

### Analysis Phase

1. **Security Metrics**:
   - Attack detection rate (%)
   - False positive rate (%)
   - Attack types detected
   - Response actions taken

2. **Performance Metrics**:
   - Maximum RPS handled
   - Latency impact (%)
   - Resource efficiency
   - Stability under load

3. **Comparison Baseline**:
   - Performance without WAF
   - Performance with WAF (idle)
   - Performance with WAF (under attack)

## Success Criteria

### Security
- ✓ Blocks 99%+ of OWASP Top 10 attacks
- ✓ < 0.1% false positive rate
- ✓ Detects sophisticated attack patterns
- ✓ Prevents data exfiltration attempts

### Performance
- ✓ < 5ms latency addition
- ✓ Handles 10,000+ RPS
- ✓ Maintains performance under attack
- ✓ < 50% CPU usage at peak load

### Reliability
- ✓ No crashes during 24-hour test
- ✓ Graceful degradation under overload
- ✓ Quick recovery after attack stops
- ✓ Accurate logging and alerting

## Test Scripts

### 1. Baseline Performance Script
```bash
#!/bin/bash
# run_baseline.sh

echo "Starting baseline performance tests..."

# Test direct access
echo "Testing direct access to vulnerable app..."
ab -n 10000 -c 100 -g direct_access.tsv http://vulnerable-app/ > direct_access.txt

# Test through WAF
echo "Testing through WAF..."
ab -n 10000 -c 100 -g waf_access.tsv http://safeline/ > waf_access.txt

# High concurrency test
echo "High concurrency test..."
vegeta attack -duration=60s -rate=1000 -targets=targets.txt | vegeta report > vegeta_report.txt

echo "Baseline tests completed!"
```

### 2. Security Test Script
```python
#!/usr/bin/env python3
# run_security_tests.py

import subprocess
import json
import time

def run_sql_injection_tests():
    print("Running SQL injection tests...")
    attacks = [
        "1' OR '1'='1",
        "1' UNION SELECT null,table_name FROM information_schema.tables--",
        "1'; DROP TABLE users--",
        "1' AND SLEEP(5)--"
    ]
    
    results = []
    for attack in attacks:
        response = subprocess.run([
            "curl", "-s", "-w", "%{http_code}",
            f"http://safeline/vulnerabilities/sqli/?id={attack}"
        ], capture_output=True, text=True)
        
        results.append({
            "attack": attack,
            "status_code": response.stdout[-3:],
            "blocked": response.stdout[-3:] in ["403", "406"]
        })
    
    return results

def run_xss_tests():
    print("Running XSS tests...")
    attacks = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')"
    ]
    
    results = []
    for attack in attacks:
        response = subprocess.run([
            "curl", "-s", "-w", "%{http_code}", "-X", "POST",
            "http://safeline/vulnerabilities/xss_s/",
            "-d", f"name={attack}"
        ], capture_output=True, text=True)
        
        results.append({
            "attack": attack,
            "status_code": response.stdout[-3:],
            "blocked": response.stdout[-3:] in ["403", "406"]
        })
    
    return results

def generate_report(results):
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sql_injection": results["sql"],
        "xss": results["xss"],
        "summary": {
            "total_attacks": len(results["sql"]) + len(results["xss"]),
            "blocked": sum(1 for r in results["sql"] + results["xss"] if r["blocked"])
        }
    }
    
    with open("/results/security_test_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"Detection rate: {report['summary']['blocked']}/{report['summary']['total_attacks']} "
          f"({report['summary']['blocked']/report['summary']['total_attacks']*100:.1f}%)")

if __name__ == "__main__":
    results = {
        "sql": run_sql_injection_tests(),
        "xss": run_xss_tests()
    }
    generate_report(results)
```

### 3. Load Testing Script
```python
#!/usr/bin/env python3
# high_throughput_test.py

import concurrent.futures
import requests
import time
import statistics

def make_request(url, attack=False):
    headers = {}
    params = {}
    
    if attack:
        # Include attack patterns in some requests
        params = {"id": "1' OR '1'='1"}
        headers = {"X-Forwarded-For": "' OR 1=1--"}
    
    try:
        start = time.time()
        response = requests.get(url, params=params, headers=headers, timeout=5)
        duration = time.time() - start
        return {
            "status": response.status_code,
            "duration": duration,
            "attack": attack
        }
    except Exception as e:
        return {
            "status": 0,
            "duration": 5,
            "attack": attack,
            "error": str(e)
        }

def run_load_test(url, duration=60, workers=100, attack_ratio=0.2):
    results = []
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        request_count = 0
        
        while time.time() - start_time < duration:
            # Determine if this should be an attack request
            is_attack = request_count % int(1/attack_ratio) == 0 if attack_ratio > 0 else False
            
            future = executor.submit(make_request, url, is_attack)
            futures.append(future)
            request_count += 1
            
            # Small delay to control request rate
            time.sleep(0.001)
        
        # Collect results
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    
    return analyze_results(results)

def analyze_results(results):
    total_requests = len(results)
    successful_requests = sum(1 for r in results if r["status"] == 200)
    blocked_attacks = sum(1 for r in results if r["attack"] and r["status"] in [403, 406])
    total_attacks = sum(1 for r in results if r["attack"])
    
    response_times = [r["duration"] for r in results if r["status"] > 0]
    
    analysis = {
        "total_requests": total_requests,
        "successful_requests": successful_requests,
        "failed_requests": total_requests - successful_requests,
        "total_attacks": total_attacks,
        "blocked_attacks": blocked_attacks,
        "attack_detection_rate": blocked_attacks / total_attacks * 100 if total_attacks > 0 else 0,
        "response_times": {
            "mean": statistics.mean(response_times),
            "median": statistics.median(response_times),
            "p95": statistics.quantiles(response_times, n=20)[18],
            "p99": statistics.quantiles(response_times, n=100)[98]
        }
    }
    
    return analysis

if __name__ == "__main__":
    import sys
    
    url = sys.argv[1] if len(sys.argv) > 1 else "http://safeline/"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    
    print(f"Starting high-throughput test against {url} for {duration} seconds...")
    results = run_load_test(url, duration=duration)
    
    print("\n=== Test Results ===")
    print(f"Total Requests: {results['total_requests']}")
    print(f"Successful: {results['successful_requests']}")
    print(f"Failed: {results['failed_requests']}")
    print(f"Attack Detection Rate: {results['attack_detection_rate']:.1f}%")
    print(f"\nResponse Times:")
    print(f"  Mean: {results['response_times']['mean']:.3f}s")
    print(f"  Median: {results['response_times']['median']:.3f}s")
    print(f"  95th percentile: {results['response_times']['p95']:.3f}s")
    print(f"  99th percentile: {results['response_times']['p99']:.3f}s")
```

## Reporting Template

### Executive Summary
- Overall security effectiveness score
- Performance impact assessment
- Key findings and recommendations

### Detailed Results
1. **Security Testing**
   - Attack types tested
   - Detection rates by category
   - False positive analysis

2. **Performance Testing**
   - Throughput metrics
   - Latency analysis
   - Resource utilization

3. **Reliability Testing**
   - Uptime during tests
   - Error rates
   - Recovery behavior

### Recommendations
- Configuration optimizations
- Detected weaknesses
- Performance tuning suggestions

## Conclusion
This comprehensive test plan provides a thorough evaluation of SafeLine WAF's capabilities, combining security effectiveness testing with high-throughput performance analysis. The three-container architecture ensures realistic testing conditions while maintaining isolation and reproducibility.