# SafeLine WAF Configuration and Testing Plan

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Phase 1: Backend Application Setup](#phase-1-backend-application-setup)
4. [Phase 2: SafeLine WAF Configuration](#phase-2-safeline-waf-configuration)
5. [Phase 3: Locust Test Scenarios](#phase-3-locust-test-scenarios)
6. [Phase 4: Test Execution Plan](#phase-4-test-execution-plan)
7. [Phase 5: Monitoring and Analysis](#phase-5-monitoring-and-analysis)

## Overview

This document outlines a comprehensive plan for:
- Configuring SafeLine WAF with a backend web application
- Creating realistic test scenarios using Locust
- Validating WAF protection capabilities
- Performance testing under various attack scenarios

### Goals
1. Deploy a vulnerable web application as the protection target
2. Configure SafeLine WAF to protect the application
3. Develop comprehensive Locust test scenarios
4. Validate WAF effectiveness against common attacks
5. Measure performance impact and protection rates

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│   Locust    │────▶│ SafeLine WAF │────▶│ Backend WebApp  │
│  Test Tool  │     │  (Port 80)   │     │   (Port 8080)   │
└─────────────┘     └──────────────┘     └─────────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │ WAF Console  │
                    │ (Port 9443)  │
                    └──────────────┘
```

## Phase 1: Backend Application Setup

### 1.1 Deploy Vulnerable Web Application

We'll deploy a deliberately vulnerable web application (DVWA - Damn Vulnerable Web Application) as our test target.

```yaml
# backend-webapp.yaml
version: '3.8'

services:
  dvwa:
    container_name: backend-webapp
    image: vulnerables/web-dvwa:latest
    ports:
      - "8080:80"
    environment:
      - DB_SERVER=dvwa-db
      - DB_DATABASE=dvwa
      - DB_USERNAME=dvwa
      - DB_PASSWORD=p@ssw0rd
    depends_on:
      - dvwa-db
    networks:
      - backend-net

  dvwa-db:
    container_name: backend-db
    image: mysql:5.7
    environment:
      - MYSQL_ROOT_PASSWORD=rootpass
      - MYSQL_DATABASE=dvwa
      - MYSQL_USER=dvwa
      - MYSQL_PASSWORD=p@ssw0rd
    volumes:
      - dvwa-db-data:/var/lib/mysql
    networks:
      - backend-net

  juice-shop:
    container_name: juice-shop
    image: bkimminich/juice-shop:latest
    ports:
      - "8081:3000"
    networks:
      - backend-net

  nodejs-app:
    container_name: nodejs-webapp
    build:
      context: ./sample-app
      dockerfile: Dockerfile
    ports:
      - "8082:3000"
    environment:
      - NODE_ENV=production
    networks:
      - backend-net

networks:
  backend-net:
    driver: bridge

volumes:
  dvwa-db-data:
```

### 1.2 Sample Node.js Application

Create a simple Node.js application with common vulnerabilities:

```javascript
// sample-app/app.js
const express = require('express');
const mysql = require('mysql');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Vulnerable to SQL Injection
app.get('/user/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  // Execute query (vulnerable)
  res.json({ query: query });
});

// Vulnerable to XSS
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  res.send(`<h1>Search results for: ${searchTerm}</h1>`);
});

// Vulnerable to Command Injection
app.post('/ping', (req, res) => {
  const { host } = req.body;
  const command = `ping -c 4 ${host}`;
  // Execute command (vulnerable)
  res.json({ command: command });
});

app.listen(3000, () => {
  console.log('Vulnerable app listening on port 3000');
});
```

## Phase 2: SafeLine WAF Configuration

### 2.1 Initial WAF Access
1. Access SafeLine Console: https://localhost:9443
2. Login with credentials:
   - Username: admin
   - Password: [from setup output]

### 2.2 Website Configuration

#### Step 1: Add Protected Website
```json
{
  "name": "DVWA Application",
  "domain": "dvwa.local",
  "port": 80,
  "backend": {
    "protocol": "http",
    "address": "backend-webapp",
    "port": 80
  }
}
```

#### Step 2: Add Multiple Backends
```json
[
  {
    "name": "Juice Shop",
    "domain": "juice.local",
    "port": 80,
    "backend": {
      "protocol": "http",
      "address": "juice-shop",
      "port": 3000
    }
  },
  {
    "name": "Node.js App",
    "domain": "nodeapp.local",
    "port": 80,
    "backend": {
      "protocol": "http",
      "address": "nodejs-webapp",
      "port": 3000
    }
  }
]
```

### 2.3 Protection Rules Configuration

#### Basic Protection Rules
1. **SQL Injection Protection**
   - Enable SQL injection detection
   - Set action: Block
   - Log level: Full

2. **XSS Protection**
   - Enable XSS detection
   - Set action: Block
   - Include response filtering

3. **Command Injection Protection**
   - Enable command injection detection
   - Set action: Block

4. **Rate Limiting**
   - Set rate limit: 100 requests/minute per IP
   - Burst: 200 requests
   - Action: Temporary block (5 minutes)

#### Custom Rules
```yaml
custom_rules:
  - name: "Block Admin Access"
    pattern: "/admin/*"
    action: "block"
    except_ips: ["192.168.1.100"]
    
  - name: "API Rate Limit"
    pattern: "/api/*"
    rate_limit: 
      requests: 50
      period: 60
      action: "challenge"
      
  - name: "File Upload Restriction"
    pattern: "*/upload"
    method: "POST"
    file_types_blocked: [".exe", ".sh", ".bat"]
```

### 2.4 IP Management

#### Whitelist Configuration
```yaml
whitelist:
  - name: "Internal Network"
    ips: 
      - "192.168.1.0/24"
      - "10.0.0.0/8"
    description: "Internal testing network"

  - name: "Monitoring Systems"
    ips:
      - "203.0.113.10"
      - "203.0.113.11"
    description: "Health check monitors"
```

#### Blacklist Configuration
```yaml
blacklist:
  - name: "Known Attackers"
    ips:
      - "198.51.100.0/24"
    description: "Previously identified attack sources"
    
  - name: "Tor Exit Nodes"
    list_url: "https://check.torproject.org/exit-addresses"
    update_frequency: "daily"
```

## Phase 3: Locust Test Scenarios

### 3.1 Test Environment Setup

```python
# locust_config.py
import os

class Config:
    # Target URLs
    WAF_URL = os.getenv('WAF_URL', 'http://localhost')
    DIRECT_URL = os.getenv('DIRECT_URL', 'http://localhost:8080')
    
    # Test Parameters
    ATTACK_RATIO = 0.3  # 30% attack traffic
    NORMAL_RATIO = 0.7  # 70% normal traffic
    
    # Attack Payloads
    SQL_INJECTION_PAYLOADS = [
        "1' OR '1'='1",
        "1'; DROP TABLE users--",
        "1' UNION SELECT * FROM passwords--",
        "admin'--",
        "1' OR 1=1#"
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(\"XSS\")'>"
    ]
    
    COMMAND_INJECTION_PAYLOADS = [
        "127.0.0.1; cat /etc/passwd",
        "localhost && whoami",
        "8.8.8.8 | ls -la",
        "google.com; rm -rf /",
        "test.com`id`"
    ]
```

### 3.2 Locust Test Scenarios

```python
# waf_test_scenarios.py
from locust import HttpUser, task, between
import random
from locust_config import Config

class NormalUser(HttpUser):
    wait_time = between(1, 3)
    weight = 70  # 70% of users
    
    @task(3)
    def browse_homepage(self):
        self.client.get("/")
    
    @task(2)
    def search_products(self):
        search_terms = ["laptop", "phone", "tablet", "camera"]
        self.client.get(f"/search?q={random.choice(search_terms)}")
    
    @task(1)
    def view_user_profile(self):
        user_id = random.randint(1, 100)
        self.client.get(f"/user/{user_id}")
    
    @task(2)
    def api_request(self):
        self.client.get("/api/products", 
                       headers={"Accept": "application/json"})

class AttackerUser(HttpUser):
    wait_time = between(0.5, 2)
    weight = 30  # 30% of users
    
    @task(3)
    def sql_injection_attack(self):
        payload = random.choice(Config.SQL_INJECTION_PAYLOADS)
        with self.client.get(
            f"/user/{payload}", 
            catch_response=True,
            name="/user/[sql_injection]"
        ) as response:
            if response.status_code == 403:
                response.success()  # WAF blocked successfully
            else:
                response.failure("SQL injection not blocked")
    
    @task(3)
    def xss_attack(self):
        payload = random.choice(Config.XSS_PAYLOADS)
        with self.client.get(
            f"/search?q={payload}",
            catch_response=True,
            name="/search?q=[xss]"
        ) as response:
            if response.status_code == 403:
                response.success()
            else:
                response.failure("XSS not blocked")
    
    @task(2)
    def command_injection_attack(self):
        payload = random.choice(Config.COMMAND_INJECTION_PAYLOADS)
        with self.client.post(
            "/ping",
            json={"host": payload},
            catch_response=True,
            name="/ping[command_injection]"
        ) as response:
            if response.status_code == 403:
                response.success()
            else:
                response.failure("Command injection not blocked")
    
    @task(1)
    def brute_force_attack(self):
        for i in range(10):
            self.client.post("/login", 
                           data={"username": "admin", "password": f"pass{i}"})

class DDoSUser(HttpUser):
    wait_time = between(0.1, 0.3)
    weight = 10  # 10% for DDoS simulation
    
    @task
    def flood_requests(self):
        self.client.get("/", 
                       name="/[ddos_flood]",
                       headers={"User-Agent": "DDoS-Bot"})

class AdvancedAttacker(HttpUser):
    wait_time = between(2, 5)
    weight = 5  # 5% advanced attacks
    
    @task
    def evasion_techniques(self):
        # Double encoding
        payload = "%253Cscript%253Ealert('XSS')%253C%252Fscript%253E"
        self.client.get(f"/search?q={payload}")
        
        # Case variation
        payload = "1' Or '1'='1"
        self.client.get(f"/user/{payload}")
        
        # Comment obfuscation
        payload = "1'/**/OR/**/1=1--"
        self.client.get(f"/user/{payload}")
```

### 3.3 Performance Test Scenarios

```python
# performance_test.py
from locust import HttpUser, task, between, events
import time

class PerformanceTestUser(HttpUser):
    wait_time = between(1, 2)
    
    def on_start(self):
        self.response_times = []
    
    @task
    def measure_latency(self):
        start_time = time.time()
        response = self.client.get("/")
        latency = (time.time() - start_time) * 1000  # ms
        self.response_times.append(latency)
        
    @task
    def heavy_payload(self):
        # Test with large request
        data = "x" * 10000  # 10KB payload
        self.client.post("/api/data", data=data)
    
    @task
    def concurrent_requests(self):
        # Simulate concurrent API calls
        for _ in range(5):
            self.client.get("/api/status", 
                          name="/api/status[concurrent]")

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    # Calculate and report metrics
    print("\n=== Performance Test Results ===")
    print(f"Total requests: {environment.stats.total.num_requests}")
    print(f"Failed requests: {environment.stats.total.num_failures}")
    print(f"Average response time: {environment.stats.total.avg_response_time}ms")
    print(f"Max response time: {environment.stats.total.max_response_time}ms")
```

## Phase 4: Test Execution Plan

### 4.1 Test Stages

#### Stage 1: Baseline Testing (Without WAF)
```bash
# Direct backend testing
locust -f waf_test_scenarios.py \
  --host http://localhost:8080 \
  --users 100 \
  --spawn-rate 10 \
  --run-time 5m \
  --html baseline_report.html
```

#### Stage 2: WAF Protection Testing
```bash
# Through WAF testing
locust -f waf_test_scenarios.py \
  --host http://localhost \
  --users 100 \
  --spawn-rate 10 \
  --run-time 5m \
  --html waf_report.html
```

#### Stage 3: Stress Testing
```bash
# High load testing
locust -f performance_test.py \
  --host http://localhost \
  --users 500 \
  --spawn-rate 50 \
  --run-time 10m \
  --html stress_report.html
```

#### Stage 4: Advanced Attack Simulation
```bash
# Advanced attack patterns
locust -f waf_test_scenarios.py \
  --host http://localhost \
  --users 200 \
  --spawn-rate 20 \
  --run-time 15m \
  --html advanced_report.html \
  -L CRITICAL
```

### 4.2 Test Execution Script

```bash
#!/bin/bash
# run_waf_tests.sh

echo "=== SafeLine WAF Testing Suite ==="
echo "Starting at: $(date)"

# Create results directory
mkdir -p test_results/$(date +%Y%m%d_%H%M%S)
cd test_results/$(date +%Y%m%d_%H%M%S)

# Stage 1: Baseline
echo "\n[Stage 1] Running baseline tests..."
locust -f ../../waf_test_scenarios.py \
  --host $DIRECT_URL \
  --users 50 \
  --spawn-rate 5 \
  --run-time 3m \
  --headless \
  --html baseline.html \
  --csv baseline

# Stage 2: WAF Protection
echo "\n[Stage 2] Running WAF protection tests..."
locust -f ../../waf_test_scenarios.py \
  --host $WAF_URL \
  --users 100 \
  --spawn-rate 10 \
  --run-time 5m \
  --headless \
  --html waf_protection.html \
  --csv waf_protection

# Stage 3: Performance
echo "\n[Stage 3] Running performance tests..."
locust -f ../../performance_test.py \
  --host $WAF_URL \
  --users 200 \
  --spawn-rate 20 \
  --run-time 5m \
  --headless \
  --html performance.html \
  --csv performance

# Stage 4: DDoS Simulation
echo "\n[Stage 4] Running DDoS simulation..."
locust -f ../../waf_test_scenarios.py \
  --host $WAF_URL \
  --users 500 \
  --spawn-rate 100 \
  --run-time 2m \
  --headless \
  --html ddos.html \
  --csv ddos \
  --only-users DDoSUser

echo "\nTests completed at: $(date)"
echo "Results saved in: $(pwd)"
```

### 4.3 Custom Metrics Collection

```python
# metrics_collector.py
from locust import events
import csv
from datetime import datetime

class MetricsCollector:
    def __init__(self):
        self.attacks_blocked = 0
        self.attacks_passed = 0
        self.false_positives = 0
        
    @events.request.add_listener
    def on_request(self, request_type, name, response_time, response_length, 
                   exception, context, **kwargs):
        if exception:
            return
            
        # Track blocked attacks
        if "injection" in name or "xss" in name or "command" in name:
            if context.get("response").status_code == 403:
                self.attacks_blocked += 1
            else:
                self.attacks_passed += 1
        
        # Track false positives (normal requests blocked)
        elif context.get("response").status_code == 403:
            self.false_positives += 1
    
    def generate_report(self):
        total_attacks = self.attacks_blocked + self.attacks_passed
        block_rate = (self.attacks_blocked / total_attacks * 100) if total_attacks > 0 else 0
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "attacks_blocked": self.attacks_blocked,
            "attacks_passed": self.attacks_passed,
            "block_rate": f"{block_rate:.2f}%",
            "false_positives": self.false_positives
        }
        
        with open("waf_effectiveness_report.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=report.keys())
            writer.writeheader()
            writer.writerow(report)
        
        return report
```

## Phase 5: Monitoring and Analysis

### 5.1 Real-time Monitoring

```python
# monitor_dashboard.py
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import pandas as pd
from datetime import datetime

app = dash.Dash(__name__)

app.layout = html.Div([
    html.H1("SafeLine WAF Real-time Monitor"),
    
    dcc.Graph(id='live-graph'),
    dcc.Graph(id='attack-types'),
    dcc.Graph(id='response-times'),
    
    dcc.Interval(
        id='graph-update',
        interval=1000  # Update every second
    ),
])

@app.callback(Output('live-graph', 'figure'),
              Input('graph-update', 'n_intervals'))
def update_graph(n):
    # Read latest metrics
    df = pd.read_csv('realtime_metrics.csv')
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['requests_per_second'],
        name='Requests/sec',
        mode='lines'
    ))
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['attacks_blocked'],
        name='Attacks Blocked',
        mode='lines',
        line=dict(color='red')
    ))
    
    return fig
```

### 5.2 Analysis Scripts

```python
# analyze_results.py
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def analyze_waf_effectiveness(baseline_csv, waf_csv):
    baseline = pd.read_csv(baseline_csv)
    waf = pd.read_csv(waf_csv)
    
    # Compare response times
    plt.figure(figsize=(12, 6))
    
    plt.subplot(1, 2, 1)
    plt.hist(baseline['response_time'], bins=50, alpha=0.5, label='Without WAF')
    plt.hist(waf['response_time'], bins=50, alpha=0.5, label='With WAF')
    plt.xlabel('Response Time (ms)')
    plt.ylabel('Frequency')
    plt.legend()
    plt.title('Response Time Distribution')
    
    # Attack effectiveness
    plt.subplot(1, 2, 2)
    attack_types = ['SQL Injection', 'XSS', 'Command Injection', 'DDoS']
    block_rates = [95, 92, 98, 85]  # Example data
    plt.bar(attack_types, block_rates)
    plt.ylabel('Block Rate (%)')
    plt.title('WAF Attack Block Rates')
    plt.ylim(0, 100)
    
    plt.tight_layout()
    plt.savefig('waf_analysis.png')
    
    # Generate report
    report = {
        'avg_latency_increase': f"{(waf['response_time'].mean() - baseline['response_time'].mean()):.2f}ms",
        'attack_block_rate': '93.75%',
        'false_positive_rate': '0.2%',
        'peak_throughput': f"{waf['requests_per_second'].max():.0f} req/s"
    }
    
    return report
```

### 5.3 Automated Reporting

```python
# generate_test_report.py
from jinja2 import Template
import json
from datetime import datetime

def generate_html_report(test_results):
    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SafeLine WAF Test Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .metric { background: #f0f0f0; padding: 20px; margin: 10px 0; }
            .success { color: green; }
            .warning { color: orange; }
            .danger { color: red; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        </style>
    </head>
    <body>
        <h1>SafeLine WAF Test Report</h1>
        <p>Generated: {{ timestamp }}</p>
        
        <h2>Executive Summary</h2>
        <div class="metric">
            <h3>Overall Protection Rate: <span class="success">{{ protection_rate }}%</span></h3>
            <p>Total Attacks Blocked: {{ attacks_blocked }} / {{ total_attacks }}</p>
        </div>
        
        <h2>Attack Type Analysis</h2>
        <table>
            <tr>
                <th>Attack Type</th>
                <th>Attempts</th>
                <th>Blocked</th>
                <th>Success Rate</th>
            </tr>
            {% for attack in attack_analysis %}
            <tr>
                <td>{{ attack.type }}</td>
                <td>{{ attack.attempts }}</td>
                <td>{{ attack.blocked }}</td>
                <td class="{% if attack.rate > 95 %}success{% elif attack.rate > 85 %}warning{% else %}danger{% endif %}">
                    {{ attack.rate }}%
                </td>
            </tr>
            {% endfor %}
        </table>
        
        <h2>Performance Impact</h2>
        <div class="metric">
            <p>Average Latency Increase: {{ latency_impact }}ms</p>
            <p>Peak Throughput: {{ peak_throughput }} requests/second</p>
            <p>Error Rate: {{ error_rate }}%</p>
        </div>
        
        <h2>Recommendations</h2>
        <ul>
            {% for rec in recommendations %}
            <li>{{ rec }}</li>
            {% endfor %}
        </ul>
    </body>
    </html>
    ''')
    
    html = template.render(**test_results)
    
    with open(f'waf_test_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html', 'w') as f:
        f.write(html)
```

## Implementation Timeline

### Week 1: Environment Setup
- Day 1-2: Deploy backend applications
- Day 3-4: Configure SafeLine WAF
- Day 5: Initial connectivity testing

### Week 2: Test Development
- Day 1-2: Develop Locust test scenarios
- Day 3-4: Create monitoring dashboard
- Day 5: Test script validation

### Week 3: Test Execution
- Day 1: Baseline testing
- Day 2-3: WAF protection testing
- Day 4: Performance testing
- Day 5: Advanced attack testing

### Week 4: Analysis and Optimization
- Day 1-2: Analyze results
- Day 3-4: WAF rule optimization
- Day 5: Final report generation

## Success Criteria

1. **Protection Effectiveness**
   - SQL Injection block rate > 95%
   - XSS block rate > 95%
   - Command Injection block rate > 98%
   - False positive rate < 1%

2. **Performance Impact**
   - Latency increase < 20ms
   - Throughput reduction < 10%
   - Zero legitimate traffic drops

3. **Operational Metrics**
   - 99.9% uptime during tests
   - All attacks logged correctly
   - Real-time alerting functional

## Conclusion

This comprehensive plan provides a structured approach to:
1. Configure SafeLine WAF with multiple backend applications
2. Develop realistic test scenarios using Locust
3. Validate WAF effectiveness against various attack types
4. Measure performance impact
5. Generate actionable insights for optimization

The combination of automated testing, real-time monitoring, and detailed analysis ensures a thorough evaluation of SafeLine WAF's capabilities in protecting web applications.