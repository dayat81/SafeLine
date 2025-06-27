# SafeLine Advanced Testing Execution Guide

## Quick Start

### 1. Deploy SafeLine Environment
```bash
# Run as root for system optimization
sudo ./deploy_advanced_safeline.sh
```

### 2. Execute High-Throughput Penetration Testing
```bash
# Basic execution (1000 RPS for 5 minutes)
./run_advanced_tests.sh

# Custom configuration
./run_advanced_tests.sh --rps 1200 --duration 600 --concurrent 600
```

### 3. Monitor Results
- **Grafana Dashboard**: http://localhost:3000 (admin/admin123)
- **Prometheus Metrics**: http://localhost:9090
- **Test Results**: `./test_results/` directory

## Detailed Execution Steps

### Phase 1: Environment Deployment (15-20 minutes)

```bash
# 1. System optimization and Docker configuration
sudo ./deploy_advanced_safeline.sh

# 2. Verify deployment
curl -k https://localhost:9443/api/open/health
curl http://localhost:80/
curl http://localhost:9090/api/v1/label/__name__/values
curl http://localhost:3000/api/health
```

**Expected Output:**
- SafeLine Management UI accessible on port 9443
- WAF proxy accessible on port 80
- Prometheus collecting metrics on port 9090
- Grafana dashboards on port 3000
- All containers running and healthy

### Phase 2: High-Throughput Testing (5-60 minutes)

```bash
# Execute comprehensive penetration testing
./run_advanced_tests.sh --rps 1000 --duration 300

# For extended testing
./run_advanced_tests.sh --rps 1500 --duration 1800 --concurrent 800

# For maximum throughput testing
./run_advanced_tests.sh --rps 2000 --duration 3600 --concurrent 1000
```

**Test Execution Flow:**
1. **Environment Verification** (30 seconds)
2. **Monitoring Startup** (30 seconds)
3. **Attack Campaign Execution** (Duration specified)
4. **Results Collection** (60 seconds)
5. **Report Generation** (60 seconds)

### Phase 3: Analysis and Reporting (5-10 minutes)

```bash
# View real-time monitoring (during test)
docker logs -f safeline-prometheus
docker logs -f safeline-grafana

# Access comprehensive results
ls -la test_results/
cat test_results/test_summary.txt
```

## Advanced Configuration Options

### Custom Attack Vectors

Edit `testing_framework/advanced_pentest_engine.py` to add custom attack patterns:

```python
# Add custom SQL injection patterns
'custom_sqli': [
    "1' AND (SELECT COUNT(*) FROM your_table)>0--",
    "1' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'--"
]

# Add custom XSS vectors
'custom_xss': [
    "<svg/onload=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>",
    "<iframe src=\"javascript:alert(document.cookie)\"></iframe>"
]
```

### Performance Tuning

Modify `compose_advanced.yaml` for higher performance:

```yaml
# Increase worker processes
environment:
  - TENGINE_WORKER_PROCESSES=16
  - TENGINE_WORKER_CONNECTIONS=8192
  - DETECTOR_THREADS=16

# Allocate more resources
deploy:
  resources:
    limits:
      memory: 16G
      cpus: '8'
```

### Monitoring Configuration

Enhance `monitoring/prometheus.yml` for custom metrics:

```yaml
# Add custom scrape targets
- job_name: 'custom-app'
  static_configs:
    - targets: ['your-app:8080']
  scrape_interval: 1s
```

## Test Scenarios

### Scenario 1: Basic Security Validation
**Objective**: Validate detection of common attacks
**Configuration**: 
```bash
./run_advanced_tests.sh --rps 100 --duration 300
```
**Expected Results**:
- 95%+ detection rate for OWASP Top 10
- <10ms average response time
- <5% CPU usage

### Scenario 2: Performance Benchmarking
**Objective**: Measure maximum sustainable throughput
**Configuration**:
```bash
./run_advanced_tests.sh --rps 1000 --duration 1800
```
**Expected Results**:
- 1000+ RPS sustained
- <50ms P95 response time
- <80% system resource usage

### Scenario 3: Stress Testing
**Objective**: Find breaking point and recovery behavior
**Configuration**:
```bash
./run_advanced_tests.sh --rps 2000 --duration 3600
```
**Expected Results**:
- Graceful degradation beyond capacity
- No service crashes
- Quick recovery when load decreases

### Scenario 4: Advanced Evasion Testing
**Objective**: Test sophisticated bypass techniques
**Configuration**:
Custom attack vectors with encoding, fragmentation, and timing attacks
**Expected Results**:
- <5% bypass rate for advanced techniques
- Consistent detection across evasion methods

## Troubleshooting

### Common Issues

#### 1. High Memory Usage
```bash
# Check container memory usage
docker stats

# Optimize PostgreSQL settings
docker exec safeline-pg-advanced psql -U safeline-ce -c "
ALTER SYSTEM SET shared_buffers = '1GB';
ALTER SYSTEM SET work_mem = '8MB';
SELECT pg_reload_conf();
"
```

#### 2. Network Connectivity Issues
```bash
# Check network configuration
docker network ls
docker network inspect safeline-advanced

# Restart networking
docker-compose -f compose_advanced.yaml restart
```

#### 3. Performance Bottlenecks
```bash
# Monitor system resources
htop
iotop
nethogs

# Check Docker resource limits
docker system df
docker system prune
```

#### 4. Detection Rule Issues
```bash
# Check rule loading
docker logs safeline-detector-advanced

# Validate rule syntax
docker exec safeline-detector-advanced lua -l /app/custom_rules/sql_injection_advanced.lua
```

### Log Analysis

```bash
# SafeLine logs
docker logs safeline-mgt-advanced
docker logs safeline-tengine-advanced
docker logs safeline-detector-advanced

# Test execution logs
tail -f test_results/monitor.log
tail -f test_results/pentest.log

# System logs
journalctl -u docker
dmesg | tail -50
```

## Performance Expectations

### Minimum System Requirements
- **CPU**: 8 cores, 3.0GHz+
- **RAM**: 16GB DDR4
- **Storage**: 100GB NVMe SSD
- **Network**: 1Gbps
- **OS**: Ubuntu 22.04 LTS

### Expected Performance Metrics

| Metric | Target | Excellent |
|--------|--------|-----------|
| Maximum RPS | 1000+ | 2000+ |
| P95 Response Time | <50ms | <20ms |
| Detection Rate | >95% | >99% |
| False Positive Rate | <1% | <0.1% |
| CPU Usage | <80% | <60% |
| Memory Usage | <70% | <50% |
| Uptime | 99.9% | 99.99% |

### Scaling Guidelines

#### For 2000+ RPS:
- Increase to 16+ CPU cores
- Allocate 32GB+ RAM
- Use multiple detector instances
- Implement load balancing

#### For 5000+ RPS:
- Deploy distributed architecture
- Use dedicated PostgreSQL cluster
- Implement horizontal scaling
- Add network optimization

## Security Considerations

### Safe Testing Practices
1. **Isolated Environment**: Use dedicated test networks
2. **Rate Limiting**: Implement safeguards against runaway tests
3. **Monitoring**: Continuous observation of system health
4. **Backup**: Ensure configuration and data backups
5. **Documentation**: Log all test parameters and results

### Production Readiness Checklist
- [ ] All tests pass with >95% detection rate
- [ ] Performance meets SLA requirements
- [ ] Security rules properly tuned
- [ ] Monitoring and alerting configured
- [ ] Backup and recovery procedures tested
- [ ] Documentation updated
- [ ] Team training completed

## Results Interpretation

### Detection Rate Analysis
- **>99%**: Excellent security coverage
- **95-99%**: Good coverage, minor tuning needed
- **90-95%**: Adequate coverage, review rules
- **<90%**: Poor coverage, major improvements needed

### Performance Analysis
- **Response Time**: Should remain stable under load
- **Error Rate**: Should stay below 0.1%
- **Resource Usage**: Should not exceed 80% sustained
- **Scalability**: Should handle 2x expected load

### Recommendations Generation
Based on test results, the system will automatically generate:
1. **Security Improvements**: Rule tuning suggestions
2. **Performance Optimizations**: Configuration adjustments
3. **Capacity Planning**: Resource scaling recommendations
4. **Operational Procedures**: Monitoring and maintenance guides

This comprehensive testing framework provides production-ready validation of SafeLine WAF capabilities under realistic high-load attack scenarios.