#!/bin/bash

# Advanced SafeLine Deployment Script for High-Throughput Testing
# Optimized for 1000+ RPS penetration testing

set -euo pipefail

# Configuration
SAFELINE_DIR="/opt/safeline"
POSTGRES_PASSWORD=$(openssl rand -base64 32)
SUBNET_PREFIX="172.22.222"
IMAGE_TAG="latest"
MGT_PORT="9443"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# System optimization for high performance
optimize_system() {
    log "Optimizing system for high-performance testing..."
    
    # Kernel parameters for high throughput
    cat >> /etc/sysctl.conf << EOF
# SafeLine High-Performance Tuning
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_max_tw_buckets = 400000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
fs.file-max = 1000000
fs.nr_open = 1000000
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF
    
    sysctl -p
    
    # Docker optimization
    cat > /etc/docker/daemon.json << EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "default-ulimits": {
        "nofile": {
            "Hard": 65536,
            "Name": "nofile",
            "Soft": 65536
        }
    }
}
EOF
    
    systemctl restart docker
    log_success "System optimization completed"
}

# Create directory structure
setup_directories() {
    log "Setting up directory structure..."
    
    mkdir -p $SAFELINE_DIR/{resources/{mgt,postgres/data,sock},logs/nginx}
    mkdir -p ./advanced_rules
    mkdir -p ./tengine_config
    mkdir -p ./detection_rules
    mkdir -p ./target_apps/{web1,api1}
    mkdir -p ./test_results
    mkdir -p ./monitoring/{grafana/{dashboards,provisioning/dashboards,provisioning/datasources},rules}
    
    # Set proper permissions
    chmod -R 755 $SAFELINE_DIR
    
    log_success "Directory structure created"
}

# Create advanced detection rules
create_detection_rules() {
    log "Creating advanced detection rules..."
    
    # SQL Injection rules
    cat > ./advanced_rules/sql_injection_advanced.lua << 'EOF'
-- Advanced SQL Injection Detection Rules
local M = {}

M.patterns = {
    -- Union-based injection patterns
    {pattern = "union\\s+.*select", severity = "high", action = "block"},
    {pattern = "\\bunion\\b.*\\bselect\\b", severity = "high", action = "block"},
    
    -- Boolean-based blind injection
    {pattern = "\\s+(and|or)\\s+\\d+\\s*=\\s*\\d+", severity = "medium", action = "log"},
    {pattern = "(and|or)\\s+.*\\s*(=|<|>)\\s*.*", severity = "medium", action = "monitor"},
    
    -- Time-based blind injection
    {pattern = "(sleep|benchmark|waitfor)\\s*\\(", severity = "high", action = "block"},
    {pattern = "pg_sleep|delay|sleep\\(", severity = "high", action = "block"},
    
    -- Error-based injection
    {pattern = "(extractvalue|updatexml|exp)\\s*\\(", severity = "high", action = "block"},
    {pattern = "convert\\s*\\(.*using", severity = "medium", action = "log"},
    
    -- Advanced evasion techniques
    {pattern = "\\/\\*.*\\*\\/", severity = "medium", action = "log"},
    {pattern = "0x[0-9a-f]+", severity = "medium", action = "log"},
}

return M
EOF

    # XSS rules
    cat > ./advanced_rules/xss_advanced.lua << 'EOF'
-- Advanced XSS Detection Rules
local M = {}

M.patterns = {
    -- Script tag variants
    {pattern = "<script[^>]*>", severity = "high", action = "block"},
    {pattern = "<\\/script>", severity = "high", action = "block"},
    {pattern = "javascript:", severity = "high", action = "block"},
    
    -- Event handler injection
    {pattern = "on(load|click|error|mouseover)\\s*=", severity = "high", action = "block"},
    {pattern = "on\\w+\\s*=\\s*[\"']?[^\"']*[\"']?", severity = "medium", action = "log"},
    
    -- Data URIs and protocol handlers
    {pattern = "data:\\s*[^,]*,", severity = "medium", action = "log"},
    {pattern = "(vbscript|livescript|mocha):", severity = "high", action = "block"},
    
    -- DOM-based XSS patterns
    {pattern = "document\\.(write|writeln|cookie)", severity = "medium", action = "log"},
    {pattern = "window\\.(location|open)", severity = "medium", action = "log"},
    
    -- Encoding evasion
    {pattern = "&#x?[0-9a-f]+;", severity = "low", action = "decode"},
    {pattern = "%[0-9a-f]{2}", severity = "low", action = "decode"},
}

return M
EOF

    log_success "Advanced detection rules created"
}

# Create target applications
create_target_apps() {
    log "Creating target applications..."
    
    # Web application 1
    cat > ./target_apps/web1/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SafeLine Test Target 1</title>
</head>
<body>
    <h1>Web Application Target 1</h1>
    <p>This is a test target for SafeLine WAF penetration testing.</p>
    
    <h2>Test Endpoints:</h2>
    <ul>
        <li><a href="/api/user?id=1">User API</a></li>
        <li><a href="/search?q=test">Search</a></li>
        <li><a href="/comment">Comment Form</a></li>
        <li><a href="/file?path=test.txt">File Access</a></li>
    </ul>
    
    <h2>Vulnerable Parameters:</h2>
    <ul>
        <li>SQL Injection: <code>/api/user?id=1' OR '1'='1</code></li>
        <li>XSS: <code>/search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
        <li>Path Traversal: <code>/file?path=../../../../etc/passwd</code></li>
        <li>Command Injection: <code>/ping?host=127.0.0.1; cat /etc/passwd</code></li>
    </ul>
    
    <form method="POST" action="/comment">
        <label>Comment: <input type="text" name="comment"></label>
        <button type="submit">Submit</button>
    </form>
</body>
</html>
EOF

    # API application nginx config
    cat > ./target_apps/api1/nginx.conf << 'EOF'
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    server {
        listen 80;
        root /usr/share/nginx/html;
        
        location /api/ {
            add_header Content-Type application/json;
            return 200 '{"status":"ok","endpoint":"$uri","args":"$args"}';
        }
        
        location /health {
            return 200 'OK';
        }
        
        location / {
            return 200 'API Target Application';
        }
    }
}
EOF

    log_success "Target applications created"
}

# Create Grafana configuration
create_grafana_config() {
    log "Creating Grafana configuration..."
    
    # Datasource configuration
    cat > ./monitoring/grafana/provisioning/datasources/prometheus.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://safeline-prometheus:9090
    isDefault: true
    editable: true
EOF

    # Dashboard provisioning
    cat > ./monitoring/grafana/provisioning/dashboards/dashboard.yml << 'EOF'
apiVersion: 1

providers:
  - name: 'SafeLine Dashboards'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
EOF

    # Main SafeLine dashboard
    cat > ./monitoring/grafana/dashboards/safeline_main.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "SafeLine WAF Advanced Monitoring",
    "tags": ["safeline", "waf", "security"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Request Rate (RPS)",
        "type": "graph",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "targets": [
          {
            "expr": "rate(safeline_requests_total[1m])",
            "legendFormat": "Total RPS"
          },
          {
            "expr": "rate(safeline_requests_blocked_total[1m])",
            "legendFormat": "Blocked RPS"
          }
        ]
      },
      {
        "id": 2,
        "title": "Response Time Distribution",
        "type": "graph",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(safeline_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P50"
          },
          {
            "expr": "histogram_quantile(0.95, rate(safeline_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P95"
          },
          {
            "expr": "histogram_quantile(0.99, rate(safeline_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P99"
          }
        ]
      },
      {
        "id": 3,
        "title": "Attack Detection by Type",
        "type": "graph",
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8},
        "targets": [
          {
            "expr": "rate(safeline_detections_total{attack_type=\"sql_injection\"}[1m])",
            "legendFormat": "SQL Injection"
          },
          {
            "expr": "rate(safeline_detections_total{attack_type=\"xss\"}[1m])",
            "legendFormat": "XSS"
          },
          {
            "expr": "rate(safeline_detections_total{attack_type=\"command_injection\"}[1m])",
            "legendFormat": "Command Injection"
          }
        ]
      }
    ],
    "time": {"from": "now-1h", "to": "now"},
    "refresh": "5s"
  }
}
EOF

    log_success "Grafana configuration created"
}

# Set environment variables
set_environment() {
    log "Setting environment variables..."
    
    cat > .env << EOF
SAFELINE_DIR=$SAFELINE_DIR
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
SUBNET_PREFIX=$SUBNET_PREFIX
IMAGE_TAG=$IMAGE_TAG
MGT_PORT=$MGT_PORT
EOF

    export SAFELINE_DIR POSTGRES_PASSWORD SUBNET_PREFIX IMAGE_TAG MGT_PORT
    
    log_success "Environment variables set"
}

# Deploy SafeLine
deploy_safeline() {
    log "Deploying SafeLine advanced environment..."
    
    # Pull images
    log "Pulling Docker images..."
    docker-compose -f compose_advanced.yaml pull
    
    # Start services
    log "Starting SafeLine services..."
    docker-compose -f compose_advanced.yaml up -d
    
    # Wait for services to be ready
    log "Waiting for services to initialize..."
    sleep 60
    
    # Health checks
    log "Performing health checks..."
    
    local checks=0
    local max_checks=30
    
    while [ $checks -lt $max_checks ]; do
        if curl -k -f https://localhost:$MGT_PORT/api/open/health >/dev/null 2>&1; then
            log_success "SafeLine management service is healthy"
            break
        fi
        
        checks=$((checks + 1))
        log "Health check $checks/$max_checks..."
        sleep 10
    done
    
    if [ $checks -eq $max_checks ]; then
        log_error "SafeLine management service failed to start"
        exit 1
    fi
    
    log_success "SafeLine deployment completed"
}

# Configure advanced rules
configure_rules() {
    log "Configuring advanced detection rules..."
    
    # Wait for management API to be fully ready
    sleep 30
    
    # Note: This would require API token authentication in real deployment
    # For testing purposes, we'll copy rules to the container
    
    docker cp ./advanced_rules/. safeline-mgt-advanced:/app/custom_rules/
    docker exec safeline-mgt-advanced chmod -R 644 /app/custom_rules/
    
    # Restart detector to load new rules
    docker-compose -f compose_advanced.yaml restart detector
    
    log_success "Advanced rules configured"
}

# Configure high-performance settings
configure_performance() {
    log "Configuring high-performance settings..."
    
    # Tengine performance configuration
    cat > ./tengine_config/performance.conf << 'EOF'
# High-performance Tengine configuration
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
    accept_mutex off;
}

http {
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 1000;
    
    # Rate limiting for high throughput
    limit_req_zone $binary_remote_addr zone=general:10m rate=1000r/s;
    limit_req_zone $binary_remote_addr zone=api:10m rate=2000r/s;
    
    # Connection limiting
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
}
EOF

    docker cp ./tengine_config/performance.conf safeline-tengine-advanced:/etc/nginx/conf.d/
    docker exec safeline-tengine-advanced nginx -s reload
    
    log_success "High-performance configuration applied"
}

# Verify deployment
verify_deployment() {
    log "Verifying deployment..."
    
    # Check all containers are running
    local containers=(
        "safeline-mgt-advanced"
        "safeline-tengine-advanced" 
        "safeline-detector-advanced"
        "safeline-pg-advanced"
        "target-web-1"
        "target-api-1"
        "advanced-load-tester"
        "safeline-prometheus"
        "safeline-grafana"
    )
    
    for container in "${containers[@]}"; do
        if docker ps --format "table {{.Names}}" | grep -q "^$container$"; then
            log_success "$container is running"
        else
            log_error "$container is not running"
            exit 1
        fi
    done
    
    # Test basic connectivity
    log "Testing connectivity..."
    
    if curl -k -s https://localhost:$MGT_PORT/api/open/health | grep -q "ok"; then
        log_success "Management API is accessible"
    else
        log_error "Management API is not accessible"
    fi
    
    if curl -s http://localhost:80/ | grep -q "Target"; then
        log_success "WAF proxy is working"
    else
        log_error "WAF proxy is not working"
    fi
    
    if curl -s http://localhost:9090/api/v1/label/__name__/values | grep -q "up"; then
        log_success "Prometheus is collecting metrics"
    else
        log_error "Prometheus is not working"
    fi
    
    log_success "Deployment verification completed"
}

# Print deployment summary
print_summary() {
    log_success "=== SafeLine Advanced Deployment Summary ==="
    echo
    echo "Management UI:     https://localhost:$MGT_PORT"
    echo "WAF Endpoint:      http://localhost:80"
    echo "Target App 1:      http://localhost:8080"
    echo "Target App 2:      http://localhost:8081"
    echo "Prometheus:        http://localhost:9090"
    echo "Grafana:           http://localhost:3000 (admin/admin123)"
    echo
    echo "Environment:"
    echo "  SafeLine Dir:    $SAFELINE_DIR"
    echo "  PostgreSQL:      Running with optimized settings"
    echo "  Max RPS Target:  1000+"
    echo "  Monitoring:      Enabled with alerts"
    echo
    echo "Next Steps:"
    echo "1. Access Grafana dashboards for monitoring"
    echo "2. Run penetration tests: python3 testing_framework/advanced_pentest_engine.py --rps 1000"
    echo "3. Monitor performance during tests"
    echo
    log_success "Deployment completed successfully!"
}

# Main execution
main() {
    log "Starting SafeLine Advanced Deployment..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for system optimization"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Execute deployment steps
    optimize_system
    setup_directories
    set_environment
    create_detection_rules
    create_target_apps
    create_grafana_config
    deploy_safeline
    configure_rules
    configure_performance
    verify_deployment
    print_summary
}

# Execute main function
main "$@"