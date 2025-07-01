#!/usr/bin/env python3
"""
SafeLine WAF API Endpoint Testing Script
Tests all available API endpoints and logs results with timestamps
"""

import requests
import json
import time
from datetime import datetime
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
API_TOKEN = "nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS"
BASE_URL = "https://localhost:9443/api/open"
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

# Log file
LOG_FILE = f"SAFELINE_API_TEST_LOG_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

def log_message(message, level="INFO"):
    """Log message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    log_entry = f"[{timestamp}] [{level}] {message}\n"
    print(log_entry.strip())
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

def test_endpoint(method, endpoint, data=None, description=""):
    """Test a single API endpoint"""
    url = f"{BASE_URL}{endpoint}"
    log_message(f"Testing: {method} {endpoint} - {description}")
    
    try:
        if method == "GET":
            response = requests.get(url, headers=HEADERS, verify=False, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=HEADERS, json=data, verify=False, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=HEADERS, json=data, verify=False, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=HEADERS, verify=False, timeout=10)
        else:
            log_message(f"Unsupported method: {method}", "ERROR")
            return None
        
        log_message(f"Response Status: {response.status_code}")
        
        # Log response content
        try:
            response_data = response.json()
            log_message(f"Response Data: {json.dumps(response_data, indent=2)[:500]}...")
        except:
            log_message(f"Response Text: {response.text[:500]}...")
        
        return response
        
    except requests.exceptions.ConnectionError:
        log_message("Connection Error: SafeLine API not accessible", "ERROR")
        return None
    except requests.exceptions.Timeout:
        log_message("Request Timeout", "ERROR")
        return None
    except Exception as e:
        log_message(f"Error: {str(e)}", "ERROR")
        return None

def main():
    """Main test execution"""
    # Initialize log file
    with open(LOG_FILE, "w") as f:
        f.write(f"# SafeLine WAF API Endpoint Test Log\n\n")
        f.write(f"- **Test Started**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **API Token**: {API_TOKEN[:10]}...{API_TOKEN[-10:]}\n")
        f.write(f"- **Base URL**: {BASE_URL}\n\n")
        f.write("---\n\n")
    
    log_message("Starting SafeLine API Endpoint Testing", "START")
    
    # Test endpoints by category
    
    # 1. System & Health Endpoints
    log_message("=== Testing System & Health Endpoints ===", "SECTION")
    test_endpoint("GET", "/health", description="System health check")
    test_endpoint("GET", "/dashboard", description="Dashboard statistics")
    test_endpoint("GET", "/system/info", description="System information")
    
    # 2. Website Management
    log_message("\n=== Testing Website Management Endpoints ===", "SECTION")
    test_endpoint("GET", "/website", description="List all websites")
    test_endpoint("GET", "/website/1", description="Get specific website")
    
    # Test creating a website
    website_data = {
        "host": "test.example.com",
        "port": 80,
        "upstream": "192.168.1.100:8080",
        "ssl": False,
        "protection_enabled": True
    }
    create_response = test_endpoint("POST", "/website", data=website_data, description="Create new website")
    
    # If website was created, try to update and delete it
    if create_response and create_response.status_code == 200:
        try:
            website_id = create_response.json().get("data", {}).get("id")
            if website_id:
                update_data = {"protection_enabled": False}
                test_endpoint("PUT", f"/website/{website_id}", data=update_data, description="Update website")
                test_endpoint("DELETE", f"/website/{website_id}", description="Delete website")
        except:
            pass
    
    # 3. Detection Rules & Policies
    log_message("\n=== Testing Detection Rules & Policies ===", "SECTION")
    test_endpoint("GET", "/policy/rule", description="List all detection rules")
    test_endpoint("GET", "/policy/rule/1", description="Get specific rule")
    
    # Test creating a rule
    rule_data = {
        "name": "Test SQL Injection Rule",
        "category": "sql_injection",
        "pattern": "union.*select",
        "action": "block",
        "severity": "high",
        "enabled": True
    }
    rule_response = test_endpoint("POST", "/policy/rule", data=rule_data, description="Create detection rule")
    
    # 4. Attack Logs
    log_message("\n=== Testing Attack Logs ===", "SECTION")
    test_endpoint("GET", "/detect/log?limit=10", description="Recent attack logs")
    test_endpoint("GET", "/detect/log?attack_type=sql_injection", description="SQL injection logs")
    test_endpoint("GET", f"/detect/log?start_time={datetime.now().strftime('%Y-%m-%d')}T00:00:00Z", description="Logs by date")
    test_endpoint("GET", "/detect/log/1", description="Specific log entry")
    
    # 5. IP Management
    log_message("\n=== Testing IP Management ===", "SECTION")
    test_endpoint("GET", "/ip/group", description="List IP groups")
    
    # Test creating IP group
    ip_group_data = {
        "name": "Test Blocked IPs",
        "type": "blacklist",
        "ips": ["192.168.1.100", "10.0.0.50"],
        "description": "Test IP group"
    }
    test_endpoint("POST", "/ip/group", data=ip_group_data, description="Create IP group")
    
    # Test blacklisting IP
    blacklist_data = {
        "ip": "192.168.1.200",
        "reason": "API test",
        "duration": 3600
    }
    test_endpoint("POST", "/ip/blacklist", data=blacklist_data, description="Add IP to blacklist")
    
    # 6. Rate Limiting
    log_message("\n=== Testing Rate Limiting ===", "SECTION")
    test_endpoint("GET", "/frequency/rule", description="List rate limiting rules")
    
    rate_limit_data = {
        "name": "Test API Rate Limit",
        "path": "/api/test/*",
        "method": "ALL",
        "requests": 100,
        "window": 60,
        "action": "block"
    }
    test_endpoint("POST", "/frequency/rule", data=rate_limit_data, description="Create rate limit rule")
    
    # 7. SSL Certificates
    log_message("\n=== Testing SSL Certificate Management ===", "SECTION")
    test_endpoint("GET", "/cert", description="List SSL certificates")
    
    # 8. User Management
    log_message("\n=== Testing User Management ===", "SECTION")
    test_endpoint("GET", "/user", description="List all users")
    
    user_data = {
        "username": "api_test_user",
        "password": "test_password_123",
        "role": "analyst",
        "email": "test@example.com"
    }
    test_endpoint("POST", "/user", data=user_data, description="Create new user")
    
    # 9. Statistics & Analytics
    log_message("\n=== Testing Statistics & Analytics ===", "SECTION")
    test_endpoint("GET", "/stats/attack?period=24h", description="Attack statistics (24h)")
    test_endpoint("GET", "/stats/performance", description="Performance metrics")
    test_endpoint("GET", "/stats/top/attackers?limit=10", description="Top 10 attackers")
    
    # 10. Configuration
    log_message("\n=== Testing Configuration Management ===", "SECTION")
    test_endpoint("GET", "/config/export", description="Export configuration")
    
    # Additional endpoints that might exist
    log_message("\n=== Testing Additional Endpoints ===", "SECTION")
    test_endpoint("GET", "/version", description="API version")
    test_endpoint("GET", "/license", description="License information")
    test_endpoint("GET", "/backup", description="Backup status")
    test_endpoint("GET", "/alert", description="Alert configurations")
    test_endpoint("GET", "/notification", description="Notification settings")
    
    # Summary
    log_message("\n=== Test Execution Complete ===", "COMPLETE")
    
    # Add summary to log file
    with open(LOG_FILE, "a") as f:
        f.write(f"\n---\n\n")
        f.write(f"## Test Summary\n\n")
        f.write(f"- **Test Completed**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Log File**: {LOG_FILE}\n")

if __name__ == "__main__":
    main()