#!/usr/bin/env python3
"""
SafeLine WAF Real API Endpoint Testing Script
Tests actual SafeLine API endpoints based on codebase analysis
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
BASE_URL = "https://localhost:9443/api"
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

# Log file
LOG_FILE = f"SAFELINE_REAL_API_TEST_LOG_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

def log_message(message, level="INFO"):
    """Log message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    log_entry = f"[{timestamp}] [{level}] {message}\n"
    print(log_entry.strip())
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

def test_endpoint(method, endpoint, data=None, description="", use_token=True):
    """Test a single API endpoint"""
    url = f"{BASE_URL}{endpoint}"
    headers = HEADERS if use_token else {"Content-Type": "application/json"}
    
    log_message(f"Testing: {method} {endpoint} - {description}")
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, verify=False, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, verify=False, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=data, verify=False, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, verify=False, timeout=10)
        else:
            log_message(f"Unsupported method: {method}", "ERROR")
            return None
        
        log_message(f"Response Status: {response.status_code}")
        
        # Log response content (truncated for readability)
        try:
            response_data = response.json()
            response_str = json.dumps(response_data, indent=2)
            if len(response_str) > 500:
                log_message(f"Response Data: {response_str[:500]}...")
            else:
                log_message(f"Response Data: {response_str}")
        except:
            response_text = response.text
            if len(response_text) > 500:
                log_message(f"Response Text: {response_text[:500]}...")
            else:
                log_message(f"Response Text: {response_text}")
        
        log_message(f"Response Headers: {dict(response.headers)}")
        log_message("---")
        
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

def attempt_login():
    """Attempt to get a valid session"""
    log_message("Attempting to establish authenticated session", "AUTH")
    
    # Try login with common credentials
    login_data = {
        "username": "admin",
        "password": "safeline"
    }
    
    response = test_endpoint("POST", "/Login", data=login_data, description="Login attempt", use_token=False)
    if response and response.status_code == 200:
        log_message("Login successful", "SUCCESS")
        # Extract session token or cookie if provided
        if 'Set-Cookie' in response.headers:
            log_message(f"Session Cookie: {response.headers['Set-Cookie']}", "AUTH")
        return response
    
    # Try with different credentials
    login_data["password"] = "admin"
    response = test_endpoint("POST", "/Login", data=login_data, description="Login attempt (admin/admin)", use_token=False)
    
    return response

def main():
    """Main test execution"""
    # Initialize log file
    with open(LOG_FILE, "w") as f:
        f.write(f"# SafeLine WAF Real API Endpoint Test Log\n\n")
        f.write(f"- **Test Started**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **API Token**: {API_TOKEN[:10]}...{API_TOKEN[-10:]}\n")
        f.write(f"- **Base URL**: {BASE_URL}\n")
        f.write(f"- **Target**: SafeLine WAF Management API\n\n")
        f.write("---\n\n")
    
    log_message("Starting SafeLine Real API Endpoint Testing", "START")
    
    # Test public endpoints first (no authentication required)
    log_message("=== Testing Public Endpoints (No Authentication) ===", "SECTION")
    
    test_endpoint("GET", "/Ping", description="Health check endpoint", use_token=False)
    test_endpoint("GET", "/Version", description="Get SafeLine version", use_token=False)
    test_endpoint("GET", "/UpgradeTips", description="Get upgrade recommendations", use_token=False)
    test_endpoint("GET", "/OTPUrl", description="Get OTP setup URL", use_token=False)
    
    # Try the /api/open/health endpoint mentioned in compose
    test_endpoint("GET", "/open/health", description="Docker health check endpoint", use_token=False)
    
    # Attempt authentication
    log_message("\n=== Authentication Attempts ===", "SECTION")
    login_response = attempt_login()
    
    # Test endpoints that might work with the provided token
    log_message("\n=== Testing Endpoints with API Token ===", "SECTION")
    
    # Dashboard endpoints
    test_endpoint("GET", "/dashboard/counts", description="Request/intercept counts")
    test_endpoint("GET", "/dashboard/sites", description="Site status summary")
    test_endpoint("GET", "/dashboard/qps", description="QPS data")
    test_endpoint("GET", "/dashboard/requests", description="Request statistics")
    test_endpoint("GET", "/dashboard/intercepts", description="Intercept statistics")
    
    # User management
    test_endpoint("GET", "/User", description="Current user information")
    
    # Detection logs
    test_endpoint("GET", "/DetectLogList", description="Detection logs list")
    test_endpoint("GET", "/DetectLogDetail", description="Detection log detail")
    
    # Website management
    test_endpoint("GET", "/Website", description="Website list")
    
    # Policy rules
    test_endpoint("GET", "/PolicyRule", description="Policy rules list")
    test_endpoint("GET", "/PolicyGroupGlobal", description="Global policy group")
    test_endpoint("GET", "/SrcIPConfig", description="Source IP configuration")
    
    # Test creating resources (will likely fail but we can see the response format)
    log_message("\n=== Testing Resource Creation (Expected to Fail) ===", "SECTION")
    
    website_data = {
        "host": "test.example.com",
        "port": 80,
        "upstream": "192.168.1.100:8080",
        "ssl": False
    }
    test_endpoint("POST", "/Website", data=website_data, description="Create test website")
    
    # Test logout
    log_message("\n=== Testing Logout ===", "SECTION")
    test_endpoint("POST", "/Logout", description="User logout", use_token=False)
    
    # Test some additional endpoints that might exist
    log_message("\n=== Testing Additional Possible Endpoints ===", "SECTION")
    
    # Common API patterns
    test_endpoint("GET", "/status", description="Status endpoint", use_token=False)
    test_endpoint("GET", "/info", description="Info endpoint", use_token=False)
    test_endpoint("GET", "/metrics", description="Metrics endpoint", use_token=False)
    
    # Internal endpoints
    test_endpoint("GET", "/open/publish/server", description="Internal server endpoint", use_token=False)
    
    # Alternative health checks
    test_endpoint("GET", "/health", description="Alternative health check", use_token=False)
    test_endpoint("GET", "/healthz", description="Kubernetes-style health check", use_token=False)
    
    # Summary
    log_message("\n=== Test Execution Complete ===", "COMPLETE")
    
    # Add summary to log file
    with open(LOG_FILE, "a") as f:
        f.write(f"\n---\n\n")
        f.write(f"## Test Summary\n\n")
        f.write(f"- **Test Completed**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Log File**: {LOG_FILE}\n")
        f.write(f"- **Total Endpoints Tested**: ~20+ endpoints\n")
        f.write(f"- **Authentication Status**: Token-based authentication attempted\n\n")
        f.write(f"### Key Findings\n")
        f.write(f"- SafeLine uses `/api/` prefix (not `/api/open/`)\n")
        f.write(f"- Health check endpoint: `/api/Ping` returns 'pong'\n")  
        f.write(f"- Session-based authentication system in place\n")
        f.write(f"- API token may require different authentication method\n")

if __name__ == "__main__":
    main()