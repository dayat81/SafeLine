#!/usr/bin/env python3
"""
SafeLine WAF API Endpoint Testing Script - Corrected Authentication
Tests all SafeLine API endpoints using the correct X-SLCE-API-TOKEN header
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
    "X-SLCE-API-TOKEN": API_TOKEN,
    "Content-Type": "application/json"
}

# Log file
LOG_FILE = f"SAFELINE_CORRECTED_API_TEST_LOG_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

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
            if len(response_str) > 1000:
                log_message(f"Response Data: {response_str[:1000]}...")
            else:
                log_message(f"Response Data: {response_str}")
        except:
            response_text = response.text
            if len(response_text) > 1000:
                log_message(f"Response Text: {response_text[:1000]}...")
            else:
                log_message(f"Response Text: {response_text}")
        
        # Log important response headers
        important_headers = ['Content-Type', 'Content-Length', 'Set-Cookie']
        header_info = {k: v for k, v in response.headers.items() if k in important_headers}
        if header_info:
            log_message(f"Important Headers: {header_info}")
        
        log_message("=" * 80)
        
        return response
        
    except requests.exceptions.ConnectionError:
        log_message("Connection Error: SafeLine API not accessible", "ERROR")
        log_message("=" * 80)
        return None
    except requests.exceptions.Timeout:
        log_message("Request Timeout", "ERROR")
        log_message("=" * 80)
        return None
    except Exception as e:
        log_message(f"Error: {str(e)}", "ERROR")
        log_message("=" * 80)
        return None

def main():
    """Main test execution"""
    # Initialize log file
    with open(LOG_FILE, "w") as f:
        f.write(f"# SafeLine WAF Corrected API Endpoint Test Log\n\n")
        f.write(f"- **Test Started**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **API Token**: {API_TOKEN[:10]}...{API_TOKEN[-10:]}\n")
        f.write(f"- **Base URL**: {BASE_URL}\n")
        f.write(f"- **Authentication**: X-SLCE-API-TOKEN header\n")
        f.write(f"- **Target**: SafeLine WAF Management API (Corrected)\n\n")
        f.write("---\n\n")
    
    log_message("Starting SafeLine Corrected API Endpoint Testing", "START")
    
    # Test public endpoints first (no authentication required)
    log_message("=== 1. TESTING PUBLIC ENDPOINTS (No Authentication Required) ===", "SECTION")
    
    test_endpoint("GET", "/Ping", description="Health check endpoint", use_token=False)
    test_endpoint("GET", "/Version", description="Get SafeLine version information", use_token=False)
    test_endpoint("GET", "/UpgradeTips", description="Get upgrade recommendations", use_token=False)
    test_endpoint("GET", "/OTPUrl", description="Get OTP setup URL for TOTP", use_token=False)
    
    # Test authentication endpoints
    log_message("\n=== 2. TESTING AUTHENTICATION ENDPOINTS ===", "SECTION")
    
    # Test login (will likely fail without proper credentials)
    login_data = {
        "username": "admin",
        "password": "admin"
    }
    test_endpoint("POST", "/Login", data=login_data, description="User login attempt", use_token=False)
    
    # Test logout
    test_endpoint("POST", "/Logout", description="User logout", use_token=False)
    
    # Test behavior and false positives (public endpoints)
    behavior_data = {
        "action": "api_test",
        "url": "/api/test",
        "timestamp": datetime.now().isoformat()
    }
    test_endpoint("POST", "/Behaviour", data=behavior_data, description="Submit behavior data", use_token=False)
    
    false_positive_data = {
        "detection_id": "test_123",
        "reason": "api_testing",
        "details": "API endpoint testing"
    }
    test_endpoint("POST", "/FalsePositives", data=false_positive_data, description="Report false positive", use_token=False)
    
    # Test endpoints with API token authentication
    log_message("\n=== 3. TESTING USER MANAGEMENT (API Token Required) ===", "SECTION")
    
    test_endpoint("GET", "/User", description="Get current user information")
    
    log_message("\n=== 4. TESTING WEBSITE MANAGEMENT (API Token Required) ===", "SECTION")
    
    test_endpoint("GET", "/Website", description="List all configured websites")
    
    # Test creating a website
    website_data = {
        "host": "api-test.example.com",
        "port": 80,
        "upstream": ["192.168.1.100:8080"],
        "ssl": False,
        "protection_enabled": True
    }
    create_response = test_endpoint("POST", "/Website", data=website_data, description="Create test website")
    
    # If website creation was successful, try to update and delete it
    website_id = None
    if create_response and create_response.status_code == 200:
        try:
            response_data = create_response.json()
            if response_data.get("data") and response_data["data"].get("id"):
                website_id = response_data["data"]["id"]
                log_message(f"Created website with ID: {website_id}", "SUCCESS")
        except:
            pass
    
    if website_id:
        update_data = {
            "id": website_id,
            "protection_enabled": False,
            "ssl": True
        }
        test_endpoint("PUT", "/Website", data=update_data, description=f"Update website {website_id}")
        
        delete_data = {"id": website_id}
        test_endpoint("DELETE", "/Website", data=delete_data, description=f"Delete website {website_id}")
    else:
        # Test with dummy data
        update_data = {"id": 999, "protection_enabled": False}
        test_endpoint("PUT", "/Website", data=update_data, description="Update website (test with dummy ID)")
        
        delete_data = {"id": 999}
        test_endpoint("DELETE", "/Website", data=delete_data, description="Delete website (test with dummy ID)")
    
    log_message("\n=== 5. TESTING DETECTION LOGS (API Token Required) ===", "SECTION")
    
    test_endpoint("GET", "/DetectLogList?page=1&page_size=20", description="Get detection logs list")
    test_endpoint("GET", "/DetectLogDetail?id=1", description="Get detection log details")
    
    log_message("\n=== 6. TESTING POLICY RULES MANAGEMENT (API Token Required) ===", "SECTION")
    
    test_endpoint("GET", "/PolicyRule", description="List all policy rules")
    
    # Test creating a policy rule
    policy_rule_data = {
        "name": "API Test SQL Injection Rule",
        "category": "sql_injection",
        "action": "block",
        "enabled": True,
        "pattern": "union.*select.*from"
    }
    rule_response = test_endpoint("POST", "/PolicyRule", data=policy_rule_data, description="Create policy rule")
    
    # Try to update and delete the rule if creation was successful
    rule_id = None
    if rule_response and rule_response.status_code == 200:
        try:
            response_data = rule_response.json()
            if response_data.get("data") and response_data["data"].get("id"):
                rule_id = response_data["data"]["id"]
        except:
            pass
    
    if rule_id:
        update_rule_data = {
            "id": rule_id,
            "enabled": False,
            "action": "log"
        }
        test_endpoint("PUT", "/PolicyRule", data=update_rule_data, description=f"Update policy rule {rule_id}")
        
        switch_rule_data = {
            "id": rule_id,
            "enabled": True
        }
        test_endpoint("PUT", "/SwitchPolicyRule", data=switch_rule_data, description=f"Toggle policy rule {rule_id}")
        
        delete_rule_data = {"id": rule_id}
        test_endpoint("DELETE", "/PolicyRule", data=delete_rule_data, description=f"Delete policy rule {rule_id}")
    else:
        # Test with dummy data
        test_endpoint("PUT", "/PolicyRule", data={"id": 999, "enabled": False}, description="Update policy rule (dummy)")
        test_endpoint("PUT", "/SwitchPolicyRule", data={"id": 999, "enabled": True}, description="Toggle policy rule (dummy)")
        test_endpoint("DELETE", "/PolicyRule", data={"id": 999}, description="Delete policy rule (dummy)")
    
    log_message("\n=== 7. TESTING DASHBOARD & ANALYTICS (API Token Required) ===", "SECTION")
    
    test_endpoint("GET", "/dashboard/counts", description="Get dashboard request/intercept counts")
    test_endpoint("GET", "/dashboard/sites", description="Get dashboard sites status")
    test_endpoint("GET", "/dashboard/qps", description="Get QPS (queries per second) metrics")
    test_endpoint("GET", "/dashboard/requests", description="Get request statistics")
    test_endpoint("GET", "/dashboard/intercepts", description="Get intercept statistics")
    
    log_message("\n=== 8. TESTING SSL CERTIFICATE MANAGEMENT (API Token Required) ===", "SECTION")
    
    # Test SSL certificate configuration
    ssl_cert_data = {
        "name": "api-test.example.com",
        "cert": "-----BEGIN CERTIFICATE-----\nMIIC...TEST...CERTIFICATE\n-----END CERTIFICATE-----",
        "key": "-----BEGIN PRIVATE KEY-----\nMIIE...TEST...KEY\n-----END PRIVATE KEY-----"
    }
    test_endpoint("POST", "/SSLCert", data=ssl_cert_data, description="Configure SSL certificate")
    
    # Note: File upload test for /UploadSSLCert would require multipart/form-data which is more complex
    log_message("Skipping /UploadSSLCert test (requires file upload)", "INFO")
    
    log_message("\n=== 9. TESTING GLOBAL CONFIGURATION (API Token Required) ===", "SECTION")
    
    test_endpoint("GET", "/PolicyGroupGlobal", description="Get global policy group settings")
    
    global_policy_data = {
        "protection_mode": "monitor",
        "log_level": "debug"
    }
    test_endpoint("PUT", "/PolicyGroupGlobal", data=global_policy_data, description="Update global policy group")
    
    test_endpoint("GET", "/SrcIPConfig", description="Get source IP configuration")
    
    src_ip_config_data = {
        "header": "X-Forwarded-For",
        "position": "first"
    }
    test_endpoint("PUT", "/SrcIPConfig", data=src_ip_config_data, description="Update source IP configuration")
    
    log_message("\n=== 10. TESTING ADDITIONAL ENDPOINTS ===", "SECTION")
    
    # Test some endpoints that might exist but aren't documented
    test_endpoint("GET", "/health", description="Alternative health check", use_token=False)
    test_endpoint("GET", "/status", description="Status endpoint", use_token=False)
    test_endpoint("GET", "/metrics", description="Metrics endpoint", use_token=False)
    
    # Summary
    log_message("\n=== TEST EXECUTION COMPLETE ===", "COMPLETE")
    
    # Add summary to log file
    with open(LOG_FILE, "a") as f:
        f.write(f"\n---\n\n")
        f.write(f"## Test Summary\n\n")
        f.write(f"- **Test Completed**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Log File**: {LOG_FILE}\n")
        f.write(f"- **Total Endpoints Tested**: 30+ endpoints across 10 categories\n")
        f.write(f"- **Authentication Method**: X-SLCE-API-TOKEN header\n")
        f.write(f"- **API Token Used**: {API_TOKEN[:10]}...{API_TOKEN[-10:]}\n\n")
        f.write(f"### Test Categories Covered\n")
        f.write(f"1. Public Endpoints (Health, Version, OTP)\n")
        f.write(f"2. Authentication (Login, Logout)\n")
        f.write(f"3. User Management\n")
        f.write(f"4. Website Management (CRUD operations)\n")
        f.write(f"5. Detection Logs\n")
        f.write(f"6. Policy Rules Management (CRUD operations)\n")
        f.write(f"7. Dashboard & Analytics\n")
        f.write(f"8. SSL Certificate Management\n")
        f.write(f"9. Global Configuration\n")
        f.write(f"10. Additional Endpoints\n\n")
        f.write(f"### Expected Results\n")
        f.write(f"- Public endpoints should return 200 or valid responses\n")
        f.write(f"- Protected endpoints with valid token should work\n")
        f.write(f"- Invalid operations should return appropriate error codes\n")
        f.write(f"- All responses should follow SafeLine API format\n")

if __name__ == "__main__":
    main()