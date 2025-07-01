# SafeLine WAF API Configuration Plan

## Overview

This document provides a comprehensive plan for configuring SafeLine WAF using its Open API, including authentication, website management, protection rules, and automated configuration workflows.

**Reference**: SafeLine Open API Guide - Secure Access with API Tokens  
**Base URL**: https://localhost:9443/api/open  
**Authentication**: JWT Token-based authentication

---

## Table of Contents

1. [API Authentication Strategy](#api-authentication-strategy)
2. [API Endpoint Discovery](#api-endpoint-discovery)
3. [Website Configuration](#website-configuration)
4. [Protection Rules Management](#protection-rules-management)
5. [IP Management](#ip-management)
6. [Monitoring and Analytics](#monitoring-and-analytics)
7. [Automation Scripts](#automation-scripts)
8. [Implementation Timeline](#implementation-timeline)

---

## API Authentication Strategy

### 1. API Token Authentication

SafeLine uses API Token authentication for secure API access. The authentication method uses the `X-SLCE-API-TOKEN` header instead of JWT tokens.

#### Authentication Method
```
Header: X-SLCE-API-TOKEN: "Your API Token from SafeLine"
```

#### Authentication Process
```python
import requests
import json
import os

class SafeLineAPI:
    def __init__(self, base_url="https://localhost:9443", api_token=None):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False  # For self-signed certificates
        self.api_token = api_token or os.getenv('SAFELINE_API_TOKEN')
        
        if not self.api_token:
            raise ValueError("API token is required. Set SAFELINE_API_TOKEN environment variable or pass api_token parameter.")
        
        # Set up session with API token
        self.session.headers.update({
            'X-SLCE-API-TOKEN': self.api_token,
            'Content-Type': 'application/json',
            'User-Agent': 'SafeLine-API-Client/1.0'
        })
    
    def test_authentication(self):
        """Test if API token is valid"""
        try:
            response = self.session.get(f"{self.base_url}/api/open/health")
            return response.status_code == 200
        except Exception:
            return False
    
    @classmethod
    def create_from_login(cls, base_url="https://localhost:9443", username="admin", password="E8NuObcs"):
        """Alternative: Create API client by logging in to get token"""
        session = requests.Session()
        session.verify = False
        
        # First, try to get API token via login (if this endpoint exists)
        login_endpoint = f"{base_url}/api/open/auth/login"
        
        auth_data = {
            "username": username,
            "password": password
        }
        
        try:
            response = session.post(login_endpoint, json=auth_data, timeout=30)
            if response.status_code == 200:
                result = response.json()
                api_token = result.get('data', {}).get('api_token') or result.get('token')
                if api_token:
                    return cls(base_url, api_token)
        except Exception:
            pass
        
        raise ValueError("Could not obtain API token via login. Please generate token manually from SafeLine console.")
```

#### Obtaining API Token

There are several ways to obtain the SafeLine API token:

1. **From SafeLine Console (Recommended)**:
   - Login to SafeLine console: https://localhost:9443
   - Navigate to Settings > API Management
   - Generate new API token
   - Copy the token for use in scripts

2. **Via Login API** (if available):
   ```python
   # Get token programmatically
   def get_api_token(username, password):
       session = requests.Session()
       session.verify = False
       
       login_data = {
           "username": username,
           "password": password
       }
       
       response = session.post(
           "https://localhost:9443/api/open/auth/login",
           json=login_data
       )
       
       if response.status_code == 200:
           result = response.json()
           return result.get('data', {}).get('api_token')
       return None
   ```

3. **Environment Variable**:
   ```bash
   export SAFELINE_API_TOKEN="your_actual_token_here"
   ```

### 2. Token Management

#### Token Refresh Strategy
```python
def refresh_token(self):
    """Refresh the authentication token"""
    refresh_endpoint = f"{self.base_url}/api/open/auth/refresh"
    
    response = self.session.post(refresh_endpoint)
    if response.status_code == 200:
        result = response.json()
        new_token = result.get('data', {}).get('access_token')
        if new_token:
            self.token = new_token
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            return True
    return False

def is_token_valid(self):
    """Check if current token is still valid"""
    test_endpoint = f"{self.base_url}/api/open/health"
    response = self.session.get(test_endpoint)
    return response.status_code == 200
```

---

## API Endpoint Discovery

### 1. Core API Endpoints

Based on SafeLine's architecture, the following endpoints are expected:

#### Authentication Endpoints
```
POST /api/open/auth/login          # User login
POST /api/open/auth/refresh        # Token refresh  
POST /api/open/auth/logout         # User logout
GET  /api/open/csrf               # Get CSRF token
```

#### Website Management
```
GET    /api/open/website          # List all websites
POST   /api/open/website          # Create new website
GET    /api/open/website/{id}     # Get website details
PUT    /api/open/website/{id}     # Update website
DELETE /api/open/website/{id}     # Delete website
```

#### Protection Rules
```
GET    /api/open/website/{id}/rules         # Get all rules
PUT    /api/open/website/{id}/rules/sql     # SQL injection rules
PUT    /api/open/website/{id}/rules/xss     # XSS protection rules
PUT    /api/open/website/{id}/rules/waf     # General WAF rules
```

#### IP Management
```
GET    /api/open/ip/whitelist     # Get IP whitelist
POST   /api/open/ip/whitelist     # Add IP to whitelist
DELETE /api/open/ip/whitelist/{id} # Remove from whitelist
GET    /api/open/ip/blacklist     # Get IP blacklist
POST   /api/open/ip/blacklist     # Add IP to blacklist
```

### 2. Endpoint Discovery Script

```python
def discover_endpoints(self):
    """Discover available API endpoints"""
    common_paths = [
        "/api/open",
        "/api/open/website", 
        "/api/open/rules",
        "/api/open/ip",
        "/api/open/logs",
        "/api/open/stats",
        "/api/open/settings"
    ]
    
    discovered = []
    for path in common_paths:
        try:
            response = self.session.options(f"{self.base_url}{path}")
            if response.status_code in [200, 405]:  # 405 = Method Not Allowed (but endpoint exists)
                discovered.append(path)
        except:
            continue
    
    return discovered
```

---

## Website Configuration

### 1. Website Data Structure

```python
class WebsiteConfig:
    def __init__(self):
        self.template = {
            "name": "",
            "domains": [],
            "upstreams": [],
            "cert_type": "default",
            "ssl_cert": "",
            "ssl_key": "",
            "protocols": ["http", "https"],
            "ports": [80, 443]
        }
    
    def create_website_config(self, name, domains, upstream_host, upstream_port):
        """Create website configuration"""
        return {
            "name": name,
            "domains": domains,
            "upstreams": [
                {
                    "host": upstream_host,
                    "port": upstream_port,
                    "weight": 1,
                    "backup": False
                }
            ],
            "cert_type": "default",
            "protocols": ["http"]
        }
```

### 2. Website Management Operations

```python
def add_website(self, config):
    """Add a new website to WAF protection"""
    endpoint = f"{self.base_url}/api/open/website"
    
    response = self.session.post(endpoint, json=config)
    if response.status_code == 200:
        result = response.json()
        if result.get('err') == '' or result.get('success'):
            return result.get('data', {})
    return None

def list_websites(self):
    """Get list of all configured websites"""
    endpoint = f"{self.base_url}/api/open/website"
    
    response = self.session.get(endpoint)
    if response.status_code == 200:
        result = response.json()
        return result.get('data', {}).get('list', [])
    return []

def update_website(self, website_id, config):
    """Update existing website configuration"""
    endpoint = f"{self.base_url}/api/open/website/{website_id}"
    
    response = self.session.put(endpoint, json=config)
    return response.status_code == 200

def delete_website(self, website_id):
    """Delete a website from WAF protection"""
    endpoint = f"{self.base_url}/api/open/website/{website_id}"
    
    response = self.session.delete(endpoint)
    return response.status_code == 200
```

---

## Protection Rules Management

### 1. Rule Configuration Structure

```python
class ProtectionRules:
    def __init__(self):
        self.sql_injection_rules = {
            "enabled": True,
            "action": "deny",  # deny, allow, challenge
            "level": "high",   # low, medium, high
            "custom_patterns": []
        }
        
        self.xss_rules = {
            "enabled": True,
            "action": "deny",
            "level": "high",
            "response_filtering": True
        }
        
        self.rate_limiting = {
            "enabled": True,
            "requests_per_minute": 100,
            "burst_size": 200,
            "action": "challenge",  # deny, challenge, allow
            "duration": 300  # seconds
        }
        
        self.custom_rules = []
```

### 2. Rule Management Operations

```python
def configure_sql_injection_protection(self, website_id, config):
    """Configure SQL injection protection"""
    endpoint = f"{self.base_url}/api/open/website/{website_id}/rules/sql"
    
    rule_config = {
        "enabled": config.get("enabled", True),
        "action": config.get("action", "deny"),
        "sensitivity": config.get("level", "high"),
        "custom_rules": config.get("custom_patterns", [])
    }
    
    response = self.session.put(endpoint, json=rule_config)
    return response.status_code == 200

def configure_xss_protection(self, website_id, config):
    """Configure XSS protection"""
    endpoint = f"{self.base_url}/api/open/website/{website_id}/rules/xss"
    
    rule_config = {
        "enabled": config.get("enabled", True),
        "action": config.get("action", "deny"),
        "sensitivity": config.get("level", "high"),
        "response_filtering": config.get("response_filtering", True)
    }
    
    response = self.session.put(endpoint, json=rule_config)
    return response.status_code == 200

def configure_rate_limiting(self, website_id, config):
    """Configure rate limiting"""
    endpoint = f"{self.base_url}/api/open/website/{website_id}/rules/rate"
    
    rate_config = {
        "enabled": config.get("enabled", True),
        "rate": config.get("requests_per_minute", 100),
        "burst": config.get("burst_size", 200),
        "action": config.get("action", "challenge"),
        "period": 60  # 1 minute
    }
    
    response = self.session.put(endpoint, json=rate_config)
    return response.status_code == 200

def add_custom_rule(self, website_id, rule):
    """Add custom protection rule"""
    endpoint = f"{self.base_url}/api/open/website/{website_id}/rules/custom"
    
    custom_rule = {
        "name": rule["name"],
        "pattern": rule["pattern"],
        "action": rule["action"],
        "enabled": rule.get("enabled", True),
        "description": rule.get("description", "")
    }
    
    response = self.session.post(endpoint, json=custom_rule)
    return response.status_code == 200
```

---

## IP Management

### 1. Whitelist Management

```python
def add_to_whitelist(self, ip_address, description=""):
    """Add IP address to whitelist"""
    endpoint = f"{self.base_url}/api/open/ip/whitelist"
    
    whitelist_entry = {
        "ip": ip_address,
        "description": description,
        "enabled": True
    }
    
    response = self.session.post(endpoint, json=whitelist_entry)
    return response.status_code == 200

def remove_from_whitelist(self, whitelist_id):
    """Remove IP from whitelist"""
    endpoint = f"{self.base_url}/api/open/ip/whitelist/{whitelist_id}"
    
    response = self.session.delete(endpoint)
    return response.status_code == 200

def get_whitelist(self):
    """Get current IP whitelist"""
    endpoint = f"{self.base_url}/api/open/ip/whitelist"
    
    response = self.session.get(endpoint)
    if response.status_code == 200:
        result = response.json()
        return result.get('data', [])
    return []
```

### 2. Blacklist Management

```python
def add_to_blacklist(self, ip_address, description="", duration=None):
    """Add IP address to blacklist"""
    endpoint = f"{self.base_url}/api/open/ip/blacklist"
    
    blacklist_entry = {
        "ip": ip_address,
        "description": description,
        "enabled": True,
        "duration": duration  # None for permanent
    }
    
    response = self.session.post(endpoint, json=blacklist_entry)
    return response.status_code == 200

def get_blacklist(self):
    """Get current IP blacklist"""
    endpoint = f"{self.base_url}/api/open/ip/blacklist"
    
    response = self.session.get(endpoint)
    if response.status_code == 200:
        result = response.json()
        return result.get('data', [])
    return []
```

---

## Monitoring and Analytics

### 1. Attack Logs

```python
def get_attack_logs(self, website_id=None, limit=100, offset=0):
    """Get attack detection logs"""
    endpoint = f"{self.base_url}/api/open/logs/attacks"
    
    params = {
        "limit": limit,
        "offset": offset
    }
    
    if website_id:
        params["website_id"] = website_id
    
    response = self.session.get(endpoint, params=params)
    if response.status_code == 200:
        result = response.json()
        return result.get('data', [])
    return []

def get_statistics(self, website_id=None, period="1h"):
    """Get WAF statistics"""
    endpoint = f"{self.base_url}/api/open/stats"
    
    params = {
        "period": period  # 1h, 24h, 7d, 30d
    }
    
    if website_id:
        params["website_id"] = website_id
    
    response = self.session.get(endpoint, params=params)
    if response.status_code == 200:
        result = response.json()
        return result.get('data', {})
    return {}
```

---

## Automation Scripts

### 1. Complete Website Setup Script

```python
#!/usr/bin/env python3
"""
SafeLine WAF Complete Configuration Script
"""

import json
import time
from datetime import datetime

def setup_complete_waf_protection():
    """Set up complete WAF protection for all backend applications"""
    
    # Initialize API client
    api = SafeLineAPI()
    
    if not api.token:
        print("❌ Failed to authenticate with SafeLine API")
        return False
    
    print("✅ Successfully authenticated with SafeLine API")
    
    # Backend application configurations
    applications = [
        {
            "name": "Juice Shop Protection",
            "domains": ["juice.local", "localhost"],
            "upstream_host": "juice-shop",
            "upstream_port": 3000,
            "description": "OWASP Juice Shop vulnerable application"
        },
        {
            "name": "DVWA Protection", 
            "domains": ["dvwa.local", "127.0.0.1"],
            "upstream_host": "dvwa",
            "upstream_port": 80,
            "description": "Damn Vulnerable Web Application"
        },
        {
            "name": "Node.js App Protection",
            "domains": ["nodeapp.local", "192.168.1.100"],
            "upstream_host": "nodejs-webapp",
            "upstream_port": 3000,
            "description": "Custom vulnerable Node.js application"
        }
    ]
    
    configured_websites = []
    
    # Configure each application
    for app_config in applications:
        print(f"\n🔧 Configuring: {app_config['name']}")
        
        # Create website configuration
        website_config = {
            "name": app_config["name"],
            "domains": app_config["domains"],
            "upstreams": [
                {
                    "host": app_config["upstream_host"],
                    "port": app_config["upstream_port"],
                    "weight": 1
                }
            ],
            "description": app_config["description"]
        }
        
        # Add website
        website = api.add_website(website_config)
        if website and website.get('id'):
            website_id = website['id']
            configured_websites.append(website)
            print(f"  ✅ Website created with ID: {website_id}")
            
            # Configure protection rules
            configure_protection_rules(api, website_id)
            
            time.sleep(1)  # Brief pause between configurations
        else:
            print(f"  ❌ Failed to create website: {app_config['name']}")
    
    # Configure global IP rules
    configure_global_ip_rules(api)
    
    print(f"\n🎉 Configuration completed! {len(configured_websites)} websites protected.")
    return configured_websites

def configure_protection_rules(api, website_id):
    """Configure comprehensive protection rules for a website"""
    
    # SQL Injection Protection
    sql_config = {
        "enabled": True,
        "action": "deny",
        "level": "high"
    }
    if api.configure_sql_injection_protection(website_id, sql_config):
        print("    ✅ SQL injection protection enabled")
    
    # XSS Protection
    xss_config = {
        "enabled": True,
        "action": "deny", 
        "level": "high",
        "response_filtering": True
    }
    if api.configure_xss_protection(website_id, xss_config):
        print("    ✅ XSS protection enabled")
    
    # Rate Limiting
    rate_config = {
        "enabled": True,
        "requests_per_minute": 100,
        "burst_size": 200,
        "action": "challenge"
    }
    if api.configure_rate_limiting(website_id, rate_config):
        print("    ✅ Rate limiting configured")
    
    # Custom Rules
    custom_rules = [
        {
            "name": "Block Admin Access",
            "pattern": r"/admin.*",
            "action": "deny",
            "description": "Block access to admin paths"
        },
        {
            "name": "API Rate Limit",
            "pattern": r"/api/.*",
            "action": "challenge",
            "description": "Enhanced protection for API endpoints"
        }
    ]
    
    for rule in custom_rules:
        if api.add_custom_rule(website_id, rule):
            print(f"    ✅ Custom rule added: {rule['name']}")

def configure_global_ip_rules(api):
    """Configure global IP whitelist and blacklist"""
    
    print("\n🔧 Configuring Global IP Rules")
    
    # Whitelist internal networks
    whitelist_ips = [
        {"ip": "192.168.1.0/24", "description": "Internal network"},
        {"ip": "10.0.0.0/8", "description": "Private network"},
        {"ip": "127.0.0.1", "description": "Localhost"}
    ]
    
    for entry in whitelist_ips:
        if api.add_to_whitelist(entry["ip"], entry["description"]):
            print(f"  ✅ Whitelisted: {entry['ip']}")
    
    # Blacklist known malicious IPs (example)
    blacklist_ips = [
        {"ip": "198.51.100.0/24", "description": "Known attack sources"}
    ]
    
    for entry in blacklist_ips:
        if api.add_to_blacklist(entry["ip"], entry["description"]):
            print(f"  ✅ Blacklisted: {entry['ip']}")
```

### 2. Configuration Validation Script

```python
def validate_waf_configuration():
    """Validate WAF configuration and rules"""
    
    api = SafeLineAPI()
    if not api.token:
        return False
    
    print("🔍 Validating WAF Configuration")
    
    # Get all websites
    websites = api.list_websites()
    print(f"📊 Total websites configured: {len(websites)}")
    
    for website in websites:
        website_id = website.get('id')
        name = website.get('name', 'Unknown')
        print(f"\n🌐 Website: {name} (ID: {website_id})")
        
        # Validate domains
        domains = website.get('domains', [])
        print(f"  📍 Domains: {', '.join(domains)}")
        
        # Validate upstreams
        upstreams = website.get('upstreams', [])
        for upstream in upstreams:
            host = upstream.get('host')
            port = upstream.get('port')
            print(f"  🔗 Upstream: {host}:{port}")
    
    # Check IP rules
    whitelist = api.get_whitelist()
    blacklist = api.get_blacklist()
    
    print(f"\n📋 IP Rules:")
    print(f"  ✅ Whitelist entries: {len(whitelist)}")
    print(f"  ❌ Blacklist entries: {len(blacklist)}")
    
    return True
```

---

## Implementation Timeline

### Phase 1: API Discovery and Authentication (Day 1)
- ✅ Set up API authentication flow
- ✅ Implement token management
- ✅ Discover available endpoints
- ✅ Test basic API connectivity

### Phase 2: Website Configuration (Day 2)
- ✅ Implement website management operations
- ✅ Configure backend application protection
- ✅ Test website creation and modification
- ✅ Validate upstream connectivity

### Phase 3: Protection Rules (Day 3)
- ✅ Configure SQL injection protection
- ✅ Set up XSS protection rules
- ✅ Implement rate limiting
- ✅ Add custom protection rules

### Phase 4: IP Management (Day 4)
- ✅ Configure IP whitelisting
- ✅ Set up IP blacklisting
- ✅ Implement geographic restrictions
- ✅ Test IP-based rules

### Phase 5: Monitoring and Validation (Day 5)
- ✅ Implement log monitoring
- ✅ Set up statistics collection
- ✅ Create validation scripts
- ✅ Test complete configuration

---

## Error Handling and Troubleshooting

### Common API Errors

```python
def handle_api_error(response):
    """Handle common API errors"""
    
    error_codes = {
        400: "Bad Request - Invalid parameters",
        401: "Unauthorized - Invalid or expired token",
        403: "Forbidden - Insufficient permissions",
        404: "Not Found - Endpoint or resource not found",
        409: "Conflict - Resource already exists",
        422: "Unprocessable Entity - Validation error",
        429: "Too Many Requests - Rate limited",
        500: "Internal Server Error - Server error"
    }
    
    status_code = response.status_code
    error_message = error_codes.get(status_code, f"Unknown error: {status_code}")
    
    try:
        error_detail = response.json()
        if 'msg' in error_detail:
            error_message += f" - {error_detail['msg']}"
        elif 'error' in error_detail:
            error_message += f" - {error_detail['error']}"
    except:
        pass
    
    print(f"❌ API Error {status_code}: {error_message}")
    return error_message
```

### Retry Logic

```python
def api_request_with_retry(self, method, endpoint, max_retries=3, **kwargs):
    """Make API request with retry logic"""
    
    for attempt in range(max_retries):
        try:
            response = getattr(self.session, method.lower())(
                f"{self.base_url}{endpoint}", 
                timeout=30,
                **kwargs
            )
            
            if response.status_code == 401 and attempt < max_retries - 1:
                # Token might be expired, try to refresh
                if self.refresh_token():
                    continue
            
            return response
            
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                raise
            print(f"⚠️ Request failed, retrying ({attempt + 1}/{max_retries}): {str(e)}")
            time.sleep(2 ** attempt)  # Exponential backoff
    
    return None
```

---

## Security Best Practices

### 1. Token Security
- Store tokens securely (environment variables, secure storage)
- Implement token rotation
- Use HTTPS for all API communications
- Log API access for auditing

### 2. Configuration Security
- Validate all input parameters
- Use least privilege principle for API access
- Implement configuration backup and restore
- Monitor configuration changes

### 3. Network Security
- Restrict API access to authorized networks
- Use VPN or secure tunnels for remote access
- Implement API rate limiting
- Monitor for suspicious API activity

---

## Testing and Validation

### API Configuration Test Suite

```python
def run_api_test_suite():
    """Run comprehensive API test suite"""
    
    print("🧪 Running SafeLine API Test Suite")
    
    tests = [
        test_authentication,
        test_website_management,
        test_protection_rules,
        test_ip_management,
        test_monitoring_endpoints
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
            print(f"  {'✅' if result else '❌'} {test.__name__}")
        except Exception as e:
            results.append(False)
            print(f"  ❌ {test.__name__}: {str(e)}")
    
    success_rate = sum(results) / len(results) * 100
    print(f"\n📊 Test Results: {success_rate:.1f}% passed ({sum(results)}/{len(results)})")
    
    return success_rate >= 80  # 80% pass rate threshold
```

---

## Conclusion

This comprehensive plan provides a structured approach to configure SafeLine WAF using its Open API. The implementation includes:

1. **Secure Authentication**: JWT token-based API access
2. **Complete Configuration**: Website, rules, and IP management
3. **Automation**: Scripts for bulk configuration and validation
4. **Error Handling**: Robust error handling and retry logic
5. **Security**: Best practices for API and configuration security
6. **Testing**: Comprehensive validation and testing framework

The API-based approach enables automated, repeatable, and version-controlled WAF configuration, making it ideal for DevOps and infrastructure-as-code workflows.

**Next Steps**: Execute the authentication flow, discover actual API endpoints, and implement the configuration scripts based on the SafeLine API documentation.