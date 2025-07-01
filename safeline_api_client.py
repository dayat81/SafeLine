#!/usr/bin/env python3
"""
SafeLine WAF API Client
Comprehensive API client for SafeLine WAF configuration using X-SLCE-API-TOKEN authentication
"""

import requests
import json
import os
import time
from datetime import datetime
from typing import Optional, Dict, List, Any
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SafeLineAPIClient:
    """SafeLine WAF API Client with token-based authentication"""
    
    def __init__(self, base_url: str = "https://localhost:9443", api_token: Optional[str] = None):
        """
        Initialize SafeLine API client
        
        Args:
            base_url: SafeLine WAF base URL
            api_token: API token for authentication (can also be set via SAFELINE_API_TOKEN env var)
        """
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token or os.getenv('SAFELINE_API_TOKEN')
        
        if not self.api_token:
            raise ValueError(
                "API token is required. Either pass api_token parameter or set SAFELINE_API_TOKEN environment variable.\n"
                "Get your token from SafeLine console: Settings > API Management"
            )
        
        # Set up session
        self.session = requests.Session()
        self.session.verify = False  # For self-signed certificates
        self.session.headers.update({
            'X-SLCE-API-TOKEN': self.api_token,
            'Content-Type': 'application/json',
            'User-Agent': 'SafeLine-API-Client/1.0',
            'Accept': 'application/json'
        })
        
        # Test authentication
        if not self.test_authentication():
            raise ValueError("Invalid API token or SafeLine WAF is not accessible")
    
    def test_authentication(self) -> bool:
        """Test if API token is valid and SafeLine is accessible"""
        try:
            response = self.session.get(f"{self.base_url}/api/open/health", timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"Authentication test failed: {e}")
            return False
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make API request with error handling"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = getattr(self.session, method.lower())(url, timeout=30, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise
    
    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle API response and extract data"""
        if response.status_code in [200, 201]:
            try:
                result = response.json()
                if result.get('err') == '' or result.get('success') is True:
                    return result.get('data', result)
                else:
                    error_msg = result.get('msg', result.get('error', 'Unknown error'))
                    raise ValueError(f"API Error: {error_msg}")
            except json.JSONDecodeError:
                return {"status": "success", "data": response.text}
        else:
            try:
                error_detail = response.json()
                error_msg = error_detail.get('msg', error_detail.get('error', f'HTTP {response.status_code}'))
            except:
                error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
            
            raise ValueError(f"API request failed: {error_msg}")
    
    # Website Management Methods
    
    def list_websites(self) -> List[Dict[str, Any]]:
        """Get list of all configured websites"""
        response = self._make_request('GET', '/api/open/website')
        result = self._handle_response(response)
        return result.get('list', result if isinstance(result, list) else [])
    
    def get_website(self, website_id: str) -> Dict[str, Any]:
        """Get specific website configuration"""
        response = self._make_request('GET', f'/api/open/website/{website_id}')
        return self._handle_response(response)
    
    def create_website(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create new website configuration"""
        response = self._make_request('POST', '/api/open/website', json=config)
        return self._handle_response(response)
    
    def update_website(self, website_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing website configuration"""
        response = self._make_request('PUT', f'/api/open/website/{website_id}', json=config)
        return self._handle_response(response)
    
    def delete_website(self, website_id: str) -> bool:
        """Delete website configuration"""
        response = self._make_request('DELETE', f'/api/open/website/{website_id}')
        try:
            self._handle_response(response)
            return True
        except:
            return False
    
    # Protection Rules Methods
    
    def update_protection_rule(self, website_id: str, rule_type: str, config: Dict[str, Any]) -> bool:
        """Update protection rule for a website"""
        endpoint = f'/api/open/website/{website_id}/rule/{rule_type}'
        response = self._make_request('PUT', endpoint, json=config)
        try:
            self._handle_response(response)
            return True
        except:
            return False
    
    def configure_sql_injection_protection(self, website_id: str, enabled: bool = True, 
                                         action: str = "deny", level: str = "high") -> bool:
        """Configure SQL injection protection"""
        config = {
            "enabled": enabled,
            "action": action,
            "level": level
        }
        return self.update_protection_rule(website_id, "sql", config)
    
    def configure_xss_protection(self, website_id: str, enabled: bool = True,
                               action: str = "deny", level: str = "high") -> bool:
        """Configure XSS protection"""
        config = {
            "enabled": enabled,
            "action": action,
            "level": level,
            "response_filtering": True
        }
        return self.update_protection_rule(website_id, "xss", config)
    
    def configure_rate_limiting(self, website_id: str, enabled: bool = True,
                              rate: int = 100, burst: int = 200, action: str = "challenge") -> bool:
        """Configure rate limiting"""
        config = {
            "enabled": enabled,
            "rate": rate,
            "burst": burst,
            "action": action,
            "period": 60
        }
        return self.update_protection_rule(website_id, "rate_limit", config)
    
    # IP Management Methods
    
    def get_ip_whitelist(self) -> List[Dict[str, Any]]:
        """Get IP whitelist"""
        response = self._make_request('GET', '/api/open/ip/whitelist')
        result = self._handle_response(response)
        return result if isinstance(result, list) else result.get('list', [])
    
    def add_ip_whitelist(self, ip: str, description: str = "") -> bool:
        """Add IP to whitelist"""
        config = {
            "ip": ip,
            "description": description,
            "enabled": True
        }
        response = self._make_request('POST', '/api/open/ip/whitelist', json=config)
        try:
            self._handle_response(response)
            return True
        except:
            return False
    
    def get_ip_blacklist(self) -> List[Dict[str, Any]]:
        """Get IP blacklist"""
        response = self._make_request('GET', '/api/open/ip/blacklist')
        result = self._handle_response(response)
        return result if isinstance(result, list) else result.get('list', [])
    
    def add_ip_blacklist(self, ip: str, description: str = "", duration: Optional[int] = None) -> bool:
        """Add IP to blacklist"""
        config = {
            "ip": ip,
            "description": description,
            "enabled": True
        }
        if duration:
            config["duration"] = duration
        
        response = self._make_request('POST', '/api/open/ip/blacklist', json=config)
        try:
            self._handle_response(response)
            return True
        except:
            return False
    
    # Monitoring Methods
    
    def get_attack_logs(self, website_id: Optional[str] = None, limit: int = 100, 
                       offset: int = 0) -> List[Dict[str, Any]]:
        """Get attack detection logs"""
        params = {
            "limit": limit,
            "offset": offset
        }
        if website_id:
            params["website_id"] = website_id
        
        response = self._make_request('GET', '/api/open/logs/attack', params=params)
        result = self._handle_response(response)
        return result if isinstance(result, list) else result.get('logs', [])
    
    def get_statistics(self, website_id: Optional[str] = None, period: str = "1h") -> Dict[str, Any]:
        """Get WAF statistics"""
        params = {"period": period}
        if website_id:
            params["website_id"] = website_id
        
        response = self._make_request('GET', '/api/open/stats', params=params)
        return self._handle_response(response)

class SafeLineConfigurator:
    """High-level SafeLine WAF configurator"""
    
    def __init__(self, api_client: SafeLineAPIClient):
        self.api = api_client
    
    def setup_backend_protection(self, applications: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Set up complete protection for backend applications"""
        
        print("🛡️ Setting up SafeLine WAF Protection for Backend Applications")
        print("=" * 70)
        
        configured_websites = []
        
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
                ]
            }
            
            try:
                # Create website
                website = self.api.create_website(website_config)
                website_id = website.get('id')
                
                if website_id:
                    configured_websites.append(website)
                    print(f"  ✅ Website created with ID: {website_id}")
                    
                    # Configure protection rules
                    self._configure_protection_rules(website_id, app_config.get('protection', {}))
                    
                    time.sleep(1)  # Brief pause between configurations
                else:
                    print(f"  ❌ Failed to create website: {app_config['name']}")
                    
            except Exception as e:
                print(f"  ❌ Error configuring {app_config['name']}: {str(e)}")
        
        print(f"\n🎉 Configuration completed! {len(configured_websites)} websites protected.")
        return configured_websites
    
    def _configure_protection_rules(self, website_id: str, protection_config: Dict[str, Any]):
        """Configure protection rules for a website"""
        
        # SQL Injection Protection
        if protection_config.get('sql_injection', True):
            if self.api.configure_sql_injection_protection(website_id):
                print("    ✅ SQL injection protection enabled")
            else:
                print("    ⚠️ Failed to enable SQL injection protection")
        
        # XSS Protection
        if protection_config.get('xss', True):
            if self.api.configure_xss_protection(website_id):
                print("    ✅ XSS protection enabled")
            else:
                print("    ⚠️ Failed to enable XSS protection")
        
        # Rate Limiting
        rate_config = protection_config.get('rate_limiting', {})
        if rate_config.get('enabled', True):
            rate = rate_config.get('rate', 100)
            burst = rate_config.get('burst', 200)
            if self.api.configure_rate_limiting(website_id, rate=rate, burst=burst):
                print(f"    ✅ Rate limiting configured ({rate} req/min, burst: {burst})")
            else:
                print("    ⚠️ Failed to configure rate limiting")
    
    def configure_ip_rules(self, whitelist_ips: List[str] = None, blacklist_ips: List[str] = None):
        """Configure IP whitelist and blacklist"""
        
        print("\n🔧 Configuring IP Rules")
        
        # Configure whitelist
        if whitelist_ips:
            for ip in whitelist_ips:
                if self.api.add_ip_whitelist(ip, "Automated whitelist"):
                    print(f"  ✅ Whitelisted: {ip}")
                else:
                    print(f"  ⚠️ Failed to whitelist: {ip}")
        
        # Configure blacklist
        if blacklist_ips:
            for ip in blacklist_ips:
                if self.api.add_ip_blacklist(ip, "Automated blacklist"):
                    print(f"  ✅ Blacklisted: {ip}")
                else:
                    print(f"  ⚠️ Failed to blacklist: {ip}")
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Validate WAF configuration"""
        
        print("\n🔍 Validating WAF Configuration")
        
        # Get all websites
        websites = self.api.list_websites()
        
        # Get IP rules
        whitelist = self.api.get_ip_whitelist()
        blacklist = self.api.get_ip_blacklist()
        
        validation_result = {
            "websites": len(websites),
            "whitelist_entries": len(whitelist),
            "blacklist_entries": len(blacklist),
            "website_details": []
        }
        
        print(f"📊 Configuration Summary:")
        print(f"  🌐 Websites configured: {len(websites)}")
        print(f"  ✅ Whitelist entries: {len(whitelist)}")
        print(f"  ❌ Blacklist entries: {len(blacklist)}")
        
        for website in websites:
            website_info = {
                "id": website.get('id'),
                "name": website.get('name'),
                "domains": website.get('domains', []),
                "upstreams": website.get('upstreams', [])
            }
            validation_result["website_details"].append(website_info)
            
            print(f"\n  🌐 {website.get('name', 'Unknown')} (ID: {website.get('id')})")
            print(f"    📍 Domains: {', '.join(website.get('domains', []))}")
            
            for upstream in website.get('upstreams', []):
                print(f"    🔗 Upstream: {upstream.get('host')}:{upstream.get('port')}")
        
        return validation_result

def main():
    """Example usage of SafeLine API client"""
    
    # Check for API token
    api_token = os.getenv('SAFELINE_API_TOKEN')
    if not api_token:
        print("❌ Please set SAFELINE_API_TOKEN environment variable")
        print("   Get your token from: https://localhost:9443 > Settings > API Management")
        return
    
    try:
        # Initialize API client
        api_client = SafeLineAPIClient(api_token=api_token)
        configurator = SafeLineConfigurator(api_client)
        
        # Define backend applications to protect
        applications = [
            {
                "name": "Juice Shop Protection",
                "domains": ["juice.local", "localhost"],
                "upstream_host": "juice-shop",
                "upstream_port": 3000,
                "protection": {
                    "sql_injection": True,
                    "xss": True,
                    "rate_limiting": {"enabled": True, "rate": 100, "burst": 200}
                }
            },
            {
                "name": "DVWA Protection",
                "domains": ["dvwa.local", "127.0.0.1"],
                "upstream_host": "dvwa",
                "upstream_port": 80,
                "protection": {
                    "sql_injection": True,
                    "xss": True,
                    "rate_limiting": {"enabled": True, "rate": 50, "burst": 100}
                }
            },
            {
                "name": "Node.js App Protection",
                "domains": ["nodeapp.local", "192.168.1.100"],
                "upstream_host": "nodejs-webapp",
                "upstream_port": 3000,
                "protection": {
                    "sql_injection": True,
                    "xss": True,
                    "rate_limiting": {"enabled": True, "rate": 150, "burst": 300}
                }
            }
        ]
        
        # Set up protection
        configured_websites = configurator.setup_backend_protection(applications)
        
        # Configure IP rules
        whitelist_ips = ["127.0.0.1", "192.168.1.0/24"]
        configurator.configure_ip_rules(whitelist_ips=whitelist_ips)
        
        # Validate configuration
        validation_result = configurator.validate_configuration()
        
        print(f"\n✅ SafeLine WAF configuration completed successfully!")
        print(f"   Configured {len(configured_websites)} websites with comprehensive protection.")
        
    except Exception as e:
        print(f"❌ Configuration failed: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())