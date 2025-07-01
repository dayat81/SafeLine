#!/usr/bin/env python3
"""
SafeLine WAF Configuration Script
Configures WAF with backend applications via API
"""

import requests
import json
import time
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SafeLineWAF:
    def __init__(self, base_url="https://localhost:9443", username="admin", password="E8NuObcs"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False
        self.token = None
        self.login(username, password)
    
    def login(self, username, password):
        """Login to SafeLine WAF and get authentication token"""
        login_url = f"{self.base_url}/api/open/auth/login"
        data = {
            "username": username,
            "password": password
        }
        
        try:
            response = self.session.post(login_url, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('err') == '':
                    self.token = result.get('data', {}).get('access_token')
                    self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                    print(f"✅ Successfully logged into SafeLine WAF")
                    return True
                else:
                    print(f"❌ Login failed: {result.get('msg', 'Unknown error')}")
            else:
                print(f"❌ Login failed with status: {response.status_code}")
        except Exception as e:
            print(f"❌ Login error: {str(e)}")
        
        return False
    
    def get_websites(self):
        """Get list of configured websites"""
        url = f"{self.base_url}/api/open/website"
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                result = response.json()
                return result.get('data', {}).get('list', [])
        except Exception as e:
            print(f"❌ Error getting websites: {str(e)}")
        return []
    
    def add_website(self, name, domains, cert_type="default", upstreams=None):
        """Add a new website to WAF protection"""
        url = f"{self.base_url}/api/open/website"
        
        if upstreams is None:
            upstreams = []
        
        data = {
            "name": name,
            "domains": domains,
            "cert_type": cert_type,
            "upstreams": upstreams
        }
        
        try:
            response = self.session.post(url, json=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('err') == '':
                    print(f"✅ Successfully added website: {name}")
                    return result.get('data', {})
                else:
                    print(f"❌ Failed to add website {name}: {result.get('msg', 'Unknown error')}")
            else:
                print(f"❌ Failed to add website {name} with status: {response.status_code}")
        except Exception as e:
            print(f"❌ Error adding website {name}: {str(e)}")
        
        return None
    
    def configure_protection_rules(self, website_id):
        """Configure protection rules for a website"""
        # Enable SQL injection protection
        self.update_rule(website_id, "sqli", {"action": "deny", "level": "high"})
        
        # Enable XSS protection
        self.update_rule(website_id, "xss", {"action": "deny", "level": "high"})
        
        # Enable command injection protection
        self.update_rule(website_id, "cmd_injection", {"action": "deny", "level": "high"})
        
        # Configure rate limiting
        self.update_rate_limit(website_id, {"enable": True, "rate": 100, "burst": 200})
    
    def update_rule(self, website_id, rule_type, config):
        """Update protection rule for a website"""
        url = f"{self.base_url}/api/open/website/{website_id}/rule/{rule_type}"
        
        try:
            response = self.session.put(url, json=config, timeout=10)
            if response.status_code == 200:
                print(f"✅ Updated {rule_type} rule for website {website_id}")
                return True
            else:
                print(f"❌ Failed to update {rule_type} rule: {response.status_code}")
        except Exception as e:
            print(f"❌ Error updating {rule_type} rule: {str(e)}")
        
        return False
    
    def update_rate_limit(self, website_id, config):
        """Update rate limiting for a website"""
        url = f"{self.base_url}/api/open/website/{website_id}/rate_limit"
        
        try:
            response = self.session.put(url, json=config, timeout=10)
            if response.status_code == 200:
                print(f"✅ Updated rate limiting for website {website_id}")
                return True
            else:
                print(f"❌ Failed to update rate limiting: {response.status_code}")
        except Exception as e:
            print(f"❌ Error updating rate limiting: {str(e)}")
        
        return False

def main():
    print("🛡️ SafeLine WAF Configuration Script")
    print("=" * 50)
    
    # Initialize WAF connection
    waf = SafeLineWAF()
    
    if not waf.token:
        print("❌ Failed to connect to WAF. Exiting.")
        return
    
    # Get current websites
    websites = waf.get_websites()
    print(f"📋 Current websites configured: {len(websites)}")
    
    # Configuration for backend applications
    backend_configs = [
        {
            "name": "Juice Shop",
            "domains": ["juice.local", "localhost"],
            "upstreams": [
                {
                    "host": "juice-shop",
                    "port": 3000,
                    "weight": 1
                }
            ]
        },
        {
            "name": "DVWA Application", 
            "domains": ["dvwa.local", "127.0.0.1"],
            "upstreams": [
                {
                    "host": "dvwa",
                    "port": 80,
                    "weight": 1
                }
            ]
        },
        {
            "name": "Node.js Vulnerable App",
            "domains": ["nodeapp.local", "192.168.1.100"],
            "upstreams": [
                {
                    "host": "nodejs-webapp", 
                    "port": 3000,
                    "weight": 1
                }
            ]
        }
    ]
    
    # Add websites to WAF
    configured_websites = []
    for config in backend_configs:
        print(f"\n🎯 Configuring: {config['name']}")
        website = waf.add_website(
            name=config['name'],
            domains=config['domains'],
            upstreams=config['upstreams']
        )
        
        if website and website.get('id'):
            configured_websites.append(website)
            # Configure protection rules
            waf.configure_protection_rules(website['id'])
            time.sleep(1)  # Brief pause between configurations
    
    print(f"\n✅ Configuration completed! {len(configured_websites)} websites configured.")
    print("🛡️ WAF is now protecting the backend applications.")

if __name__ == "__main__":
    main()