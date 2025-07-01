#!/usr/bin/env python3
"""
SafeLine WAF API Client - Fixed for Actual Endpoints
Based on discovered API structure
"""

import requests
import json
import time
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SafeLineAPI:
    def __init__(self, api_token="wMQ1jNOJM6Pfoj6950kG3vhAw6E6beQ4", base_url="https://localhost:9443"):
        self.base_url = base_url
        self.api_token = api_token
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'X-SLCE-API-TOKEN': self.api_token,
            'Content-Type': 'application/json'
        })
        
        # Test connection
        if not self.test_connection():
            raise ValueError("Failed to connect to SafeLine API")
    
    def test_connection(self):
        """Test API connection"""
        try:
            response = self.session.get(f"{self.base_url}/api/open/health")
            return response.status_code == 200
        except:
            return False
    
    def list_sites(self):
        """List all configured sites"""
        response = self.session.get(f"{self.base_url}/api/open/site")
        if response.status_code == 200:
            data = response.json()
            return data.get('data', {}).get('data', [])
        return []
    
    def create_site(self, name, domains, upstream_host, upstream_port):
        """Create a new site configuration"""
        
        # Try different payload structures based on SafeLine expectations
        payloads_to_try = [
            # Structure 1: Simple upstream
            {
                "name": name,
                "domain": domains,
                "upstream": f"{upstream_host}:{upstream_port}"
            },
            # Structure 2: Upstream object
            {
                "name": name,
                "domain": domains,
                "upstream": {
                    "host": upstream_host,
                    "port": upstream_port
                }
            },
            # Structure 3: Backend array
            {
                "name": name,
                "domain": domains,
                "backend": [
                    {
                        "host": upstream_host,
                        "port": upstream_port,
                        "weight": 1
                    }
                ]
            },
            # Structure 4: Multiple domains array
            {
                "name": name,
                "domains": domains if isinstance(domains, list) else [domains],
                "upstream": f"{upstream_host}:{upstream_port}"
            }
        ]
        
        for i, payload in enumerate(payloads_to_try):
            print(f"  🧪 Trying payload structure {i+1}...")
            
            response = self.session.post(f"{self.base_url}/api/open/site", json=payload)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('err') is None and 'nginx: [emerg]' not in data.get('msg', ''):
                    print(f"    ✅ Site created successfully with structure {i+1}")
                    return data.get('data', {})
                else:
                    print(f"    ⚠️ Structure {i+1} failed: {data.get('msg', '')[:100]}...")
            else:
                print(f"    ❌ Structure {i+1} failed with status {response.status_code}")
        
        return None
    
    def list_policies(self):
        """List protection policies"""
        response = self.session.get(f"{self.base_url}/api/open/policy")
        if response.status_code == 200:
            data = response.json()
            return data.get('data', {}).get('data', [])
        return []
    
    def list_users(self):
        """List users (for testing)"""
        response = self.session.get(f"{self.base_url}/api/open/users")
        if response.status_code == 200:
            data = response.json()
            return data.get('data', {}).get('data', [])
        return []

def main():
    print("🛡️ SafeLine WAF API Configuration (Fixed)")
    print("=" * 50)
    
    try:
        api = SafeLineAPI()
        print("✅ Connected to SafeLine API")
        
        # List current sites
        sites = api.list_sites()
        print(f"📊 Current sites: {len(sites)}")
        for site in sites:
            print(f"  - {site.get('name', 'Unknown')}")
        
        # List policies
        policies = api.list_policies()
        print(f"📋 Available policies: {len(policies)}")
        for policy in policies[:3]:  # Show first 3
            print(f"  - {policy.get('name', 'Unknown')} (ID: {policy.get('id')})")
        
        # Try to create sites for our backend applications
        print(f"\n🔧 Creating Sites for Backend Applications")
        
        applications = [
            {
                "name": "Juice Shop WAF",
                "domains": ["juice.local"],
                "upstream_host": "juice-shop",
                "upstream_port": 3000
            },
            {
                "name": "DVWA WAF", 
                "domains": ["dvwa.local"],
                "upstream_host": "dvwa",
                "upstream_port": 80
            },
            {
                "name": "Node.js App WAF",
                "domains": ["nodeapp.local"],
                "upstream_host": "nodejs-webapp", 
                "upstream_port": 3000
            }
        ]
        
        created_sites = []
        for app in applications:
            print(f"\n🎯 Creating: {app['name']}")
            
            site = api.create_site(
                app['name'],
                app['domains'],
                app['upstream_host'],
                app['upstream_port']
            )
            
            if site:
                created_sites.append(site)
                print(f"  ✅ Successfully created: {app['name']}")
                time.sleep(2)  # Pause between creations
            else:
                print(f"  ❌ Failed to create: {app['name']}")
        
        print(f"\n📊 Final Results:")
        print(f"  🎯 Attempted to create: {len(applications)} sites")
        print(f"  ✅ Successfully created: {len(created_sites)} sites")
        
        # List sites again to see what was created
        final_sites = api.list_sites()
        print(f"  📋 Total sites now: {len(final_sites)}")
        
        for site in final_sites:
            print(f"    - {site.get('name', 'Unknown')} (ID: {site.get('id', 'N/A')})")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    main()