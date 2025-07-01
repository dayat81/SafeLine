#!/usr/bin/env python3
"""
SafeLine WAF API Configuration using container hostnames
Testing with actual container names instead of IPs
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
            
        print("✅ Connected to SafeLine API successfully")
    
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
    
    def create_site(self, name, domain, upstream):
        """Create a new site configuration using hostname"""
        
        payload = {
            "name": name,
            "domain": [domain] if isinstance(domain, str) else domain,
            "upstream": upstream
        }
        
        print(f"  📤 Sending payload: {json.dumps(payload, indent=2)}")
        
        response = self.session.post(f"{self.base_url}/api/open/site", json=payload)
        
        if response.status_code == 200:
            data = response.json()
            print(f"  📥 Response: {json.dumps(data, indent=2)}")
            
            if data.get('err') is None:
                if 'nginx: [emerg]' not in data.get('msg', ''):
                    return data.get('data', {})
                else:
                    print(f"    ⚠️ Nginx configuration error: {data.get('msg', '')}") 
                    return None
            else:
                print(f"    ❌ API error: {data.get('msg', data.get('err'))}")
                return None
        else:
            print(f"    ❌ HTTP error: {response.status_code} - {response.text}")
            return None

def main():
    print("🛡️ SafeLine WAF API Configuration (Container Hostnames)")
    print("=" * 65)
    
    try:
        api = SafeLineAPI()
        
        # Check current sites
        sites = api.list_sites()
        print(f"📊 Current sites: {len(sites)}")
        
        # Backend applications with container names instead of IPs
        applications = [
            {
                "name": "Juice Shop WAF Protection",
                "domain": "juice.local",
                "upstream": "juice-shop:3000",
                "description": "OWASP Juice Shop protection using container hostname"
            },
            {
                "name": "DVWA WAF Protection",
                "domain": "dvwa.local", 
                "upstream": "dvwa:80",
                "description": "DVWA protection using container hostname"
            },
            {
                "name": "Node.js App WAF Protection",
                "domain": "nodeapp.local",
                "upstream": "nodejs-webapp:3000",
                "description": "Node.js vulnerable app protection using container hostname"
            }
        ]
        
        print(f"\n🔧 Creating WAF Protection using Container Hostnames")
        print("=" * 60)
        
        created_sites = []
        for app in applications:
            print(f"\n🎯 Creating: {app['name']}")
            print(f"   📍 Domain: {app['domain']}")
            print(f"   🔗 Upstream: {app['upstream']}")
            
            site = api.create_site(
                app['name'],
                app['domain'],
                app['upstream']
            )
            
            if site:
                created_sites.append({**app, **site})
                print(f"  ✅ Successfully created: {app['name']}")
                time.sleep(2)  # Brief pause between creations
            else:
                print(f"  ❌ Failed to create: {app['name']}")
        
        # Final status check
        print(f"\n📊 Configuration Results")
        print("=" * 30)
        
        final_sites = api.list_sites()
        print(f"🎯 Attempted to create: {len(applications)} sites")
        print(f"✅ Successfully created: {len(created_sites)} sites")
        print(f"📋 Total sites now: {len(final_sites)}")
        
        if final_sites:
            print(f"\n📑 Current Sites Configuration:")
            for i, site in enumerate(final_sites, 1):
                print(f"  {i}. {site.get('name', 'Unknown')} (ID: {site.get('id', 'N/A')})") 
                domains = site.get('domain', [])
                if domains:
                    print(f"     📍 Domains: {', '.join(domains)}")
        
        if len(created_sites) > 0:
            print(f"\n✅ Sites created successfully using container hostnames!")
        else:
            print(f"\n⚠️ No sites were created - network resolution issue persists")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()