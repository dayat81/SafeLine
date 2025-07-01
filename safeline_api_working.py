#!/usr/bin/env python3
"""
SafeLine WAF API Configuration - Working Version
Uses container IP addresses for backend configuration
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
    
    def create_site(self, name, domain, upstream_ip, upstream_port):
        """Create a new site configuration using IP address"""
        
        # Use the working payload structure that SafeLine expects
        payload = {
            "name": name,
            "domain": [domain] if isinstance(domain, str) else domain,
            "upstream": f"{upstream_ip}:{upstream_port}"
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
    
    def get_site_details(self, site_id):
        """Get detailed information about a site"""
        response = self.session.get(f"{self.base_url}/api/open/site/{site_id}")
        if response.status_code == 200:
            return response.json().get('data', {})
        return None
    
    def list_policies(self):
        """List protection policies"""
        response = self.session.get(f"{self.base_url}/api/open/policy")
        if response.status_code == 200:
            data = response.json()
            return data.get('data', {}).get('data', [])
        return []

def main():
    print("🛡️ SafeLine WAF API Configuration (Working Version)")
    print("=" * 60)
    
    try:
        api = SafeLineAPI()
        
        # Check current sites
        sites = api.list_sites()
        print(f"📊 Current sites: {len(sites)}")
        
        # Backend applications with their actual container IP addresses
        applications = [
            {
                "name": "Juice Shop WAF Protection",
                "domain": "juice.local",
                "upstream_ip": "172.22.222.3",  # juice-shop container IP
                "upstream_port": 3000,
                "description": "OWASP Juice Shop protection"
            },
            {
                "name": "DVWA WAF Protection",
                "domain": "dvwa.local", 
                "upstream_ip": "172.22.222.6",  # dvwa container IP
                "upstream_port": 80,
                "description": "DVWA protection"
            },
            {
                "name": "Node.js App WAF Protection",
                "domain": "nodeapp.local",
                "upstream_ip": "172.22.222.9",  # nodejs-webapp container IP
                "upstream_port": 3000,
                "description": "Node.js vulnerable app protection"
            }
        ]
        
        print(f"\n🔧 Creating WAF Protection for Backend Applications")
        print("=" * 60)
        
        created_sites = []
        for app in applications:
            print(f"\n🎯 Creating: {app['name']}")
            print(f"   📍 Domain: {app['domain']}")
            print(f"   🔗 Upstream: {app['upstream_ip']}:{app['upstream_port']}")
            
            site = api.create_site(
                app['name'],
                app['domain'],
                app['upstream_ip'],
                app['upstream_port']
            )
            
            if site:
                created_sites.append({**app, **site})
                print(f"  ✅ Successfully created: {app['name']}")
                
                # Get site details if ID available
                site_id = site.get('id')
                if site_id:
                    details = api.get_site_details(site_id)
                    if details:
                        print(f"    🆔 Site ID: {site_id}")
                        print(f"    📋 Status: {details.get('status', 'Unknown')}")
                
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
        
        # Test site accessibility
        if created_sites:
            print(f"\n🧪 Testing Site Accessibility")
            print("=" * 30)
            
            for site_info in created_sites:
                domain = site_info['domain']
                print(f"\n🔍 Testing: {domain}")
                
                # Test direct backend
                backend_url = f"http://{site_info['upstream_ip']}:{site_info['upstream_port']}"
                try:
                    response = requests.get(backend_url, timeout=5)
                    print(f"  📡 Direct backend ({backend_url}): {response.status_code}")
                except Exception as e:
                    print(f"  📡 Direct backend ({backend_url}): Error - {str(e)}")
                
                # Note: WAF testing would require DNS setup or host file modification
                print(f"  🛡️ WAF URL: http://{domain} (requires DNS/hosts file setup)")
        
        # Show next steps
        print(f"\n🎯 Next Steps")
        print("=" * 15)
        print("1. Configure DNS or update /etc/hosts file:")
        for site_info in created_sites:
            print(f"   127.0.0.1 {site_info['domain']}")
        
        print("\n2. Test WAF protection:")
        for site_info in created_sites:
            print(f"   curl http://{site_info['domain']}")
        
        print("\n3. Run attack tests through WAF:")
        print("   python3 simple_waf_test.py")
        
        print(f"\n✅ SafeLine WAF configuration completed successfully!")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()