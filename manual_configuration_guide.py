#!/usr/bin/env python3
"""
SafeLine Manual Configuration Guide
Since API automation failed due to nginx upstream resolution issues,
this script guides manual configuration through the web console.
"""

import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_safeline_status():
    """Check SafeLine status and current configuration"""
    token = "wMQ1jNOJM6Pfoj6950kG3vhAw6E6beQ4"
    base_url = "https://localhost:9443"
    
    headers = {
        "X-SLCE-API-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    print("🛡️ SafeLine Configuration Status Check")
    print("=" * 50)
    
    try:
        # Check API health
        response = requests.get(f"{base_url}/api/open/health", headers=headers, verify=False)
        if response.status_code == 200:
            print("✅ SafeLine API is accessible")
        else:
            print(f"❌ SafeLine API error: {response.status_code}")
            return False
        
        # Check current sites
        response = requests.get(f"{base_url}/api/open/site", headers=headers, verify=False)
        if response.status_code == 200:
            data = response.json()
            sites = data.get('data', {}).get('data', [])
            print(f"📊 Current sites configured: {len(sites)}")
            
            if sites:
                print("📋 Existing sites:")
                for i, site in enumerate(sites, 1):
                    print(f"  {i}. {site.get('name', 'Unknown')} (ID: {site.get('id', 'N/A')})")
            else:
                print("📋 No sites currently configured")
        else:
            print(f"❌ Failed to get sites: {response.status_code}")
        
        return True
        
    except Exception as e:
        print(f"❌ Status check failed: {str(e)}")
        return False

def verify_backend_apps():
    """Verify that backend applications are running"""
    print(f"\n🔍 Backend Applications Status")
    print("=" * 35)
    
    backends = [
        {"name": "Juice Shop", "url": "http://localhost:8081", "container_ip": "172.22.222.3:3000"},
        {"name": "DVWA", "url": "http://localhost:8080", "container_ip": "172.22.222.6:80"},
        {"name": "Node.js App", "url": "http://localhost:8082", "container_ip": "172.22.222.9:3000"}
    ]
    
    for backend in backends:
        try:
            response = requests.get(backend["url"], timeout=5)
            print(f"✅ {backend['name']}: Running on {backend['url']} (Status: {response.status_code})")
            print(f"   🔗 Container IP: {backend['container_ip']}")
        except Exception as e:
            print(f"❌ {backend['name']}: Failed to connect - {str(e)}")

def print_manual_configuration_steps():
    """Print detailed manual configuration steps"""
    print(f"\n📋 Manual Configuration Steps")
    print("=" * 40)
    
    print(f"1. 🌐 Access SafeLine Web Console:")
    print(f"   URL: https://localhost:9443")
    print(f"   Username: admin")
    print(f"   Password: E8NuObcs")
    print(f"   ⚠️  Accept self-signed certificate warning")
    
    print(f"\n2. 🧭 Navigate to Website Management:")
    print(f"   • Look for '通用设置' (General Settings) in left sidebar")
    print(f"   • Or look for '防护应用' (Protected Applications)")
    print(f"   • Click on website/site management section")
    
    print(f"\n3. ➕ Add New Sites:")
    print(f"   For each backend application, create a new site:")
    
    sites_config = [
        {
            "name": "Juice Shop Protection",
            "domain": "juice.local",
            "upstream": "172.22.222.3:3000",
            "description": "OWASP Juice Shop WAF Protection"
        },
        {
            "name": "DVWA Protection", 
            "domain": "dvwa.local",
            "upstream": "172.22.222.6:80",
            "description": "DVWA WAF Protection"
        },
        {
            "name": "Node.js App Protection",
            "domain": "nodeapp.local", 
            "upstream": "172.22.222.9:3000",
            "description": "Node.js App WAF Protection"
        }
    ]
    
    for i, site in enumerate(sites_config, 1):
        print(f"\n   Site {i}: {site['name']}")
        print(f"   • Name: {site['name']}")
        print(f"   • Domain: {site['domain']}")
        print(f"   • Upstream/Backend: {site['upstream']}")
        print(f"   • Description: {site['description']}")
    
    print(f"\n4. 🔧 Configuration Details:")
    print(f"   • Make sure upstream IPs are reachable from SafeLine container")
    print(f"   • Enable protection rules (SQL injection, XSS, etc.)")
    print(f"   • Set appropriate rate limiting if needed")
    print(f"   • Save and activate each site")
    
    print(f"\n5. 🧪 Test Configuration:")
    print(f"   • Add to /etc/hosts (or use DNS):")
    for site in sites_config:
        print(f"     127.0.0.1 {site['domain']}")
    
    print(f"\n   • Test direct access:")
    for site in sites_config:
        print(f"     curl http://{site['domain']}")
    
    print(f"\n   • Run attack tests:")
    print(f"     python3 simple_waf_test.py")

def create_hosts_file_entries():
    """Create /etc/hosts entries for testing"""
    print(f"\n📝 /etc/hosts File Entries")
    print("=" * 30)
    
    hosts_entries = [
        "127.0.0.1 juice.local",
        "127.0.0.1 dvwa.local", 
        "127.0.0.1 nodeapp.local"
    ]
    
    print("Add these entries to /etc/hosts for testing:")
    print()
    for entry in hosts_entries:
        print(f"  {entry}")
    
    print(f"\nTo add automatically:")
    print(f"echo '127.0.0.1 juice.local' | sudo tee -a /etc/hosts")
    print(f"echo '127.0.0.1 dvwa.local' | sudo tee -a /etc/hosts")
    print(f"echo '127.0.0.1 nodeapp.local' | sudo tee -a /etc/hosts")

def main():
    print("🛡️ SafeLine Manual Configuration Guide")
    print("=" * 50)
    print("This guide helps configure SafeLine through the web console")
    print("since API automation encountered nginx upstream resolution issues.")
    print()
    
    # Check current status
    if not check_safeline_status():
        print("❌ SafeLine is not accessible. Please ensure it's running.")
        return
    
    # Verify backend apps
    verify_backend_apps()
    
    # Print manual steps
    print_manual_configuration_steps()
    
    # Create hosts file entries
    create_hosts_file_entries()
    
    print(f"\n✅ Configuration Guide Complete")
    print(f"📖 Follow the manual steps above to configure SafeLine")
    print(f"🧪 Run attack tests after configuration: python3 simple_waf_test.py")
    
    # Create summary file
    summary = {
        "manual_configuration_required": True,
        "reason": "API automation failed due to nginx upstream resolution",
        "web_console": "https://localhost:9443",
        "credentials": {"username": "admin", "password": "E8NuObcs"},
        "backend_apps": [
            {"name": "Juice Shop", "url": "http://localhost:8081", "container": "172.22.222.3:3000"},
            {"name": "DVWA", "url": "http://localhost:8080", "container": "172.22.222.6:80"},
            {"name": "Node.js App", "url": "http://localhost:8082", "container": "172.22.222.9:3000"}
        ],
        "next_steps": [
            "Access web console manually",
            "Navigate to website management",
            "Add three sites with container IPs as upstreams",
            "Configure protection rules",
            "Add /etc/hosts entries",
            "Test with attack scenarios"
        ]
    }
    
    with open("/home/pt/SafeLine/manual_config_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"📄 Summary saved: manual_config_summary.json")

if __name__ == "__main__":
    main()