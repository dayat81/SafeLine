#!/usr/bin/env python3
"""
SafeLine API Explorer
Discover available API endpoints
"""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def explore_api():
    token = "wMQ1jNOJM6Pfoj6950kG3vhAw6E6beQ4"
    base_url = "https://localhost:9443"
    
    headers = {
        "X-SLCE-API-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    # Common endpoint patterns to try
    endpoints = [
        "/api/open/site",
        "/api/open/sites", 
        "/api/open/website",
        "/api/open/websites",
        "/api/open/config",
        "/api/open/settings",
        "/api/open/rule",
        "/api/open/rules",
        "/api/open/policy",
        "/api/open/policies",
        "/api/open/ip",
        "/api/open/whitelist",
        "/api/open/blacklist",
        "/api/open/log",
        "/api/open/logs",
        "/api/open/stat",
        "/api/open/stats",
        "/api/open/dashboard",
        "/api/open/status",
        "/api/open/info",
        "/api/open/user",
        "/api/open/users"
    ]
    
    print("🔍 Exploring SafeLine API Endpoints")
    print("=" * 50)
    
    found_endpoints = []
    
    for endpoint in endpoints:
        try:
            response = requests.get(
                f"{base_url}{endpoint}",
                headers=headers,
                verify=False,
                timeout=5
            )
            
            if response.status_code == 200:
                print(f"✅ {endpoint} - {response.status_code}")
                try:
                    data = response.json()
                    print(f"   Response: {str(data)[:100]}...")
                except:
                    print(f"   Response: {response.text[:100]}...")
                found_endpoints.append(endpoint)
            elif response.status_code == 405:  # Method not allowed - endpoint exists
                print(f"🔶 {endpoint} - {response.status_code} (Method not allowed - try POST/PUT)")
                found_endpoints.append(endpoint)
            elif response.status_code == 401:
                print(f"🔒 {endpoint} - {response.status_code} (Unauthorized)")
            elif response.status_code == 403:
                print(f"🚫 {endpoint} - {response.status_code} (Forbidden)")
            else:
                print(f"❌ {endpoint} - {response.status_code}")
                
        except Exception as e:
            print(f"❌ {endpoint} - Error: {str(e)}")
    
    print(f"\n📊 Found {len(found_endpoints)} working endpoints:")
    for endpoint in found_endpoints:
        print(f"  - {endpoint}")
    
    # Test POST on site endpoint to understand structure
    if "/api/open/site" in found_endpoints:
        print(f"\n🧪 Testing POST to /api/open/site")
        test_site_creation()

def test_site_creation():
    token = "wMQ1jNOJM6Pfoj6950kG3vhAw6E6beQ4"
    base_url = "https://localhost:9443"
    
    headers = {
        "X-SLCE-API-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    # Test site creation payload
    test_payload = {
        "name": "Test Site",
        "domain": ["test.local"],
        "upstream": {
            "host": "localhost",
            "port": 8080
        }
    }
    
    try:
        response = requests.post(
            f"{base_url}/api/open/site",
            headers=headers,
            json=test_payload,
            verify=False,
            timeout=10
        )
        
        print(f"Status: {response.status_code}")
        try:
            data = response.json()
            print(f"Response: {data}")
        except:
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    explore_api()