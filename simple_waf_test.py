#!/usr/bin/env python3
"""
Simple WAF Test Script - Manual Testing Without Locust
Demonstrates attack scenarios and measures basic performance
"""

import requests
import time
import json
import statistics
from datetime import datetime
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SimpleWAFTester:
    def __init__(self, target_url="http://localhost:8082"):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.verify = False
        self.results = {
            'normal_requests': [],
            'attack_attempts': [],
            'blocked_attacks': 0,
            'passed_attacks': 0,
            'false_positives': 0
        }
    
    def test_normal_requests(self):
        """Test normal, legitimate requests"""
        print("🔍 Testing Normal Requests...")
        
        normal_tests = [
            ("GET", "/", "Homepage"),
            ("GET", "/search?q=laptop", "Search"),
            ("GET", "/user/1", "User Profile"),
            ("GET", "/api/products", "API Call"),
            ("POST", "/login", "Login", {"username": "test", "password": "test123"})
        ]
        
        for method, path, name, data in [(t[0], t[1], t[2], t[3] if len(t) > 3 else None) for t in normal_tests]:
            start_time = time.time()
            
            try:
                if method == "GET":
                    response = self.session.get(f"{self.target_url}{path}", timeout=10)
                else:
                    response = self.session.post(f"{self.target_url}{path}", data=data, timeout=10)
                
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 403:
                    self.results['false_positives'] += 1
                    print(f"  ❌ {name}: BLOCKED (False Positive) - {response.status_code}")
                else:
                    print(f"  ✅ {name}: OK - {response.status_code} ({response_time:.1f}ms)")
                
                self.results['normal_requests'].append({
                    'name': name,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'blocked': response.status_code == 403
                })
                
            except Exception as e:
                print(f"  ❌ {name}: ERROR - {str(e)}")
            
            time.sleep(0.5)  # Brief pause between requests
    
    def test_sql_injection_attacks(self):
        """Test SQL injection attack detection"""
        print("\n🎯 Testing SQL Injection Attacks...")
        
        sqli_payloads = [
            "1' OR '1'='1",
            "1'; DROP TABLE users--",
            "admin'--", 
            "1' UNION SELECT * FROM passwords--",
            "'; SELECT * FROM information_schema.tables--"
        ]
        
        for payload in sqli_payloads:
            start_time = time.time()
            
            try:
                response = self.session.get(f"{self.target_url}/user/{payload}", timeout=10)
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 403:
                    self.results['blocked_attacks'] += 1
                    print(f"  🛡️ SQL Injection BLOCKED: {payload[:30]}...")
                else:
                    self.results['passed_attacks'] += 1
                    print(f"  ⚠️ SQL Injection PASSED: {payload[:30]}... - {response.status_code}")
                
                self.results['attack_attempts'].append({
                    'type': 'SQL Injection',
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'blocked': response.status_code == 403
                })
                
            except Exception as e:
                print(f"  ❌ SQL Injection ERROR: {str(e)}")
            
            time.sleep(0.3)
    
    def test_xss_attacks(self):
        """Test XSS attack detection"""
        print("\n🎯 Testing XSS Attacks...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>"
        ]
        
        for payload in xss_payloads:
            start_time = time.time()
            
            try:
                response = self.session.get(f"{self.target_url}/search?q={payload}", timeout=10)
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 403:
                    self.results['blocked_attacks'] += 1
                    print(f"  🛡️ XSS BLOCKED: {payload[:30]}...")
                else:
                    self.results['passed_attacks'] += 1
                    print(f"  ⚠️ XSS PASSED: {payload[:30]}... - {response.status_code}")
                
                self.results['attack_attempts'].append({
                    'type': 'XSS',
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'blocked': response.status_code == 403
                })
                
            except Exception as e:
                print(f"  ❌ XSS ERROR: {str(e)}")
            
            time.sleep(0.3)
    
    def test_command_injection_attacks(self):
        """Test command injection attack detection"""
        print("\n🎯 Testing Command Injection Attacks...")
        
        cmdi_payloads = [
            "127.0.0.1; cat /etc/passwd",
            "localhost && whoami", 
            "8.8.8.8 | ls -la",
            "google.com; rm -rf /",
            "test.com`id`"
        ]
        
        for payload in cmdi_payloads:
            start_time = time.time()
            
            try:
                response = self.session.post(f"{self.target_url}/ping", 
                                           json={"host": payload}, timeout=10)
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 403:
                    self.results['blocked_attacks'] += 1
                    print(f"  🛡️ Command Injection BLOCKED: {payload[:30]}...")
                else:
                    self.results['passed_attacks'] += 1
                    print(f"  ⚠️ Command Injection PASSED: {payload[:30]}... - {response.status_code}")
                
                self.results['attack_attempts'].append({
                    'type': 'Command Injection',
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'blocked': response.status_code == 403
                })
                
            except Exception as e:
                print(f"  ❌ Command Injection ERROR: {str(e)}")
            
            time.sleep(0.3)
    
    def performance_test(self, num_requests=20):
        """Basic performance testing"""
        print(f"\n⚡ Performance Test ({num_requests} requests)...")
        
        response_times = []
        successful_requests = 0
        
        for i in range(num_requests):
            start_time = time.time()
            
            try:
                response = self.session.get(f"{self.target_url}/", timeout=10)
                response_time = (time.time() - start_time) * 1000
                response_times.append(response_time)
                
                if response.status_code in [200, 302]:
                    successful_requests += 1
                
                if (i + 1) % 5 == 0:
                    print(f"  📊 Completed {i + 1}/{num_requests} requests...")
                
            except Exception as e:
                print(f"  ❌ Request {i + 1} failed: {str(e)}")
            
            time.sleep(0.1)  # Small delay between requests
        
        if response_times:
            avg_time = statistics.mean(response_times)
            min_time = min(response_times)
            max_time = max(response_times)
            
            print(f"  📈 Average Response Time: {avg_time:.2f}ms")
            print(f"  📈 Min Response Time: {min_time:.2f}ms")
            print(f"  📈 Max Response Time: {max_time:.2f}ms")
            print(f"  📈 Success Rate: {successful_requests}/{num_requests} ({successful_requests/num_requests*100:.1f}%)")
        
        return response_times
    
    def generate_report(self):
        """Generate final test report"""
        total_attacks = self.results['blocked_attacks'] + self.results['passed_attacks']
        block_rate = (self.results['blocked_attacks'] / total_attacks * 100) if total_attacks > 0 else 0
        
        print("\n" + "="*60)
        print("🛡️ WAF Test Results Summary")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        print(f"📊 Attack Statistics:")
        print(f"  Total Attacks: {total_attacks}")
        print(f"  Blocked: {self.results['blocked_attacks']}")
        print(f"  Passed: {self.results['passed_attacks']}")
        print(f"  Block Rate: {block_rate:.1f}%")
        print(f"  False Positives: {self.results['false_positives']}")
        print()
        
        # Protection effectiveness rating
        if block_rate >= 95:
            rating = "🟢 Excellent"
        elif block_rate >= 85:
            rating = "🟡 Good"
        elif block_rate >= 70:
            rating = "🟠 Fair"
        else:
            rating = "🔴 Poor"
        
        print(f"🎯 Protection Rating: {rating}")
        
        # Save results to JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(f'simple_waf_test_results_{timestamp}.json', 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n📄 Detailed results saved to: simple_waf_test_results_{timestamp}.json")

def main():
    print("🛡️ SafeLine WAF Simple Test Suite")
    print("="*50)
    
    # Test configurations
    test_configs = [
        {"url": "http://localhost:8082", "name": "Node.js App (Direct)"},
        {"url": "http://localhost:8081", "name": "Juice Shop (Direct)"},
        {"url": "http://localhost:8080", "name": "DVWA (Direct)"}
    ]
    
    for config in test_configs:
        print(f"\n🎯 Testing: {config['name']}")
        print(f"URL: {config['url']}")
        print("-" * 40)
        
        tester = SimpleWAFTester(config['url'])
        
        # Run all tests
        tester.test_normal_requests()
        tester.test_sql_injection_attacks()
        tester.test_xss_attacks()  
        tester.test_command_injection_attacks()
        tester.performance_test(10)
        tester.generate_report()
        
        print("\n" + "="*50)
        time.sleep(2)  # Pause between different target tests

if __name__ == "__main__":
    main()