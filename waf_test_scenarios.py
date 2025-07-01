#!/usr/bin/env python3
"""
SafeLine WAF Test Scenarios using Locust
Comprehensive testing including normal traffic and various attack vectors
"""

from locust import HttpUser, task, between, events
import random
import time
import csv
from datetime import datetime
from locust_config import Config

# Global metrics collection
attack_results = {
    'blocked': 0,
    'passed': 0,
    'false_positives': 0
}

class NormalUser(HttpUser):
    """Normal user behavior - represents legitimate traffic"""
    wait_time = between(1, 3)
    weight = 70  # 70% of users
    
    def on_start(self):
        """Initialize user session"""
        self.test_start_time = time.time()
    
    @task(3)
    def browse_homepage(self):
        """Browse main pages"""
        endpoints = ["/", "/index.html", "/home", "/about"]
        endpoint = random.choice(endpoints)
        
        with self.client.get(endpoint, catch_response=True, name="homepage") as response:
            if response.status_code == 403:
                attack_results['false_positives'] += 1
                response.failure("Normal request blocked (false positive)")
            elif response.status_code in [200, 302, 404]:
                response.success()
    
    @task(2)
    def search_products(self):
        """Search functionality"""
        search_terms = ["laptop", "phone", "tablet", "camera", "headphones", "mouse"]
        term = random.choice(search_terms)
        
        with self.client.get(f"/search?q={term}", catch_response=True, name="search") as response:
            if response.status_code == 403:
                attack_results['false_positives'] += 1
                response.failure("Normal search blocked (false positive)")
            elif response.status_code in [200, 302]:
                response.success()
    
    @task(1) 
    def view_user_profile(self):
        """View user profiles with legitimate IDs"""
        user_id = random.randint(1, 100)
        
        with self.client.get(f"/user/{user_id}", catch_response=True, name="user_profile") as response:
            if response.status_code == 403:
                attack_results['false_positives'] += 1
                response.failure("Normal profile view blocked (false positive)")
            elif response.status_code in [200, 404]:
                response.success()
    
    @task(2)
    def api_requests(self):
        """Legitimate API calls"""
        endpoints = ["/api/products", "/api/status", "/api/health"]
        endpoint = random.choice(endpoints)
        
        headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
        
        with self.client.get(endpoint, headers=headers, catch_response=True, name="api_call") as response:
            if response.status_code == 403:
                attack_results['false_positives'] += 1
                response.failure("Normal API call blocked (false positive)")
            elif response.status_code in [200, 404]:
                response.success()
    
    @task(1)
    def login_attempts(self):
        """Normal login attempts"""
        credentials = [
            {"username": "user1", "password": "password123"},
            {"username": "testuser", "password": "test123"},
            {"username": "demo", "password": "demo"}
        ]
        cred = random.choice(credentials)
        
        with self.client.post("/login", data=cred, catch_response=True, name="login") as response:
            if response.status_code == 403:
                attack_results['false_positives'] += 1
                response.failure("Normal login blocked (false positive)")
            elif response.status_code in [200, 302, 401]:
                response.success()

class SQLInjectionAttacker(HttpUser):
    """SQL Injection attack simulation"""
    wait_time = between(0.5, 2)
    weight = 10  # 10% of users
    
    @task
    def sql_injection_user_endpoint(self):
        """SQL injection via user ID parameter"""
        payload = random.choice(Config.SQL_INJECTION_PAYLOADS)
        
        with self.client.get(
            f"/user/{payload}", 
            catch_response=True,
            name="sqli_user_id"
        ) as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()  # WAF blocked successfully
            else:
                attack_results['passed'] += 1
                response.failure("SQL injection not blocked")
    
    @task
    def sql_injection_search(self):
        """SQL injection via search parameter"""
        payload = random.choice(Config.SQL_INJECTION_PAYLOADS)
        
        with self.client.get(
            f"/search?q={payload}",
            catch_response=True,
            name="sqli_search"
        ) as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()
            else:
                attack_results['passed'] += 1
                response.failure("SQL injection via search not blocked")
    
    @task 
    def sql_injection_login(self):
        """SQL injection via login form"""
        payload = random.choice(Config.SQL_INJECTION_PAYLOADS)
        data = {"username": payload, "password": "anything"}
        
        with self.client.post("/login", data=data, catch_response=True, name="sqli_login") as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()
            else:
                attack_results['passed'] += 1
                response.failure("SQL injection via login not blocked")

class XSSAttacker(HttpUser):
    """Cross-Site Scripting attack simulation"""
    wait_time = between(0.5, 2)
    weight = 10  # 10% of users
    
    @task
    def xss_search_attack(self):
        """XSS via search parameter"""
        payload = random.choice(Config.XSS_PAYLOADS)
        
        with self.client.get(
            f"/search?q={payload}",
            catch_response=True,
            name="xss_search"
        ) as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()
            else:
                attack_results['passed'] += 1
                response.failure("XSS attack not blocked")
    
    @task
    def xss_comment_attack(self):
        """XSS via comment/post functionality"""
        payload = random.choice(Config.XSS_PAYLOADS)
        data = {"comment": payload, "name": "attacker"}
        
        with self.client.post("/comment", data=data, catch_response=True, name="xss_comment") as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()
            else:
                attack_results['passed'] += 1
                response.failure("XSS via comment not blocked")

class CommandInjectionAttacker(HttpUser):
    """Command injection attack simulation"""
    wait_time = between(1, 3)
    weight = 5  # 5% of users
    
    @task
    def command_injection_ping(self):
        """Command injection via ping functionality"""
        payload = random.choice(Config.COMMAND_INJECTION_PAYLOADS)
        data = {"host": payload}
        
        with self.client.post("/ping", json=data, catch_response=True, name="cmdi_ping") as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()
            else:
                attack_results['passed'] += 1
                response.failure("Command injection not blocked")

class DDoSAttacker(HttpUser):
    """DDoS simulation - high volume requests"""
    wait_time = between(0.1, 0.3)
    weight = 5  # 5% of users
    
    @task
    def flood_requests(self):
        """Flood the server with requests"""
        endpoints = ["/", "/search", "/api/status", "/login"]
        endpoint = random.choice(endpoints)
        
        with self.client.get(
            endpoint, 
            catch_response=True,
            name="ddos_flood",
            headers={"User-Agent": "DDoS-Bot-v1.0"}
        ) as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()  # Rate limited successfully
            elif response.status_code == 429:
                attack_results['blocked'] += 1
                response.success()  # Rate limited
            else:
                attack_results['passed'] += 1

class AdvancedAttacker(HttpUser):
    """Advanced attack techniques and evasion"""
    wait_time = between(2, 5)
    weight = 3  # 3% of users
    
    @task
    def evasion_double_encoding(self):
        """Double URL encoding evasion"""
        payload = "%253Cscript%253Ealert('XSS')%253C%252Fscript%253E"
        
        with self.client.get(f"/search?q={payload}", catch_response=True, name="evasion_double_encoding") as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()
            else:
                attack_results['passed'] += 1
                response.failure("Double encoding evasion not blocked")
    
    @task
    def evasion_case_variation(self):
        """Case variation evasion"""
        payload = "1' Or '1'='1"  # Mixed case
        
        with self.client.get(f"/user/{payload}", catch_response=True, name="evasion_case") as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()
            else:
                attack_results['passed'] += 1
                response.failure("Case variation evasion not blocked")
    
    @task
    def evasion_comment_obfuscation(self):
        """SQL comment obfuscation"""
        payload = "1'/**/OR/**/1=1--"
        
        with self.client.get(f"/user/{payload}", catch_response=True, name="evasion_comment") as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()
            else:
                attack_results['passed'] += 1
                response.failure("Comment obfuscation evasion not blocked")
    
    @task
    def path_traversal_attack(self):
        """Directory traversal attack"""
        payload = random.choice(Config.PATH_TRAVERSAL_PAYLOADS)
        
        with self.client.get(f"/file?path={payload}", catch_response=True, name="path_traversal") as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()
            else:
                attack_results['passed'] += 1
                response.failure("Path traversal not blocked")

class BruteForceAttacker(HttpUser):
    """Brute force attack simulation"""
    wait_time = between(0.5, 1)
    weight = 2  # 2% of users
    
    def on_start(self):
        self.attempt_count = 0
    
    @task
    def brute_force_login(self):
        """Brute force login attempts"""
        usernames = ["admin", "root", "administrator", "user", "test"]
        passwords = ["password", "123456", "admin", "root", "pass", "12345"]
        
        username = random.choice(usernames)
        password = random.choice(passwords)
        
        self.attempt_count += 1
        
        with self.client.post(
            "/login", 
            data={"username": username, "password": password},
            catch_response=True,
            name=f"brute_force_attempt_{self.attempt_count}"
        ) as response:
            if response.status_code == 403:
                attack_results['blocked'] += 1
                response.success()  # Blocked by WAF
            elif response.status_code == 429:
                attack_results['blocked'] += 1
                response.success()  # Rate limited
            else:
                attack_results['passed'] += 1

# Event listeners for metrics collection
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Initialize test metrics"""
    print("\n🔥 Starting SafeLine WAF Attack Simulation")
    print("=" * 50)
    
    # Reset metrics
    attack_results['blocked'] = 0
    attack_results['passed'] = 0
    attack_results['false_positives'] = 0

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Generate final metrics report"""
    total_attacks = attack_results['blocked'] + attack_results['passed']
    block_rate = (attack_results['blocked'] / total_attacks * 100) if total_attacks > 0 else 0
    
    print("\n" + "=" * 60)
    print("🛡️ SafeLine WAF Test Results")
    print("=" * 60)
    print(f"Total Attack Attempts: {total_attacks}")
    print(f"Attacks Blocked: {attack_results['blocked']}")
    print(f"Attacks Passed: {attack_results['passed']}")
    print(f"Block Rate: {block_rate:.2f}%")
    print(f"False Positives: {attack_results['false_positives']}")
    print(f"Total Requests: {environment.stats.total.num_requests}")
    print(f"Failed Requests: {environment.stats.total.num_failures}")
    print(f"Average Response Time: {environment.stats.total.avg_response_time:.2f}ms")
    print(f"Max Response Time: {environment.stats.total.max_response_time}ms")
    print(f"Requests per Second: {environment.stats.total.total_rps:.2f}")
    
    # Save detailed metrics to CSV
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f'waf_test_results_{timestamp}.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Total Attacks', total_attacks])
        writer.writerow(['Attacks Blocked', attack_results['blocked']])
        writer.writerow(['Attacks Passed', attack_results['passed']])
        writer.writerow(['Block Rate %', f"{block_rate:.2f}"])
        writer.writerow(['False Positives', attack_results['false_positives']])
        writer.writerow(['Total Requests', environment.stats.total.num_requests])
        writer.writerow(['Failed Requests', environment.stats.total.num_failures])
        writer.writerow(['Avg Response Time ms', environment.stats.total.avg_response_time])
        writer.writerow(['Max Response Time ms', environment.stats.total.max_response_time])
        writer.writerow(['Requests per Second', environment.stats.total.total_rps])
    
    print(f"\n📊 Detailed results saved to: waf_test_results_{timestamp}.csv")

if __name__ == "__main__":
    # Can be run standalone for testing
    print("SafeLine WAF Test Scenarios")
    print("Use with: locust -f waf_test_scenarios.py --host http://your-waf-url")