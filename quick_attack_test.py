#!/usr/bin/env python3
"""
Quick Attack Test - Run 20 attacks to demonstrate WAF protection
"""

import requests
import time
import random
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def quick_attack_test():
    target_host = "127.0.0.1"
    target_domain = "dvwa.local"
    
    attacks = [
        ("SQL", "1' OR '1'='1", "/vulnerabilities/sqli/"),
        ("XSS", "<script>alert('xss')</script>", "/search"),
        ("CMD", "; cat /etc/passwd", "/test"),
        ("SQL", "1' UNION SELECT 1,2,3--", "/login.php"),
        ("XSS", "<img src=x onerror=alert('xss')>", "/"),
        ("CMD", "| id", "/admin"),
        ("SQL", "admin'--", "/vulnerabilities/sqli/"),
        ("XSS", "javascript:alert('xss')", "/search"),
        ("CMD", "&& whoami", "/config.php"),
        ("SQL", "1'; DROP TABLE users--", "/"),
        ("XSS", "<svg onload=alert('xss')>", "/index.php"),
        ("CMD", "; ls -la", "/vulnerabilities/exec/"),
        ("SQL", "1' AND 1=1--", "/login.php"),
        ("XSS", "'><script>alert('xss')</script>", "/search"),
        ("CMD", "| cat /etc/hosts", "/admin"),
        ("SQL", "' OR 1=1#", "/vulnerabilities/sqli/"),
        ("XSS", "<iframe src=javascript:alert('xss')>", "/"),
        ("CMD", "&& ps aux", "/test"),
        ("SQL", "1' ORDER BY 10--", "/login.php"),
        ("XSS", "<body onload=alert('xss')>", "/search")
    ]
    
    print("🚀 Quick Attack Test - 20 Attacks")
    print("=" * 60)
    print("Target: {} (Host: {})".format(target_domain, target_host))
    print("-" * 60)
    print("Time     Type | Status Response     | Payload")
    print("-" * 60)
    
    blocked = 0
    success = 0
    errors = 0
    
    for i, (attack_type, payload, path) in enumerate(attacks, 1):
        try:
            headers = {'Host': target_domain}
            params = {'q': payload} if attack_type == "XSS" else {'id': payload}
            
            response = requests.get(
                f"http://{target_host}{path}",
                params=params,
                headers=headers,
                timeout=3
            )
            
            status = response.status_code
            reason = response.reason
            
            if status == 403:
                emoji = "🔒"
                blocked += 1
            elif status == 200:
                emoji = "⚠️"
                success += 1
            else:
                emoji = "❓"
                errors += 1
                
        except requests.exceptions.Timeout:
            status, reason, emoji = 504, "Timeout", "⏱️"
            errors += 1
        except Exception as e:
            status, reason, emoji = 0, "Error", "❌"
            errors += 1
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        payload_short = payload[:40] + "..." if len(payload) > 40 else payload
        
        print(f"{timestamp} {emoji} {attack_type:3} | {status:3} {reason:15} | {payload_short}")
        
        time.sleep(0.5)  # Brief pause between attacks
    
    print("-" * 60)
    print(f"📊 Results Summary:")
    print(f"   🔒 Blocked (403): {blocked}")
    print(f"   ⚠️ Success (200): {success}")
    print(f"   ❓ Errors/Timeouts: {errors}")
    
    if blocked + success + errors > 0:
        block_rate = blocked / (blocked + success + errors) * 100
        print(f"   📈 Block Rate: {block_rate:.1f}%")
        
        if block_rate > 90:
            print("   🛡️ Excellent WAF protection!")
        elif block_rate > 70:
            print("   ✅ Good WAF protection")
        else:
            print("   ⚠️ Needs improvement")

if __name__ == "__main__":
    quick_attack_test()