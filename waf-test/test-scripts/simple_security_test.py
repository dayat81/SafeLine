#!/usr/bin/env python3

import subprocess
import json
import time
from datetime import datetime

RESULTS_DIR = "/home/pt/SafeLine/waf-test/test-results"
DIRECT_URL = "http://localhost:8080"
PROXY_URL = "http://localhost:8090"

def run_attack_test(url, attack_name, payload, param_name="q"):
    """Run a single attack test and return results"""
    try:
        if param_name == "data":
            # POST request
            cmd = ["curl", "-s", "-w", "\\n%{http_code}", "-X", "POST", 
                   "-d", f"{param_name}={payload}", url]
        else:
            # GET request
            cmd = ["curl", "-s", "-w", "\\n%{http_code}", f"{url}?{param_name}={payload}"]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().split('\\n')
        status_code = lines[-1] if lines else "0"
        
        return {
            "attack": attack_name,
            "payload": payload,
            "status_code": status_code,
            "blocked": status_code in ["403", "406", "400", "500"],
            "response_size": len(result.stdout)
        }
    except Exception as e:
        return {
            "attack": attack_name,
            "payload": payload,
            "status_code": "error",
            "blocked": False,
            "error": str(e)
        }

def main():
    print("=== Simple Security Test Suite ===")
    print(f"Started at: {datetime.now()}")
    
    # Define attack patterns
    attacks = [
        ("SQL Injection - Basic OR", "1' OR '1'='1", "user"),
        ("SQL Injection - Union", "1' UNION SELECT null--", "user"),
        ("XSS - Script Tag", "<script>alert('XSS')</script>", "comment"),
        ("XSS - IMG Tag", "<img src=x onerror=alert(1)>", "comment"),
        ("Command Injection", "127.0.0.1; cat /etc/passwd", "host"),
        ("Path Traversal", "../../../../etc/passwd", "file"),
        ("XXE Basic", "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>", "xml"),
        ("Large Payload", "A" * 10000, "data"),
        ("Null Byte", "test\\x00.php", "filename"),
        ("Directory Traversal", "../../../etc/passwd", "path")
    ]
    
    results = {
        "direct_access": [],
        "proxy_access": []
    }
    
    print("\\nTesting direct access (no protection)...")
    for attack_name, payload, param in attacks:
        result = run_attack_test(DIRECT_URL, attack_name, payload, param)
        results["direct_access"].append(result)
        print(f"  {attack_name}: {result['status_code']}")
    
    print("\\nTesting proxy access (simulated WAF)...")
    for attack_name, payload, param in attacks:
        result = run_attack_test(PROXY_URL, attack_name, payload, param)
        results["proxy_access"].append(result)
        status = "BLOCKED" if result["blocked"] else "PASSED"
        print(f"  {attack_name}: {result['status_code']} ({status})")
    
    # Generate summary
    direct_blocked = sum(1 for r in results["direct_access"] if r["blocked"])
    proxy_blocked = sum(1 for r in results["proxy_access"] if r["blocked"])
    total_attacks = len(attacks)
    
    summary = {
        "test_date": datetime.now().isoformat(),
        "total_attacks": total_attacks,
        "direct_access": {
            "blocked": direct_blocked,
            "detection_rate": f"{direct_blocked/total_attacks*100:.1f}%"
        },
        "proxy_access": {
            "blocked": proxy_blocked,
            "detection_rate": f"{proxy_blocked/total_attacks*100:.1f}%"
        },
        "results": results
    }
    
    # Save results
    with open(f"{RESULTS_DIR}/security_test_results.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    print("\\n=== Test Summary ===")
    print(f"Total Attacks: {total_attacks}")
    print(f"Direct Access Blocked: {direct_blocked}/{total_attacks} ({direct_blocked/total_attacks*100:.1f}%)")
    print(f"Proxy Access Blocked: {proxy_blocked}/{total_attacks} ({proxy_blocked/total_attacks*100:.1f}%)")
    print(f"\\nResults saved to: {RESULTS_DIR}/security_test_results.json")

if __name__ == "__main__":
    main()