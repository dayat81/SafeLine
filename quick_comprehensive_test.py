#!/usr/bin/env python3
"""
Quick Comprehensive Test - Complete execution demonstration
"""

import urllib.request
import urllib.parse
import time
import json
import random
import threading
from datetime import datetime

def log_event(message):
    """Log events with timestamp"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")
    
    # Append to execution log
    log_entry = f"\n### {timestamp} - {message}\n"
    with open("/home/pt/SafeLine/COMPLETE_EXECUTION_LOG.md", "a") as f:
        f.write(log_entry)

def test_target(url, attack_payload):
    """Test single target with attack payload"""
    try:
        test_url = f"{url}/?test={urllib.parse.quote(attack_payload)}"
        req = urllib.request.Request(test_url)
        req.add_header('User-Agent', 'SafeLine-QuickTest/1.0')
        
        start_time = time.time()
        with urllib.request.urlopen(req, timeout=5) as response:
            response_time = time.time() - start_time
            status_code = response.getcode()
            content = response.read().decode('utf-8', errors='ignore')[:200]
            
            # Check if blocked
            blocked = status_code in [403, 406, 429] or 'blocked' in content.lower()
            
            return {
                'url': url,
                'payload': attack_payload[:50],
                'status': status_code,
                'response_time': response_time,
                'blocked': blocked,
                'success': True
            }
    except Exception as e:
        return {
            'url': url,
            'payload': attack_payload[:50],
            'status': 0,
            'response_time': 0,
            'blocked': False,
            'success': False,
            'error': str(e)[:100]
        }

def main():
    log_event("Quick Comprehensive Test Started")
    
    # Test targets
    targets = [
        'http://localhost:8080',   # Vulnerable app
        'http://localhost:8090',   # Proxy/WAF
    ]
    
    # Attack payloads
    attack_payloads = [
        "1' OR '1'='1",                           # SQL Injection
        "<script>alert('XSS')</script>",          # XSS
        "; cat /etc/passwd",                      # Command Injection
        "../../../../etc/passwd",                 # Path Traversal
        "<img src=x onerror=alert(1)>",          # XSS Event Handler
        "1' UNION SELECT null,null--",            # SQL Union
        "|| whoami",                              # Command Injection
        "javascript:alert('test')",               # XSS JavaScript
        "../../../windows/system32/config/sam",  # Windows Path Traversal
        "1'; DROP TABLE users--"                 # SQL Drop Table
    ]
    
    log_event(f"Testing {len(targets)} targets with {len(attack_payloads)} attack patterns")
    
    all_results = []
    
    # Test each target with each payload
    for target in targets:
        log_event(f"Testing target: {target}")
        
        target_results = []
        for payload in attack_payloads:
            result = test_target(target, payload)
            target_results.append(result)
            all_results.append(result)
            time.sleep(0.1)  # Small delay
        
        # Analyze target results
        successful = sum(1 for r in target_results if r['success'])
        blocked = sum(1 for r in target_results if r['blocked'])
        avg_response_time = sum(r['response_time'] for r in target_results if r['success']) / max(successful, 1)
        
        log_event(f"Target {target}: {successful}/{len(attack_payloads)} successful, {blocked} blocked, {avg_response_time*1000:.1f}ms avg")
    
    # Overall analysis
    log_event("Analyzing overall results")
    
    total_tests = len(all_results)
    successful_tests = sum(1 for r in all_results if r['success'])
    blocked_tests = sum(1 for r in all_results if r['blocked'])
    error_tests = sum(1 for r in all_results if not r['success'])
    
    overall_detection_rate = (blocked_tests / total_tests * 100) if total_tests > 0 else 0
    success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
    
    # Save results
    results_data = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'test_type': 'quick_comprehensive_test',
            'targets': targets,
            'total_attacks': len(attack_payloads),
            'total_tests': total_tests
        },
        'summary': {
            'total_tests': total_tests,
            'successful_tests': successful_tests,
            'blocked_tests': blocked_tests,
            'error_tests': error_tests,
            'detection_rate': overall_detection_rate,
            'success_rate': success_rate
        },
        'results': all_results
    }
    
    # Save to file
    output_file = f"/home/pt/SafeLine/full_test_results/quick_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    log_event(f"Results saved to: {output_file}")
    
    # Print summary
    log_event("=== QUICK TEST SUMMARY ===")
    log_event(f"Total Tests: {total_tests}")
    log_event(f"Successful: {successful_tests} ({success_rate:.1f}%)")
    log_event(f"Blocked: {blocked_tests} ({overall_detection_rate:.1f}%)")
    log_event(f"Errors: {error_tests}")
    
    # Test breakdown by target
    log_event("=== TARGET BREAKDOWN ===")
    for target in targets:
        target_results = [r for r in all_results if r['url'] == target]
        target_blocked = sum(1 for r in target_results if r['blocked'])
        target_success = sum(1 for r in target_results if r['success'])
        target_detection_rate = (target_blocked / len(target_results) * 100) if target_results else 0
        
        log_event(f"{target}: {target_blocked}/{len(target_results)} blocked ({target_detection_rate:.1f}%)")
    
    log_event("Quick Comprehensive Test Completed Successfully")
    
    return results_data

if __name__ == "__main__":
    main()