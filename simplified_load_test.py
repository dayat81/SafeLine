#!/usr/bin/env python3
"""
Simplified High-Throughput Load Testing for SafeLine WAF
Compatible with system Python environment
"""

import urllib.request
import urllib.parse
import urllib.error
import threading
import time
import json
import random
from datetime import datetime
import concurrent.futures
import sys

class SimplifiedLoadTester:
    def __init__(self, target_url="http://localhost", max_threads=100):
        self.target_url = target_url.rstrip('/')
        self.max_threads = max_threads
        self.results = []
        self.attack_patterns = {
            'sql_injection': [
                "1' OR '1'='1",
                "1' UNION SELECT null,null--",
                "1'; DROP TABLE users--",
                "1' AND (SELECT SLEEP(5))--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')"
            ],
            'command_injection': [
                "; cat /etc/passwd",
                "| whoami",
                "&& id",
                "|| uname -a"
            ],
            'path_traversal': [
                "../../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "/etc/passwd%00"
            ]
        }
    
    def make_request(self, attack_type, payload, endpoint="/"):
        """Make a single HTTP request with attack payload"""
        start_time = time.time()
        attack_id = f"{attack_type}_{int(time.time()*1000000) % 1000000}"
        
        try:
            # Prepare URL with payload
            if endpoint == "/":
                url = f"{self.target_url}/?q={urllib.parse.quote(payload)}"
            else:
                url = f"{self.target_url}{endpoint}?param={urllib.parse.quote(payload)}"
            
            # Make request
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'SafeLine-LoadTest/1.0')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                response_time = time.time() - start_time
                status_code = response.getcode()
                content = response.read().decode('utf-8', errors='ignore')
                
                # Determine if blocked
                blocked = self._is_blocked(status_code, content)
                
                return {
                    'timestamp': start_time,
                    'attack_id': attack_id,
                    'attack_type': attack_type,
                    'payload': payload[:100],  # Truncate for logging
                    'status_code': status_code,
                    'response_time': response_time,
                    'blocked': blocked,
                    'success': True
                }
        
        except urllib.error.HTTPError as e:
            response_time = time.time() - start_time
            blocked = e.code in [403, 406, 429, 444]
            
            return {
                'timestamp': start_time,
                'attack_id': attack_id,
                'attack_type': attack_type,
                'payload': payload[:100],
                'status_code': e.code,
                'response_time': response_time,
                'blocked': blocked,
                'success': True
            }
        
        except Exception as e:
            return {
                'timestamp': start_time,
                'attack_id': attack_id,
                'attack_type': attack_type,
                'payload': payload[:100],
                'status_code': 0,
                'response_time': time.time() - start_time,
                'blocked': False,
                'success': False,
                'error': str(e)
            }
    
    def _is_blocked(self, status_code, content):
        """Determine if request was blocked"""
        if status_code in [403, 406, 429, 444]:
            return True
        
        # Check content for block indicators
        block_indicators = ['blocked', 'denied', 'security', 'safeline']
        content_lower = content.lower()
        
        for indicator in block_indicators:
            if indicator in content_lower:
                return True
        
        return False
    
    def load_test_worker(self, duration, requests_per_second):
        """Worker thread for load testing"""
        end_time = time.time() + duration
        request_interval = 1.0 / requests_per_second
        
        local_results = []
        
        while time.time() < end_time:
            # Select random attack
            attack_type = random.choice(list(self.attack_patterns.keys()))
            payload = random.choice(self.attack_patterns[attack_type])
            
            # Make request
            result = self.make_request(attack_type, payload)
            local_results.append(result)
            
            # Rate limiting
            time.sleep(request_interval)
        
        return local_results
    
    def run_load_test(self, duration=60, target_rps=100):
        """Run concurrent load test"""
        print(f"Starting load test: {duration}s duration, {target_rps} RPS target")
        
        # Calculate requests per thread
        rps_per_thread = max(1, target_rps // self.max_threads)
        
        # Start worker threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for i in range(self.max_threads):
                future = executor.submit(self.load_test_worker, duration, rps_per_thread)
                futures.append(future)
            
            # Collect results
            all_results = []
            for future in concurrent.futures.as_completed(futures):
                try:
                    thread_results = future.result()
                    all_results.extend(thread_results)
                except Exception as e:
                    print(f"Thread failed: {e}")
        
        return all_results
    
    def analyze_results(self, results):
        """Analyze test results"""
        if not results:
            return {"error": "No results to analyze"}
        
        total_requests = len(results)
        successful_requests = sum(1 for r in results if r.get('success', False))
        blocked_requests = sum(1 for r in results if r.get('blocked', False))
        
        # Calculate response times
        response_times = [r['response_time'] for r in results if r.get('response_time', 0) > 0]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Attack type breakdown
        attack_breakdown = {}
        for result in results:
            attack_type = result.get('attack_type', 'unknown')
            if attack_type not in attack_breakdown:
                attack_breakdown[attack_type] = {'total': 0, 'blocked': 0}
            
            attack_breakdown[attack_type]['total'] += 1
            if result.get('blocked', False):
                attack_breakdown[attack_type]['blocked'] += 1
        
        # Calculate detection rates
        for attack_type in attack_breakdown:
            total = attack_breakdown[attack_type]['total']
            blocked = attack_breakdown[attack_type]['blocked']
            attack_breakdown[attack_type]['detection_rate'] = (blocked / total * 100) if total > 0 else 0
        
        # Status code distribution
        status_codes = {}
        for result in results:
            code = result.get('status_code', 0)
            status_codes[code] = status_codes.get(code, 0) + 1
        
        return {
            'summary': {
                'total_requests': total_requests,
                'successful_requests': successful_requests,
                'blocked_requests': blocked_requests,
                'overall_detection_rate': (blocked_requests / total_requests * 100) if total_requests > 0 else 0,
                'avg_response_time_ms': avg_response_time * 1000,
                'actual_rps': total_requests / (max(r['timestamp'] for r in results) - min(r['timestamp'] for r in results)) if len(results) > 1 else 0
            },
            'attack_breakdown': attack_breakdown,
            'status_distribution': status_codes
        }

def main():
    print("=== SafeLine Simplified Load Testing ===")
    print(f"Start time: {datetime.now()}")
    
    # Configuration
    target_url = "http://localhost"
    duration = 60  # 1 minute test
    target_rps = 50  # Conservative RPS for simplified test
    max_threads = 20
    
    # Check if target is accessible
    try:
        with urllib.request.urlopen(f"{target_url}/", timeout=5) as response:
            print(f"Target accessible: {target_url} (Status: {response.getcode()})")
    except Exception as e:
        print(f"Target not accessible: {target_url} - {e}")
        print("Note: This test can still run to demonstrate the framework")
    
    # Initialize tester
    tester = SimplifiedLoadTester(target_url, max_threads)
    
    # Run load test
    print(f"Executing load test: {duration}s at {target_rps} RPS...")
    results = tester.run_load_test(duration, target_rps)
    
    # Analyze results
    analysis = tester.analyze_results(results)
    
    # Print results
    print("\n=== Test Results ===")
    if 'error' in analysis:
        print(f"Error: {analysis['error']}")
    else:
        summary = analysis['summary']
        print(f"Total Requests: {summary['total_requests']:,}")
        print(f"Successful Requests: {summary['successful_requests']:,}")
        print(f"Blocked Requests: {summary['blocked_requests']:,}")
        print(f"Detection Rate: {summary['overall_detection_rate']:.1f}%")
        print(f"Average Response Time: {summary['avg_response_time_ms']:.1f}ms")
        print(f"Actual RPS: {summary['actual_rps']:.1f}")
        
        print("\n=== Attack Type Breakdown ===")
        for attack_type, stats in analysis['attack_breakdown'].items():
            print(f"{attack_type}: {stats['blocked']}/{stats['total']} blocked ({stats['detection_rate']:.1f}%)")
        
        print("\n=== Status Code Distribution ===")
        for status, count in sorted(analysis['status_distribution'].items()):
            print(f"Status {status}: {count}")
    
    # Save results
    output_file = f"/home/pt/SafeLine/test_results_advanced/load_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump({
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'target_url': target_url,
                'duration': duration,
                'target_rps': target_rps,
                'max_threads': max_threads
            },
            'analysis': analysis,
            'raw_results': results
        }, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    print(f"Test completed at: {datetime.now()}")

if __name__ == "__main__":
    main()