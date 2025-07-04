#!/usr/bin/env python3
"""
SafeLine Load Testing Runner
Configurable duration and RPS load testing script for SafeLine WAF
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
        
        # Malicious payloads for WAF testing (detection only)
        self.waf_test_payloads = [
            {'method': 'GET', 'path': "/?id=1' OR '1'='1", 'data': None, 'type': 'sql_injection'},
            {'method': 'GET', 'path': '/?search=<script>alert(1)</script>', 'data': None, 'type': 'xss'},
            {'method': 'GET', 'path': '/../../../etc/passwd', 'data': None, 'type': 'path_traversal'},
            {'method': 'POST', 'path': '/login.php', 'data': "username=admin'--&password=test", 'type': 'sql_injection'},
            {'method': 'GET', 'path': '/?cmd=cat /etc/passwd', 'data': None, 'type': 'command_injection'},
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
                request.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            # Add common headers
            request.add_header('User-Agent', 'LoadTestRunner/1.0')
            request.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
            
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
            
            return {
                'success': False,
                'error': str(e),
                'response_time': response_time
            }

    def worker_thread(self, target_url, thread_id):
        """Worker thread for generating load"""
        print(f"Worker thread {thread_id} started")
        
        while self.running:
            # Choose payload type based on thread ID for variety
            if thread_id % 5 == 0:  # 20% malicious payloads for WAF testing
                payload = random.choice(self.waf_test_payloads)
            else:  # 80% normal payloads
                payload = random.choice(self.test_payloads)
            
            result = self.make_request(target_url, payload)
            
            # Sleep to maintain target RPS
            time.sleep(self.request_interval)
        
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