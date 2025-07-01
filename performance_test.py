#!/usr/bin/env python3
"""
SafeLine WAF Performance Testing
Focus on performance impact and throughput measurement
"""

from locust import HttpUser, task, between, events
import time
import statistics
import csv
from datetime import datetime

# Performance metrics collection
performance_metrics = {
    'response_times': [],
    'latencies': [],
    'error_rates': [],
    'throughput_samples': []
}

class PerformanceTestUser(HttpUser):
    """Performance testing focused user"""
    wait_time = between(1, 2)
    
    def on_start(self):
        """Initialize performance tracking"""
        self.response_times = []
        self.start_time = time.time()
    
    @task(3)
    def measure_homepage_latency(self):
        """Measure homepage response latency"""
        start_time = time.time()
        
        with self.client.get("/", catch_response=True, name="homepage_perf") as response:
            latency = (time.time() - start_time) * 1000  # Convert to ms
            
            performance_metrics['response_times'].append(latency)
            performance_metrics['latencies'].append(latency)
            
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")
    
    @task(2)
    def measure_api_performance(self):
        """Measure API endpoint performance"""
        start_time = time.time()
        
        with self.client.get("/api/products", 
                          headers={"Accept": "application/json"},
                          catch_response=True, 
                          name="api_perf") as response:
            latency = (time.time() - start_time) * 1000
            performance_metrics['response_times'].append(latency)
            
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"API error: {response.status_code}")
    
    @task(2)
    def heavy_payload_test(self):
        """Test performance with large payloads"""
        # Create 10KB payload
        large_data = "x" * 10000
        start_time = time.time()
        
        with self.client.post("/api/data", 
                            data={"payload": large_data},
                            catch_response=True,
                            name="heavy_payload") as response:
            latency = (time.time() - start_time) * 1000
            performance_metrics['response_times'].append(latency)
            
            if response.status_code in [200, 413]:  # 413 = Payload Too Large
                response.success()
            else:
                response.failure(f"Heavy payload error: {response.status_code}")
    
    @task(1)
    def concurrent_api_calls(self):
        """Simulate multiple API calls in sequence"""
        endpoints = ["/api/status", "/api/products", "/api/health"]
        total_time = 0
        
        for endpoint in endpoints:
            start_time = time.time()
            
            with self.client.get(endpoint, catch_response=True, name=f"concurrent_{endpoint.split('/')[-1]}") as response:
                latency = (time.time() - start_time) * 1000
                total_time += latency
                
                if response.status_code in [200, 404]:
                    response.success()
                else:
                    response.failure(f"Concurrent call failed: {response.status_code}")
        
        # Record total time for concurrent calls
        performance_metrics['response_times'].append(total_time)

class HighThroughputUser(HttpUser):
    """High throughput testing"""
    wait_time = between(0.1, 0.5)
    weight = 3
    
    @task
    def rapid_requests(self):
        """Generate rapid requests to test throughput"""
        endpoints = ["/", "/api/status", "/search?q=test"]
        endpoint = random.choice(endpoints) if 'random' in globals() else endpoints[0]
        
        start_time = time.time()
        
        with self.client.get(endpoint, catch_response=True, name="high_throughput") as response:
            latency = (time.time() - start_time) * 1000
            performance_metrics['throughput_samples'].append(latency)
            
            if response.status_code in [200, 302, 404]:
                response.success()
            else:
                response.failure(f"High throughput error: {response.status_code}")

class StressTestUser(HttpUser):
    """Stress testing with mixed workloads"""
    wait_time = between(0.5, 1)
    weight = 2
    
    @task
    def stress_mixed_workload(self):
        """Mixed workload for stress testing"""
        import random
        
        # Random mix of request types
        request_types = [
            ("GET", "/"),
            ("GET", "/search?q=laptop"),
            ("POST", "/login", {"username": "test", "password": "test"}),
            ("GET", "/user/1"),
            ("GET", "/api/products")
        ]
        
        method, url, data = random.choice(request_types) + (None,) if len(random.choice(request_types)) == 2 else random.choice(request_types)
        
        start_time = time.time()
        
        if method == "GET":
            with self.client.get(url, catch_response=True, name="stress_mixed") as response:
                latency = (time.time() - start_time) * 1000
                performance_metrics['response_times'].append(latency)
                response.success() if response.status_code < 500 else response.failure(f"Server error: {response.status_code}")
        else:
            with self.client.post(url, data=data, catch_response=True, name="stress_mixed") as response:
                latency = (time.time() - start_time) * 1000
                performance_metrics['response_times'].append(latency)
                response.success() if response.status_code < 500 else response.failure(f"Server error: {response.status_code}")

# Event listeners for performance monitoring
@events.test_start.add_listener
def on_performance_test_start(environment, **kwargs):
    """Initialize performance test"""
    print("\n⚡ Starting SafeLine WAF Performance Test")
    print("=" * 50)
    
    # Reset metrics
    performance_metrics['response_times'].clear()
    performance_metrics['latencies'].clear()
    performance_metrics['error_rates'].clear()
    performance_metrics['throughput_samples'].clear()

@events.test_stop.add_listener
def on_performance_test_stop(environment, **kwargs):
    """Generate performance report"""
    if performance_metrics['response_times']:
        avg_latency = statistics.mean(performance_metrics['response_times'])
        median_latency = statistics.median(performance_metrics['response_times'])
        p95_latency = sorted(performance_metrics['response_times'])[int(len(performance_metrics['response_times']) * 0.95)]
        p99_latency = sorted(performance_metrics['response_times'])[int(len(performance_metrics['response_times']) * 0.99)]
    else:
        avg_latency = median_latency = p95_latency = p99_latency = 0
    
    error_rate = (environment.stats.total.num_failures / environment.stats.total.num_requests * 100) if environment.stats.total.num_requests > 0 else 0
    
    print("\n" + "=" * 60)
    print("⚡ SafeLine WAF Performance Test Results")
    print("=" * 60)
    print(f"Total Requests: {environment.stats.total.num_requests}")
    print(f"Failed Requests: {environment.stats.total.num_failures}")
    print(f"Error Rate: {error_rate:.2f}%")
    print(f"Average Latency: {avg_latency:.2f}ms")
    print(f"Median Latency: {median_latency:.2f}ms")
    print(f"95th Percentile: {p95_latency:.2f}ms")
    print(f"99th Percentile: {p99_latency:.2f}ms")
    print(f"Max Response Time: {environment.stats.total.max_response_time}ms")
    print(f"Min Response Time: {environment.stats.total.min_response_time}ms")
    print(f"Requests per Second: {environment.stats.total.total_rps:.2f}")
    
    # Performance rating
    if avg_latency < 50:
        rating = "🟢 Excellent"
    elif avg_latency < 100:
        rating = "🟡 Good"
    elif avg_latency < 200:
        rating = "🟠 Fair"
    else:
        rating = "🔴 Poor"
    
    print(f"Performance Rating: {rating}")
    
    # Save performance metrics
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f'waf_performance_results_{timestamp}.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Metric', 'Value', 'Unit'])
        writer.writerow(['Total Requests', environment.stats.total.num_requests, 'count'])
        writer.writerow(['Failed Requests', environment.stats.total.num_failures, 'count'])
        writer.writerow(['Error Rate', f"{error_rate:.2f}", '%'])
        writer.writerow(['Average Latency', f"{avg_latency:.2f}", 'ms'])
        writer.writerow(['Median Latency', f"{median_latency:.2f}", 'ms'])
        writer.writerow(['95th Percentile', f"{p95_latency:.2f}", 'ms'])
        writer.writerow(['99th Percentile', f"{p99_latency:.2f}", 'ms'])
        writer.writerow(['Max Response Time', environment.stats.total.max_response_time, 'ms'])
        writer.writerow(['Min Response Time', environment.stats.total.min_response_time, 'ms'])
        writer.writerow(['Requests per Second', f"{environment.stats.total.total_rps:.2f}", 'rps'])
        writer.writerow(['Performance Rating', rating.split()[1], 'category'])
    
    print(f"\n📊 Performance results saved to: waf_performance_results_{timestamp}.csv")

if __name__ == "__main__":
    print("SafeLine WAF Performance Test")
    print("Use with: locust -f performance_test.py --host http://your-waf-url")