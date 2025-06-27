#!/usr/bin/env python3

import concurrent.futures
import requests
import time
import statistics
import json
import random
import os
from datetime import datetime

RESULTS_DIR = f"/results/throughput_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(RESULTS_DIR, exist_ok=True)

WAF_URL = "http://safeline-tengine"
DIRECT_URL = "http://vulnerable-app"

# Attack patterns for mixed traffic
ATTACK_PATTERNS = [
    ("sql", "1' OR '1'='1"),
    ("xss", "<script>alert('test')</script>"),
    ("cmd", "127.0.0.1; cat /etc/passwd"),
    ("path", "../../../../etc/passwd"),
    ("sqli_union", "1' UNION SELECT null,null--"),
    ("xss_img", "<img src=x onerror=alert(1)>"),
    ("cmd_pipe", "test | whoami"),
    ("xxe", "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>")
]

def make_request(url, attack_type=None, session=None):
    """Make a single HTTP request with optional attack payload"""
    headers = {
        "User-Agent": "Mozilla/5.0 (LoadTest/1.0)",
        "Accept": "text/html,application/json"
    }
    params = {}
    
    if attack_type:
        attack_name, payload = random.choice(ATTACK_PATTERNS)
        if attack_name in ["sql", "sqli_union"]:
            params = {"id": payload}
        elif attack_name in ["xss", "xss_img"]:
            params = {"name": payload}
        elif attack_name in ["cmd", "cmd_pipe"]:
            params = {"host": payload}
        elif attack_name in ["path"]:
            params = {"page": payload}
        headers["X-Attack-Type"] = attack_name
    
    try:
        start = time.time()
        if session:
            response = session.get(url, params=params, headers=headers, timeout=5)
        else:
            response = requests.get(url, params=params, headers=headers, timeout=5)
        duration = time.time() - start
        
        return {
            "status": response.status_code,
            "duration": duration,
            "attack": attack_type is not None,
            "timestamp": time.time()
        }
    except requests.exceptions.Timeout:
        return {
            "status": 0,
            "duration": 5.0,
            "attack": attack_type is not None,
            "error": "timeout",
            "timestamp": time.time()
        }
    except Exception as e:
        return {
            "status": 0,
            "duration": 0,
            "attack": attack_type is not None,
            "error": str(e),
            "timestamp": time.time()
        }

def run_mixed_traffic_test(url, duration=60, workers=100, attack_ratio=0.2):
    """Run high-throughput test with mixed legitimate and attack traffic"""
    print(f"\n=== Mixed Traffic Test ===")
    print(f"Target: {url}")
    print(f"Duration: {duration}s")
    print(f"Workers: {workers}")
    print(f"Attack ratio: {attack_ratio*100}%")
    
    results = []
    start_time = time.time()
    request_count = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        # Use session for connection pooling
        session = requests.Session()
        session.mount('http://', requests.adapters.HTTPAdapter(pool_connections=workers, pool_maxsize=workers))
        
        futures = []
        
        while time.time() - start_time < duration:
            # Determine if this should be an attack request
            is_attack = random.random() < attack_ratio
            
            future = executor.submit(make_request, url, "attack" if is_attack else None, session)
            futures.append(future)
            request_count += 1
            
            # Control request rate
            time.sleep(0.001)
        
        # Collect results
        print("Collecting results...")
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"Error collecting result: {e}")
    
    return analyze_results(results, duration)

def run_stress_test(url, duration=30, initial_rate=100, max_rate=5000, step=100):
    """Gradually increase load to find breaking point"""
    print(f"\n=== Stress Test ===")
    print(f"Finding maximum sustainable RPS...")
    
    current_rate = initial_rate
    results_by_rate = {}
    
    while current_rate <= max_rate:
        print(f"\nTesting at {current_rate} RPS...")
        
        results = []
        workers = min(current_rate, 200)  # Cap workers at 200
        delay = 1.0 / current_rate
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            start_time = time.time()
            futures = []
            
            while time.time() - start_time < 10:  # 10 second test per rate
                future = executor.submit(make_request, url)
                futures.append(future)
                time.sleep(delay)
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except:
                    pass
        
        # Analyze results for this rate
        successful = sum(1 for r in results if r["status"] == 200)
        success_rate = successful / len(results) * 100 if results else 0
        avg_response_time = statistics.mean([r["duration"] for r in results if r["duration"] > 0])
        
        results_by_rate[current_rate] = {
            "success_rate": success_rate,
            "avg_response_time": avg_response_time,
            "total_requests": len(results)
        }
        
        print(f"  Success rate: {success_rate:.1f}%")
        print(f"  Avg response time: {avg_response_time*1000:.1f}ms")
        
        # Stop if success rate drops below 95% or response time exceeds 1 second
        if success_rate < 95 or avg_response_time > 1.0:
            print(f"\nMaximum sustainable rate: {current_rate - step} RPS")
            break
        
        current_rate += step
    
    return results_by_rate

def run_spike_test(url, baseline_rate=100, spike_rate=2000, spike_duration=10):
    """Test WAF behavior during traffic spikes"""
    print(f"\n=== Spike Test ===")
    print(f"Baseline rate: {baseline_rate} RPS")
    print(f"Spike rate: {spike_rate} RPS")
    print(f"Spike duration: {spike_duration}s")
    
    results = []
    phases = [
        ("Pre-spike", baseline_rate, 20),
        ("Spike", spike_rate, spike_duration),
        ("Recovery", baseline_rate, 20)
    ]
    
    for phase_name, rate, duration in phases:
        print(f"\n{phase_name} phase ({rate} RPS for {duration}s)...")
        phase_results = run_mixed_traffic_test(url, duration=duration, 
                                             workers=min(rate, 200), 
                                             attack_ratio=0.1)
        phase_results["phase"] = phase_name
        results.append(phase_results)
    
    return results

def analyze_results(results, duration):
    """Analyze test results and generate statistics"""
    total_requests = len(results)
    successful_requests = sum(1 for r in results if r["status"] == 200)
    blocked_attacks = sum(1 for r in results if r["attack"] and r["status"] in [403, 406])
    total_attacks = sum(1 for r in results if r["attack"])
    failed_requests = sum(1 for r in results if r["status"] == 0)
    
    response_times = [r["duration"] for r in results if r["status"] > 0 and r["duration"] > 0]
    
    # Calculate percentiles
    if response_times:
        response_times_sorted = sorted(response_times)
        p50 = response_times_sorted[int(len(response_times_sorted) * 0.50)]
        p95 = response_times_sorted[int(len(response_times_sorted) * 0.95)]
        p99 = response_times_sorted[int(len(response_times_sorted) * 0.99)]
    else:
        p50 = p95 = p99 = 0
    
    # Calculate throughput over time
    timestamps = [r["timestamp"] for r in results if "timestamp" in r]
    if timestamps:
        time_range = max(timestamps) - min(timestamps)
        actual_rps = total_requests / time_range if time_range > 0 else 0
    else:
        actual_rps = total_requests / duration
    
    analysis = {
        "total_requests": total_requests,
        "successful_requests": successful_requests,
        "failed_requests": failed_requests,
        "error_rate": (failed_requests / total_requests * 100) if total_requests > 0 else 0,
        "total_attacks": total_attacks,
        "blocked_attacks": blocked_attacks,
        "attack_detection_rate": (blocked_attacks / total_attacks * 100) if total_attacks > 0 else 0,
        "actual_rps": actual_rps,
        "response_times": {
            "mean": statistics.mean(response_times) if response_times else 0,
            "median": p50,
            "p95": p95,
            "p99": p99,
            "min": min(response_times) if response_times else 0,
            "max": max(response_times) if response_times else 0
        }
    }
    
    return analysis

def generate_performance_report(test_results):
    """Generate comprehensive performance test report"""
    report = {
        "test_date": datetime.now().isoformat(),
        "test_results": test_results
    }
    
    # Save JSON report
    with open(f"{RESULTS_DIR}/performance_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    # Generate HTML report with charts
    html_report = f"""
    <html>
    <head>
        <title>SafeLine WAF Performance Test Report</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .metric {{ display: inline-block; margin: 10px 20px; }}
            .chart-container {{ width: 80%; margin: 20px auto; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; }}
        </style>
    </head>
    <body>
        <h1>SafeLine WAF Performance Test Report</h1>
        <div class="summary">
            <h2>Test Summary</h2>
            <p>Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    """
    
    # Add results for each test type
    if "mixed_traffic" in test_results:
        mixed = test_results["mixed_traffic"]
        html_report += f"""
        <h2>Mixed Traffic Test Results</h2>
        <div class="summary">
            <div class="metric">
                <strong>Total Requests:</strong> {mixed['total_requests']:,}
            </div>
            <div class="metric">
                <strong>Actual RPS:</strong> {mixed['actual_rps']:.1f}
            </div>
            <div class="metric">
                <strong>Error Rate:</strong> {mixed['error_rate']:.2f}%
            </div>
            <div class="metric">
                <strong>Attack Detection:</strong> {mixed['attack_detection_rate']:.1f}%
            </div>
        </div>
        
        <h3>Response Time Statistics</h3>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value (ms)</th>
            </tr>
            <tr>
                <td>Mean</td>
                <td>{mixed['response_times']['mean']*1000:.2f}</td>
            </tr>
            <tr>
                <td>Median (P50)</td>
                <td>{mixed['response_times']['median']*1000:.2f}</td>
            </tr>
            <tr>
                <td>95th Percentile</td>
                <td>{mixed['response_times']['p95']*1000:.2f}</td>
            </tr>
            <tr>
                <td>99th Percentile</td>
                <td>{mixed['response_times']['p99']*1000:.2f}</td>
            </tr>
        </table>
        """
    
    if "stress_test" in test_results:
        html_report += """
        <h2>Stress Test Results</h2>
        <div class="chart-container">
            <canvas id="stressChart"></canvas>
        </div>
        <script>
        const stressData = """ + json.dumps(test_results["stress_test"]) + """;
        const rates = Object.keys(stressData).map(Number).sort((a,b) => a-b);
        const successRates = rates.map(r => stressData[r].success_rate);
        const responseTimes = rates.map(r => stressData[r].avg_response_time * 1000);
        
        new Chart(document.getElementById('stressChart'), {
            type: 'line',
            data: {
                labels: rates,
                datasets: [{
                    label: 'Success Rate (%)',
                    data: successRates,
                    borderColor: 'green',
                    yAxisID: 'y-success'
                }, {
                    label: 'Response Time (ms)',
                    data: responseTimes,
                    borderColor: 'red',
                    yAxisID: 'y-time'
                }]
            },
            options: {
                scales: {
                    'y-success': {
                        type: 'linear',
                        position: 'left',
                        max: 100
                    },
                    'y-time': {
                        type: 'linear',
                        position: 'right'
                    }
                }
            }
        });
        </script>
        """
    
    html_report += """
    </body>
    </html>
    """
    
    with open(f"{RESULTS_DIR}/performance_report.html", "w") as f:
        f.write(html_report)

def main():
    print("=== SafeLine WAF High-Throughput Performance Test ===")
    print(f"Started at: {datetime.now()}")
    print(f"Results directory: {RESULTS_DIR}")
    
    test_results = {}
    
    # Test 1: Mixed traffic (legitimate + attacks)
    print("\n--- Running Mixed Traffic Test ---")
    mixed_results = run_mixed_traffic_test(WAF_URL, duration=60, workers=100, attack_ratio=0.2)
    test_results["mixed_traffic"] = mixed_results
    
    print("\n=== Mixed Traffic Test Results ===")
    print(f"Total Requests: {mixed_results['total_requests']:,}")
    print(f"Successful: {mixed_results['successful_requests']:,}")
    print(f"Failed: {mixed_results['failed_requests']:,}")
    print(f"Actual RPS: {mixed_results['actual_rps']:.1f}")
    print(f"Attack Detection Rate: {mixed_results['attack_detection_rate']:.1f}%")
    print(f"Response Times (ms):")
    print(f"  Mean: {mixed_results['response_times']['mean']*1000:.2f}")
    print(f"  P50: {mixed_results['response_times']['median']*1000:.2f}")
    print(f"  P95: {mixed_results['response_times']['p95']*1000:.2f}")
    print(f"  P99: {mixed_results['response_times']['p99']*1000:.2f}")
    
    # Test 2: Stress test (find breaking point)
    print("\n--- Running Stress Test ---")
    stress_results = run_stress_test(WAF_URL)
    test_results["stress_test"] = stress_results
    
    # Test 3: Spike test
    print("\n--- Running Spike Test ---")
    spike_results = run_spike_test(WAF_URL)
    test_results["spike_test"] = spike_results
    
    # Generate reports
    generate_performance_report(test_results)
    
    print(f"\n=== All Tests Completed ===")
    print(f"Reports saved to: {RESULTS_DIR}")
    print(f"Completed at: {datetime.now()}")

if __name__ == "__main__":
    main()