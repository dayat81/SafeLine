#!/usr/bin/env python3
"""
Real-time Load Testing Monitor for SafeLine WAF
Provides real-time metrics during high-throughput testing
"""

import asyncio
import time
import json
import psutil
import docker
import requests
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, List, Any
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.dates import DateFormatter
import pandas as pd
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SystemMetrics:
    timestamp: float
    cpu_percent: float
    memory_percent: float
    network_io: Dict[str, int]
    disk_io: Dict[str, int]

@dataclass
class WAFMetrics:
    timestamp: float
    total_requests: int
    blocked_requests: int
    response_time_avg: float
    response_time_p95: float
    response_time_p99: float
    error_rate: float
    detection_rate: float

class MetricsExporter(BaseHTTPRequestHandler):
    """Simple HTTP server to export metrics for Prometheus"""
    
    def __init__(self, monitor):
        self.monitor = monitor
        super().__init__()
    
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
            metrics = self.monitor.get_prometheus_metrics()
            self.wfile.write(metrics.encode())
        else:
            self.send_response(404)
            self.end_headers()

class LoadTestMonitor:
    """Real-time monitoring system for load testing"""
    
    def __init__(self, target_url: str = "http://localhost"):
        self.target_url = target_url
        self.docker_client = docker.from_env()
        self.metrics_history = []
        self.system_metrics_history = []
        self.waf_metrics_history = []
        self.running = False
        
        # Containers to monitor
        self.containers = [
            'safeline-mgt-advanced',
            'safeline-tengine-advanced', 
            'safeline-detector-advanced',
            'safeline-pg-advanced'
        ]
        
        # Current metrics
        self.current_metrics = {
            'rps': 0,
            'blocked_rps': 0,
            'response_time': 0,
            'error_rate': 0,
            'cpu_usage': 0,
            'memory_usage': 0,
            'detection_rate': 0
        }
    
    def get_container_stats(self) -> Dict[str, Any]:
        """Get Docker container statistics"""
        stats = {}
        
        for container_name in self.containers:
            try:
                container = self.docker_client.containers.get(container_name)
                if container.status == 'running':
                    container_stats = container.stats(stream=False)
                    
                    # CPU usage
                    cpu_delta = (container_stats['cpu_stats']['cpu_usage']['total_usage'] - 
                               container_stats['precpu_stats']['cpu_usage']['total_usage'])
                    system_delta = (container_stats['cpu_stats']['system_cpu_usage'] - 
                                  container_stats['precpu_stats']['system_cpu_usage'])
                    cpu_percent = (cpu_delta / system_delta) * len(container_stats['cpu_stats']['cpu_usage']['percpu_usage']) * 100
                    
                    # Memory usage
                    memory_usage = container_stats['memory_stats']['usage']
                    memory_limit = container_stats['memory_stats']['limit']
                    memory_percent = (memory_usage / memory_limit) * 100
                    
                    stats[container_name] = {
                        'cpu_percent': cpu_percent,
                        'memory_percent': memory_percent,
                        'memory_usage_mb': memory_usage / 1024 / 1024,
                        'memory_limit_mb': memory_limit / 1024 / 1024
                    }
            except Exception as e:
                logger.warning(f"Failed to get stats for {container_name}: {e}")
                stats[container_name] = None
        
        return stats
    
    def get_system_metrics(self) -> SystemMetrics:
        """Get system-level metrics"""
        return SystemMetrics(
            timestamp=time.time(),
            cpu_percent=psutil.cpu_percent(interval=1),
            memory_percent=psutil.virtual_memory().percent,
            network_io=psutil.net_io_counters()._asdict(),
            disk_io=psutil.disk_io_counters()._asdict()
        )
    
    def get_waf_metrics(self) -> WAFMetrics:
        """Get WAF-specific metrics from Prometheus"""
        try:
            # Query Prometheus for metrics
            prometheus_url = "http://localhost:9090/api/v1/query"
            
            queries = {
                'total_requests': 'rate(safeline_requests_total[1m])',
                'blocked_requests': 'rate(safeline_requests_blocked_total[1m])',
                'response_time_avg': 'histogram_quantile(0.50, rate(safeline_request_duration_seconds_bucket[5m]))',
                'response_time_p95': 'histogram_quantile(0.95, rate(safeline_request_duration_seconds_bucket[5m]))',
                'response_time_p99': 'histogram_quantile(0.99, rate(safeline_request_duration_seconds_bucket[5m]))',
                'error_rate': 'rate(safeline_requests_total{status=~"5.."}[1m]) / rate(safeline_requests_total[1m])'
            }
            
            metrics = {}
            for metric_name, query in queries.items():
                try:
                    response = requests.get(prometheus_url, params={'query': query}, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if data['data']['result']:
                            metrics[metric_name] = float(data['data']['result'][0]['value'][1])
                        else:
                            metrics[metric_name] = 0
                    else:
                        metrics[metric_name] = 0
                except Exception as e:
                    logger.warning(f"Failed to query {metric_name}: {e}")
                    metrics[metric_name] = 0
            
            total_requests = metrics.get('total_requests', 0)
            blocked_requests = metrics.get('blocked_requests', 0)
            detection_rate = (blocked_requests / total_requests * 100) if total_requests > 0 else 0
            
            return WAFMetrics(
                timestamp=time.time(),
                total_requests=total_requests,
                blocked_requests=blocked_requests,
                response_time_avg=metrics.get('response_time_avg', 0),
                response_time_p95=metrics.get('response_time_p95', 0),
                response_time_p99=metrics.get('response_time_p99', 0),
                error_rate=metrics.get('error_rate', 0) * 100,
                detection_rate=detection_rate
            )
            
        except Exception as e:
            logger.warning(f"Failed to get WAF metrics: {e}")
            return WAFMetrics(
                timestamp=time.time(),
                total_requests=0,
                blocked_requests=0,
                response_time_avg=0,
                response_time_p95=0,
                response_time_p99=0,
                error_rate=0,
                detection_rate=0
            )
    
    async def collect_metrics(self):
        """Continuously collect metrics"""
        while self.running:
            try:
                # Collect system metrics
                system_metrics = self.get_system_metrics()
                self.system_metrics_history.append(system_metrics)
                
                # Collect WAF metrics
                waf_metrics = self.get_waf_metrics()
                self.waf_metrics_history.append(waf_metrics)
                
                # Collect container stats
                container_stats = self.get_container_stats()
                
                # Update current metrics for display
                self.current_metrics.update({
                    'rps': waf_metrics.total_requests,
                    'blocked_rps': waf_metrics.blocked_requests,
                    'response_time': waf_metrics.response_time_avg * 1000,  # Convert to ms
                    'error_rate': waf_metrics.error_rate,
                    'cpu_usage': system_metrics.cpu_percent,
                    'memory_usage': system_metrics.memory_percent,
                    'detection_rate': waf_metrics.detection_rate
                })
                
                # Store combined metrics
                combined_metrics = {
                    'timestamp': time.time(),
                    'system': system_metrics,
                    'waf': waf_metrics,
                    'containers': container_stats
                }
                
                self.metrics_history.append(combined_metrics)
                
                # Keep only last 1000 data points
                if len(self.metrics_history) > 1000:
                    self.metrics_history = self.metrics_history[-1000:]
                    self.system_metrics_history = self.system_metrics_history[-1000:]
                    self.waf_metrics_history = self.waf_metrics_history[-1000:]
                
                # Log current status
                logger.info(f"RPS: {waf_metrics.total_requests:.0f} | "
                          f"Blocked: {waf_metrics.blocked_requests:.0f} | "
                          f"Detection: {waf_metrics.detection_rate:.1f}% | "
                          f"Response: {waf_metrics.response_time_avg*1000:.1f}ms | "
                          f"CPU: {system_metrics.cpu_percent:.1f}% | "
                          f"Memory: {system_metrics.memory_percent:.1f}%")
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
            
            await asyncio.sleep(2)  # Collect every 2 seconds
    
    def get_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format"""
        if not self.current_metrics:
            return ""
        
        metrics = [
            f"load_test_rps {self.current_metrics['rps']}",
            f"load_test_blocked_rps {self.current_metrics['blocked_rps']}",
            f"load_test_response_time_ms {self.current_metrics['response_time']}",
            f"load_test_error_rate {self.current_metrics['error_rate']}",
            f"load_test_cpu_usage {self.current_metrics['cpu_usage']}",
            f"load_test_memory_usage {self.current_metrics['memory_usage']}",
            f"load_test_detection_rate {self.current_metrics['detection_rate']}"
        ]
        
        return "\n".join(metrics) + "\n"
    
    def save_metrics_report(self, filename: str):
        """Save detailed metrics report"""
        if not self.metrics_history:
            logger.warning("No metrics to save")
            return
        
        # Convert to DataFrame for analysis
        data = []
        for entry in self.metrics_history:
            row = {
                'timestamp': entry['timestamp'],
                'datetime': datetime.fromtimestamp(entry['timestamp']),
                'system_cpu': entry['system'].cpu_percent,
                'system_memory': entry['system'].memory_percent,
                'waf_rps': entry['waf'].total_requests,
                'waf_blocked_rps': entry['waf'].blocked_requests,
                'waf_response_time_avg': entry['waf'].response_time_avg,
                'waf_response_time_p95': entry['waf'].response_time_p95,
                'waf_response_time_p99': entry['waf'].response_time_p99,
                'waf_error_rate': entry['waf'].error_rate,
                'waf_detection_rate': entry['waf'].detection_rate
            }
            
            # Add container metrics
            for container, stats in entry['containers'].items():
                if stats:
                    row[f'{container}_cpu'] = stats['cpu_percent']
                    row[f'{container}_memory'] = stats['memory_percent']
            
            data.append(row)
        
        df = pd.DataFrame(data)
        
        # Generate summary statistics
        summary = {
            'test_duration_minutes': (df['timestamp'].max() - df['timestamp'].min()) / 60,
            'avg_rps': df['waf_rps'].mean(),
            'max_rps': df['waf_rps'].max(),
            'avg_response_time_ms': df['waf_response_time_avg'].mean() * 1000,
            'p95_response_time_ms': df['waf_response_time_p95'].mean() * 1000,
            'p99_response_time_ms': df['waf_response_time_p99'].mean() * 1000,
            'avg_detection_rate': df['waf_detection_rate'].mean(),
            'avg_system_cpu': df['system_cpu'].mean(),
            'max_system_cpu': df['system_cpu'].max(),
            'avg_system_memory': df['system_memory'].mean(),
            'max_system_memory': df['system_memory'].max(),
            'total_attacks_estimated': df['waf_blocked_rps'].sum() * 2  # 2-second intervals
        }
        
        # Save to files
        df.to_csv(f'/results/{filename}_detailed.csv', index=False)
        
        with open(f'/results/{filename}_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Generate plots
        self.generate_performance_plots(df, filename)
        
        logger.info(f"Metrics report saved: {filename}")
        return summary
    
    def generate_performance_plots(self, df: pd.DataFrame, filename: str):
        """Generate performance visualization plots"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('SafeLine WAF Load Test Performance Analysis')
        
        # RPS over time
        axes[0, 0].plot(df['datetime'], df['waf_rps'], label='Total RPS', color='blue')
        axes[0, 0].plot(df['datetime'], df['waf_blocked_rps'], label='Blocked RPS', color='red')
        axes[0, 0].set_title('Request Rate Over Time')
        axes[0, 0].set_ylabel('Requests per Second')
        axes[0, 0].legend()
        axes[0, 0].grid(True)
        
        # Response time over time
        axes[0, 1].plot(df['datetime'], df['waf_response_time_avg'] * 1000, label='Average', color='green')
        axes[0, 1].plot(df['datetime'], df['waf_response_time_p95'] * 1000, label='P95', color='orange')
        axes[0, 1].plot(df['datetime'], df['waf_response_time_p99'] * 1000, label='P99', color='red')
        axes[0, 1].set_title('Response Time Over Time')
        axes[0, 1].set_ylabel('Response Time (ms)')
        axes[0, 1].legend()
        axes[0, 1].grid(True)
        
        # System resources
        axes[1, 0].plot(df['datetime'], df['system_cpu'], label='CPU %', color='purple')
        axes[1, 0].plot(df['datetime'], df['system_memory'], label='Memory %', color='brown')
        axes[1, 0].set_title('System Resource Usage')
        axes[1, 0].set_ylabel('Usage %')
        axes[1, 0].legend()
        axes[1, 0].grid(True)
        
        # Detection rate
        axes[1, 1].plot(df['datetime'], df['waf_detection_rate'], label='Detection Rate', color='darkred')
        axes[1, 1].set_title('Attack Detection Rate Over Time')
        axes[1, 1].set_ylabel('Detection Rate %')
        axes[1, 1].legend()
        axes[1, 1].grid(True)
        
        # Format x-axis
        for ax in axes.flat:
            ax.xaxis.set_major_formatter(DateFormatter('%H:%M:%S'))
            plt.setp(ax.xaxis.get_majorticklabels(), rotation=45)
        
        plt.tight_layout()
        plt.savefig(f'/results/{filename}_performance.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def start_monitoring(self):
        """Start the monitoring system"""
        self.running = True
        logger.info("Starting load test monitoring...")
        
        # Start metrics collection in background
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.collect_metrics())
    
    def stop_monitoring(self):
        """Stop the monitoring system"""
        self.running = False
        logger.info("Stopping load test monitoring...")
    
    def real_time_display(self):
        """Display real-time metrics in terminal"""
        while self.running:
            # Clear screen and display current metrics
            import os
            os.system('clear' if os.name == 'posix' else 'cls')
            
            print("=== SafeLine WAF Load Test Monitor ===")
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print()
            
            metrics = self.current_metrics
            print(f"📊 Request Rate:")
            print(f"   Total RPS:     {metrics['rps']:.0f}")
            print(f"   Blocked RPS:   {metrics['blocked_rps']:.0f}")
            print(f"   Detection:     {metrics['detection_rate']:.1f}%")
            print()
            
            print(f"⚡ Performance:")
            print(f"   Response Time: {metrics['response_time']:.1f}ms")
            print(f"   Error Rate:    {metrics['error_rate']:.1f}%")
            print()
            
            print(f"💻 System Resources:")
            print(f"   CPU Usage:     {metrics['cpu_usage']:.1f}%")
            print(f"   Memory Usage:  {metrics['memory_usage']:.1f}%")
            print()
            
            if self.metrics_history:
                duration = time.time() - self.metrics_history[0]['timestamp']
                print(f"⏱️  Test Duration:   {duration/60:.1f} minutes")
                print(f"📈 Data Points:    {len(self.metrics_history)}")
            
            print()
            print("Press Ctrl+C to stop monitoring")
            
            time.sleep(5)

def run_monitor_server():
    """Run the monitoring server"""
    monitor = LoadTestMonitor()
    
    # Start metrics collection in a separate thread
    monitor_thread = threading.Thread(target=monitor.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    try:
        # Start real-time display
        monitor.real_time_display()
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop_monitoring()
        
        # Save final report
        summary = monitor.save_metrics_report("load_test_monitor")
        
        print("\n=== Final Test Summary ===")
        print(f"Test Duration: {summary.get('test_duration_minutes', 0):.1f} minutes")
        print(f"Average RPS: {summary.get('avg_rps', 0):.0f}")
        print(f"Max RPS: {summary.get('max_rps', 0):.0f}")
        print(f"Average Response Time: {summary.get('avg_response_time_ms', 0):.1f}ms")
        print(f"Average Detection Rate: {summary.get('avg_detection_rate', 0):.1f}%")
        print(f"Average CPU Usage: {summary.get('avg_system_cpu', 0):.1f}%")
        print(f"Reports saved to /results/")

if __name__ == "__main__":
    run_monitor_server()