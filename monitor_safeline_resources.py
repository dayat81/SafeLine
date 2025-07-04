#!/usr/bin/env python3
"""
SafeLine Resource Usage Monitor
Real-time monitoring of CPU and RAM usage for all SafeLine containers
"""

import subprocess
import json
import time
import signal
import sys
import re
from datetime import datetime
from collections import defaultdict

class SafeLineResourceMonitor:
    def __init__(self, interval=5):
        """
        Initialize SafeLine resource monitor
        
        Args:
            interval (int): Monitoring interval in seconds
        """
        self.interval = interval
        self.running = False
        
        # SafeLine container names
        self.safeline_containers = [
            'safeline-mgt',
            'safeline-pg',
            'safeline-detector',
            'safeline-tengine',
            'safeline-luigi',
            'safeline-fvm',
            'safeline-chaos'
        ]
        
        # Resource history for trending
        self.resource_history = defaultdict(list)
        self.max_history = 100  # Keep last 100 measurements
        
    def signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        print(f"\nReceived signal {signum}. Stopping monitor...")
        self.running = False

    def get_container_stats(self):
        """Get resource statistics for all containers"""
        try:
            # Get stats for all containers
            cmd = ['docker', 'stats', '--no-stream', '--format', 'json'] + self.safeline_containers
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return None
            
            stats = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        stat = json.loads(line)
                        stats.append(stat)
                    except json.JSONDecodeError:
                        continue
            
            return stats
            
        except subprocess.TimeoutExpired:
            print("Warning: Docker stats command timed out")
            return None
        except Exception as e:
            print(f"Error getting container stats: {e}")
            return None

    def parse_memory_usage(self, mem_usage_str, mem_perc_str=None):
        """Parse memory usage string and return percentage"""
        try:
            # Format: "123.4MiB / 1.234GiB"
            parts = mem_usage_str.split(' / ')
            if len(parts) != 2:
                return 0.0, 0.0, 0.0
            
            used_str = parts[0].strip()
            total_str = parts[1].strip()
            
            # Convert to bytes
            used_bytes = self.convert_to_bytes(used_str)
            total_bytes = self.convert_to_bytes(total_str)
            
            # Use provided memory percentage if available, otherwise calculate
            if mem_perc_str:
                try:
                    percentage = float(mem_perc_str.replace('%', ''))
                except Exception:
                    percentage = (used_bytes / total_bytes) * 100 if total_bytes > 0 else 0.0
            else:
                percentage = (used_bytes / total_bytes) * 100 if total_bytes > 0 else 0.0
            
            return used_bytes, total_bytes, percentage
            
        except Exception as e:
            print(f"Debug: Memory parsing error: {e}, input: {mem_usage_str}")
            return 0.0, 0.0, 0.0

    def convert_to_bytes(self, size_str):
        """Convert size string to bytes"""
        try:
            # Handle formats like "103.4MiB", "1.234GiB", "512MB", etc.
            size_str = size_str.upper().strip()
            
            # Extract numeric part and unit
            match = re.match(r'^([\d.]+)\s*([A-Z]+)$', size_str)
            if not match:
                # Try without unit (assume bytes)
                return float(size_str)
            
            value = float(match.group(1))
            unit = match.group(2)
            
            # Handle different unit formats
            if unit in ['B', 'BYTES']:
                return value
            elif unit in ['K', 'KB', 'KIB']:
                return value * 1024
            elif unit in ['M', 'MB', 'MIB']:
                return value * 1024 * 1024
            elif unit in ['G', 'GB', 'GIB']:
                return value * 1024 * 1024 * 1024
            elif unit in ['T', 'TB', 'TIB']:
                return value * 1024 * 1024 * 1024 * 1024
            else:
                return value
                
        except Exception as e:
            print(f"Debug: Byte conversion error: {e}, input: {size_str}")
            return 0.0

    def format_bytes(self, bytes_val):
        """Format bytes to human readable string"""
        if bytes_val < 1024:
            return f"{bytes_val:.1f}B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val/1024:.1f}KB"
        elif bytes_val < 1024 * 1024 * 1024:
            return f"{bytes_val/(1024*1024):.1f}MB"
        else:
            return f"{bytes_val/(1024*1024*1024):.1f}GB"

    def parse_cpu_percentage(self, cpu_str):
        """Parse CPU percentage string"""
        try:
            return float(cpu_str.replace('%', ''))
        except Exception:
            return 0.0

    def get_system_info(self):
        """Get system resource information"""
        try:
            # Get total system memory
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            
            total_mem = 0
            for line in meminfo.split('\n'):
                if line.startswith('MemTotal:'):
                    total_mem = int(line.split()[1]) * 1024  # Convert KB to bytes
                    break
            
            # Get CPU count
            cpu_count = subprocess.run(['nproc'], capture_output=True, text=True)
            cpu_cores = int(cpu_count.stdout.strip()) if cpu_count.returncode == 0 else 1
            
            return total_mem, cpu_cores
            
        except Exception:
            return 0, 1

    def update_history(self, container_name, cpu_percent, mem_percent):
        """Update resource history for trending"""
        timestamp = time.time()
        self.resource_history[container_name].append({
            'timestamp': timestamp,
            'cpu_percent': cpu_percent,
            'mem_percent': mem_percent
        })
        
        # Keep only recent history
        if len(self.resource_history[container_name]) > self.max_history:
            self.resource_history[container_name] = self.resource_history[container_name][-self.max_history:]

    def get_average_usage(self, container_name, duration_minutes=5):
        """Get average usage over specified duration"""
        if container_name not in self.resource_history:
            return 0.0, 0.0
        
        history = self.resource_history[container_name]
        if not history:
            return 0.0, 0.0
        
        cutoff_time = time.time() - (duration_minutes * 60)
        recent_data = [h for h in history if h['timestamp'] >= cutoff_time]
        
        if not recent_data:
            return 0.0, 0.0
        
        avg_cpu = sum(h['cpu_percent'] for h in recent_data) / len(recent_data)
        avg_mem = sum(h['mem_percent'] for h in recent_data) / len(recent_data)
        
        return avg_cpu, avg_mem

    def display_stats(self, stats):
        """Display formatted resource statistics"""
        if not stats:
            print("No container statistics available")
            return
        
        # Clear screen
        print('\033[2J\033[H', end='')
        
        print("="*90)
        print(f"SafeLine Resource Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*90)
        
        # Header
        print(f"{'Container':<20} {'CPU %':<8} {'CPU Avg':<8} {'Memory %':<10} {'Mem Avg':<8} {'Memory Usage':<20} {'Status':<8}")
        print("-"*90)
        
        total_cpu = 0.0
        total_mem_used = 0.0
        total_mem_limit = 0.0
        running_containers = 0
        
        for stat in stats:
            container_name = stat.get('Name', 'Unknown')
            
            # Parse CPU percentage
            cpu_percent = self.parse_cpu_percentage(stat.get('CPUPerc', '0%'))
            
            # Parse memory usage
            mem_usage = stat.get('MemUsage', '0B / 0B')
            mem_perc_str = stat.get('MemPerc', '0%')
            mem_used, mem_limit, mem_percent = self.parse_memory_usage(mem_usage, mem_perc_str)
            
            # Update history
            self.update_history(container_name, cpu_percent, mem_percent)
            
            # Get averages
            avg_cpu, avg_mem = self.get_average_usage(container_name)
            
            # Format memory usage
            mem_usage_formatted = f"{self.format_bytes(mem_used)} / {self.format_bytes(mem_limit)}"
            
            # Determine status based on usage
            if cpu_percent > 80 or mem_percent > 80:
                status = "HIGH"
            elif cpu_percent > 50 or mem_percent > 50:
                status = "MEDIUM"
            else:
                status = "OK"
            
            # Display row
            print(f"{container_name:<20} {cpu_percent:>6.1f}% {avg_cpu:>6.1f}% {mem_percent:>8.1f}% {avg_mem:>6.1f}% {mem_usage_formatted:<20} {status:<8}")
            
            # Accumulate totals
            total_cpu += cpu_percent
            total_mem_used += mem_used
            total_mem_limit += mem_limit
            running_containers += 1
        
        # Summary
        print("-"*90)
        avg_cpu_all = total_cpu / running_containers if running_containers > 0 else 0
        total_mem_percent = (total_mem_used / total_mem_limit * 100) if total_mem_limit > 0 else 0
        
        print(f"{'TOTAL/AVERAGE':<20} {avg_cpu_all:>6.1f}% {'':>8} {total_mem_percent:>8.1f}% {'':>8} {self.format_bytes(total_mem_used):<20} {'':>8}")
        
        # System info
        system_mem, cpu_cores = self.get_system_info()
        system_mem_percent = (total_mem_used / system_mem * 100) if system_mem > 0 else 0
        
        print("="*90)
        print(f"System Info: {cpu_cores} CPU cores | Total Memory: {self.format_bytes(system_mem)} | SafeLine Memory Usage: {system_mem_percent:.1f}%")
        print(f"Running Containers: {running_containers} | Update Interval: {self.interval}s | Press Ctrl+C to stop")
        print("="*90)

    def check_containers_running(self):
        """Check if SafeLine containers are running"""
        try:
            result = subprocess.run(['docker', 'ps', '--format', 'json'], capture_output=True, text=True)
            if result.returncode != 0:
                return False
            
            running_containers = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        container = json.loads(line)
                        container_name = container.get('Names', '')
                        if container_name in self.safeline_containers:
                            running_containers.append(container_name)
                    except json.JSONDecodeError:
                        continue
            
            if not running_containers:
                print("No SafeLine containers are currently running.")
                print("Start SafeLine with: ./start_safeline.sh")
                return False
            
            missing_containers = set(self.safeline_containers) - set(running_containers)
            if missing_containers:
                print(f"Warning: Some SafeLine containers are not running: {', '.join(missing_containers)}")
            
            return True
            
        except Exception as e:
            print(f"Error checking container status: {e}")
            return False

    def run_monitor(self):
        """Run the resource monitor"""
        print("SafeLine Resource Monitor")
        print("========================")
        print(f"Monitoring interval: {self.interval} seconds")
        print("Press Ctrl+C to stop monitoring\n")
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Check if containers are running
        if not self.check_containers_running():
            return
        
        self.running = True
        
        try:
            while self.running:
                stats = self.get_container_stats()
                if stats:
                    self.display_stats(stats)
                else:
                    print("Failed to get container statistics. Retrying...")
                
                # Wait for next update
                for _ in range(self.interval):
                    if not self.running:
                        break
                    time.sleep(1)
                    
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
        except Exception as e:
            print(f"\nError during monitoring: {e}")
        finally:
            self.running = False
            print("Resource monitoring stopped.")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='SafeLine Resource Usage Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                    # Monitor with 5 second intervals
  %(prog)s -i 10              # Monitor with 10 second intervals
  %(prog)s --interval 2       # Monitor with 2 second intervals
        '''
    )
    
    parser.add_argument(
        '-i', '--interval',
        type=int,
        default=5,
        help='Monitoring interval in seconds (default: 5)'
    )
    
    args = parser.parse_args()
    
    if args.interval < 1:
        print("Error: Interval must be at least 1 second")
        sys.exit(1)
    
    monitor = SafeLineResourceMonitor(interval=args.interval)
    monitor.run_monitor()