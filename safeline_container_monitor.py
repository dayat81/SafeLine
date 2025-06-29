#!/usr/bin/env python3
"""
SafeLine Container Monitoring Script
Monitors CPU, RAM, and disk usage for all SafeLine-related containers
"""

import subprocess
import json
import time
import os
from datetime import datetime
import argparse
import sys

class SafeLineMonitor:
    def __init__(self, compose_file='docker-compose.yaml'):
        self.compose_file = compose_file
        self.safeline_containers = self.get_safeline_containers()
        
    def get_safeline_containers(self):
        """Get list of all SafeLine containers"""
        try:
            # Get all running containers with safeline prefix
            result = subprocess.run(
                ['docker', 'ps', '--format', '{{.Names}}', '--filter', 'name=safeline'],
                capture_output=True, text=True
            )
            containers = result.stdout.strip().split('\n')
            return [c for c in containers if c]
        except Exception as e:
            print(f"Error getting containers: {e}")
            return []
    
    def get_container_stats(self, container_name):
        """Get CPU and memory stats for a specific container"""
        try:
            # Get container stats in JSON format
            result = subprocess.run(
                ['docker', 'stats', container_name, '--no-stream', '--format', 
                 '{"cpu":"{{.CPUPerc}}","memory":"{{.MemUsage}}","mem_percent":"{{.MemPerc}}"}'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0 and result.stdout.strip():
                # Parse the JSON output
                stats_str = result.stdout.strip()
                # Remove percentage signs and parse
                stats_str = stats_str.replace('%', '')
                stats = json.loads(stats_str)
                
                # Parse memory usage
                mem_parts = stats['memory'].split(' / ')
                mem_used = self.parse_memory_value(mem_parts[0])
                mem_limit = self.parse_memory_value(mem_parts[1])
                
                # Get CPU limits
                cpu_limit = self.get_cpu_limit(container_name)
                
                return {
                    'cpu_percent': float(stats['cpu']),
                    'cpu_limit': cpu_limit,
                    'memory_used': mem_used,
                    'memory_limit': mem_limit,
                    'memory_percent': float(stats['mem_percent']),
                    'memory_used_str': mem_parts[0],
                    'memory_limit_str': mem_parts[1]
                }
            return None
        except Exception as e:
            print(f"Error getting stats for {container_name}: {e}")
            return None
    
    def get_cpu_limit(self, container_name):
        """Get CPU limit for a container"""
        try:
            # Get container inspect data
            result = subprocess.run(
                ['docker', 'inspect', container_name, '--format', 
                 '{{json .HostConfig}}'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0 and result.stdout.strip():
                host_config = json.loads(result.stdout.strip())
                
                # Check different CPU limit configurations
                cpu_limit_info = {}
                
                # CPU quota and period (hard limit)
                cpu_quota = host_config.get('CpuQuota', 0)
                cpu_period = host_config.get('CpuPeriod', 0)
                if cpu_quota > 0 and cpu_period > 0:
                    cpu_limit_info['cores'] = cpu_quota / cpu_period
                    cpu_limit_info['percent'] = (cpu_quota / cpu_period) * 100
                
                # CPU shares (soft limit)
                cpu_shares = host_config.get('CpuShares', 0)
                if cpu_shares > 0 and cpu_shares != 1024:  # 1024 is default
                    cpu_limit_info['shares'] = cpu_shares
                
                # Nano CPUs (Docker >= 1.12)
                nano_cpus = host_config.get('NanoCpus', 0)
                if nano_cpus > 0:
                    cpu_limit_info['cores'] = nano_cpus / 1_000_000_000
                    cpu_limit_info['percent'] = (nano_cpus / 1_000_000_000) * 100
                
                # Cpuset CPUs (specific CPU cores)
                cpuset_cpus = host_config.get('CpusetCpus', '')
                if cpuset_cpus:
                    cpu_limit_info['cpuset'] = cpuset_cpus
                
                return cpu_limit_info if cpu_limit_info else None
            
            return None
        except Exception as e:
            print(f"Error getting CPU limit for {container_name}: {e}")
            return None
    
    def parse_memory_value(self, mem_str):
        """Convert memory string (e.g., '1.5GiB', '500MiB') to bytes"""
        mem_str = mem_str.strip()
        units = {
            'B': 1,
            'KiB': 1024,
            'MiB': 1024**2,
            'GiB': 1024**3,
            'KB': 1000,
            'MB': 1000**2,
            'GB': 1000**3,
            'Ki': 1024,
            'Mi': 1024**2,
            'Gi': 1024**3
        }
        
        for unit, multiplier in units.items():
            if mem_str.endswith(unit):
                try:
                    value = float(mem_str[:-len(unit)])
                    return int(value * multiplier)
                except ValueError:
                    continue
        return 0
    
    def get_disk_usage(self):
        """Get disk usage information for Docker volumes and system"""
        disk_info = {}
        
        # Get system disk usage
        try:
            result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 5:
                    disk_info['system'] = {
                        'filesystem': parts[0],
                        'size': parts[1],
                        'used': parts[2],
                        'available': parts[3],
                        'use_percent': parts[4].rstrip('%'),
                        'mount': parts[5] if len(parts) > 5 else '/'
                    }
        except Exception as e:
            print(f"Error getting system disk usage: {e}")
        
        # Get Docker volume information
        try:
            result = subprocess.run(['docker', 'system', 'df', '--format', 'json'], 
                                  capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                try:
                    df_data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    # Fallback to non-JSON format
                    result = subprocess.run(['docker', 'system', 'df'], 
                                          capture_output=True, text=True)
                    disk_info['docker_info'] = result.stdout
                    return disk_info
                
                # Extract volume information
                if 'Volumes' in df_data:
                    volumes = df_data['Volumes']
                    total_size = sum(v.get('Size', 0) for v in volumes if v.get('Size'))
                    safeline_volumes = [v for v in volumes if 'safeline' in v.get('Name', '').lower()]
                    safeline_size = sum(v.get('Size', 0) for v in safeline_volumes if v.get('Size'))
                    
                    disk_info['docker_volumes'] = {
                        'total_count': len(volumes),
                        'total_size': self.format_bytes(total_size),
                        'safeline_count': len(safeline_volumes),
                        'safeline_size': self.format_bytes(safeline_size),
                        'safeline_volumes': [v.get('Name', 'unknown') for v in safeline_volumes]
                    }
                
                # Extract total Docker disk usage
                if 'LayersSize' in df_data:
                    disk_info['docker_total'] = {
                        'layers_size': self.format_bytes(df_data['LayersSize'])
                    }
        except Exception as e:
            print(f"Error getting Docker disk usage: {e}")
        
        return disk_info
    
    def format_bytes(self, bytes_value):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def display_stats(self, continuous=False):
        """Display container statistics"""
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            
            print("🛡️  SafeLine Container Monitoring")
            print("=" * 80)
            print(f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 80)
            
            # Container Stats
            print("\n📊 CONTAINER RESOURCE USAGE")
            print("-" * 100)
            print(f"{'Container':<20} {'CPU %':<8} {'CPU Limit':<12} {'Memory Used':<15} {'Memory Limit':<15} {'Mem %':<10}")
            print("-" * 100)
            
            total_cpu = 0
            total_mem_used = 0
            total_mem_limit = 0
            
            for container in self.safeline_containers:
                stats = self.get_container_stats(container)
                if stats:
                    # Format CPU limit
                    cpu_limit_str = 'No limit'
                    if stats['cpu_limit']:
                        if 'cores' in stats['cpu_limit']:
                            cpu_limit_str = f"{stats['cpu_limit']['cores']:.1f} cores"
                        elif 'cpuset' in stats['cpu_limit']:
                            cpu_limit_str = f"CPUs: {stats['cpu_limit']['cpuset']}"
                        elif 'shares' in stats['cpu_limit']:
                            cpu_limit_str = f"{stats['cpu_limit']['shares']} shares"
                    
                    print(f"{container:<20} {stats['cpu_percent']:<8.1f} {cpu_limit_str:<12} "
                          f"{stats['memory_used_str']:<15} {stats['memory_limit_str']:<15} "
                          f"{stats['memory_percent']:<10.1f}")
                    
                    total_cpu += stats['cpu_percent']
                    total_mem_used += stats['memory_used']
                    total_mem_limit += stats['memory_limit']
                else:
                    print(f"{container:<20} {'N/A':<8} {'N/A':<12} {'N/A':<15} {'N/A':<15} {'N/A':<10}")
            
            print("-" * 100)
            if total_mem_limit > 0:
                total_mem_percent = (total_mem_used / total_mem_limit) * 100
                print(f"{'TOTAL':<20} {total_cpu:<8.1f} {'':<12} "
                      f"{self.format_bytes(total_mem_used):<15} "
                      f"{self.format_bytes(total_mem_limit):<15} "
                      f"{total_mem_percent:<10.1f}")
            
            # Disk Usage
            disk_info = self.get_disk_usage()
            print("\n💾 DISK USAGE")
            print("-" * 80)
            
            if 'system' in disk_info:
                sys_disk = disk_info['system']
                print(f"System Disk (/):")
                print(f"  Total: {sys_disk['size']}, Used: {sys_disk['used']}, "
                      f"Available: {sys_disk['available']}, Usage: {sys_disk['use_percent']}%")
            
            if 'docker_volumes' in disk_info:
                vol_info = disk_info['docker_volumes']
                print(f"\nDocker Volumes:")
                print(f"  Total Volumes: {vol_info['total_count']} ({vol_info['total_size']})")
                print(f"  SafeLine Volumes: {vol_info['safeline_count']} ({vol_info['safeline_size']})")
                if vol_info['safeline_volumes']:
                    print(f"  SafeLine Volume Names:")
                    for vol in vol_info['safeline_volumes'][:5]:  # Show first 5
                        print(f"    - {vol}")
                    if len(vol_info['safeline_volumes']) > 5:
                        print(f"    ... and {len(vol_info['safeline_volumes']) - 5} more")
            
            if 'docker_total' in disk_info:
                print(f"\nDocker Total:")
                print(f"  Image Layers: {disk_info['docker_total']['layers_size']}")
            
            # Container Health Status
            print("\n🏥 CONTAINER HEALTH")
            print("-" * 80)
            
            for container in self.safeline_containers:
                try:
                    result = subprocess.run(
                        ['docker', 'inspect', '--format', '{{.State.Health.Status}}', container],
                        capture_output=True, text=True
                    )
                    health = result.stdout.strip() if result.returncode == 0 else 'unknown'
                    if health == 'healthy':
                        health_icon = '✅'
                    elif health == 'unhealthy':
                        health_icon = '❌'
                    elif health == 'starting':
                        health_icon = '🔄'
                    else:
                        health_icon = '❓'
                    
                    print(f"{container:<30} {health_icon} {health}")
                except:
                    print(f"{container:<30} ❓ unknown")
            
            if not continuous:
                break
            
            print("\n\nPress Ctrl+C to exit...")
            time.sleep(5)
    
    def export_stats_json(self, output_file):
        """Export current stats to JSON file"""
        stats_data = {
            'timestamp': datetime.now().isoformat(),
            'containers': {},
            'disk_usage': self.get_disk_usage()
        }
        
        for container in self.safeline_containers:
            stats = self.get_container_stats(container)
            if stats:
                stats_data['containers'][container] = stats
        
        with open(output_file, 'w') as f:
            json.dump(stats_data, f, indent=2)
        
        print(f"Stats exported to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Monitor SafeLine container resources')
    parser.add_argument('-c', '--continuous', action='store_true', 
                       help='Continuous monitoring mode (updates every 5 seconds)')
    parser.add_argument('-e', '--export', type=str, 
                       help='Export stats to JSON file')
    parser.add_argument('-f', '--compose-file', type=str, default='docker-compose.yaml',
                       help='Docker compose file to use (default: docker-compose.yaml)')
    
    args = parser.parse_args()
    
    monitor = SafeLineMonitor(compose_file=args.compose_file)
    
    if args.export:
        monitor.export_stats_json(args.export)
    else:
        try:
            monitor.display_stats(continuous=args.continuous)
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped.")
            sys.exit(0)

if __name__ == '__main__':
    main()