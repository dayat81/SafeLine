#!/usr/bin/env python3
"""
SafeLine WAF 48-Hour Test Monitoring Dashboard
Real-time monitoring and status reporting
"""

import time
import json
import os
import subprocess
from datetime import datetime, timedelta
import glob

def get_process_status():
    """Check if the continuous test process is running"""
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        processes = result.stdout
        
        for line in processes.split('\n'):
            if 'continuous_48hr_load_test.py' in line and 'grep' not in line:
                parts = line.split()
                return {
                    'running': True,
                    'pid': parts[1],
                    'cpu_percent': parts[2],
                    'memory_percent': parts[3],
                    'runtime': parts[9]
                }
        return {'running': False}
    except Exception as e:
        return {'running': False, 'error': str(e)}

def get_latest_results():
    """Get the latest test results from intermediate files"""
    results_dir = "/home/pt/SafeLine/continuous_test_results"
    
    if not os.path.exists(results_dir):
        return None
    
    # Find the latest intermediate result file
    pattern = os.path.join(results_dir, "intermediate_*.json")
    files = glob.glob(pattern)
    
    if not files:
        return None
    
    latest_file = max(files, key=os.path.getctime)
    
    try:
        with open(latest_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        return {'error': f"Failed to read {latest_file}: {e}"}

def get_safeline_status():
    """Check SafeLine WAF service status"""
    try:
        result = subprocess.run(['docker-compose', '-f', 'docker-compose.yaml', 'ps', 'mgt'], 
                              capture_output=True, text=True, cwd='/home/pt/SafeLine')
        
        if 'Up' in result.stdout:
            return {'status': 'running', 'health': 'healthy'}
        else:
            return {'status': 'down', 'health': 'unhealthy'}
    except Exception as e:
        return {'status': 'unknown', 'error': str(e)}

def display_dashboard():
    """Display real-time monitoring dashboard"""
    while True:
        os.system('clear')
        
        print("🔥 SafeLine WAF 48-Hour Continuous Load Test - MONITORING DASHBOARD")
        print("=" * 80)
        print(f"🕐 Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        # Process Status
        process_status = get_process_status()
        print("\n📊 LOAD TEST PROCESS STATUS")
        print("-" * 40)
        
        if process_status.get('running'):
            print("✅ Status: RUNNING")
            print(f"🆔 PID: {process_status.get('pid', 'N/A')}")
            print(f"⚡ CPU Usage: {process_status.get('cpu_percent', 'N/A')}%")
            print(f"💾 Memory Usage: {process_status.get('memory_percent', 'N/A')}%")
            print(f"⏱️  Runtime: {process_status.get('runtime', 'N/A')}")
        else:
            print("❌ Status: NOT RUNNING")
            if 'error' in process_status:
                print(f"⚠️  Error: {process_status['error']}")
        
        # SafeLine Status
        safeline_status = get_safeline_status()
        print("\n🛡️  SAFELINE WAF STATUS")
        print("-" * 40)
        print(f"Status: {'✅ RUNNING' if safeline_status.get('status') == 'running' else '❌ DOWN'}")
        print(f"Health: {'✅ HEALTHY' if safeline_status.get('health') == 'healthy' else '⚠️ UNHEALTHY'}")
        
        # Latest Test Results
        latest_results = get_latest_results()
        print("\n📈 LATEST TEST RESULTS")
        print("-" * 40)
        
        if latest_results and 'error' not in latest_results:
            metadata = latest_results.get('metadata', {})
            total_requests = metadata.get('total_requests', 0)
            elapsed_hours = metadata.get('elapsed_hours', 0)
            
            print(f"⏱️  Elapsed Time: {elapsed_hours:.2f} hours")
            print(f"📊 Total Requests: {total_requests:,}")
            print(f"📈 Current RPS: {(total_requests / (elapsed_hours * 3600)):.1f}" if elapsed_hours > 0 else "📈 Current RPS: Calculating...")
            
            # Phase breakdown
            phase_results = latest_results.get('phase_results', {})
            if phase_results:
                print(f"📋 Active Phases: {len(phase_results)}")
                for phase_name, results in phase_results.items():
                    if results:
                        blocked_count = sum(1 for r in results if r.get('blocked', False))
                        detection_rate = (blocked_count / len(results) * 100) if results else 0
                        print(f"   {phase_name}: {len(results)} requests, {detection_rate:.1f}% blocked")
        
        elif latest_results and 'error' in latest_results:
            print(f"⚠️  Error reading results: {latest_results['error']}")
        else:
            print("⏳ No results available yet...")
        
        # System Resources
        print("\n💻 SYSTEM RESOURCES")
        print("-" * 40)
        
        try:
            # Get load average
            with open('/proc/loadavg', 'r') as f:
                load_avg = f.read().strip().split()[:3]
                print(f"🔧 Load Average: {' '.join(load_avg)}")
        except:
            print("🔧 Load Average: N/A")
        
        try:
            # Get memory info
            with open('/proc/meminfo', 'r') as f:
                memory_info = f.read()
                for line in memory_info.split('\n'):
                    if 'MemTotal:' in line:
                        total_mem = int(line.split()[1])
                    elif 'MemAvailable:' in line:
                        available_mem = int(line.split()[1])
                        break
                
                used_mem = total_mem - available_mem
                mem_percent = (used_mem / total_mem) * 100
                print(f"💾 Memory Usage: {mem_percent:.1f}% ({used_mem//1024}MB/{total_mem//1024}MB)")
        except:
            print("💾 Memory Usage: N/A")
        
        # Test Progress
        print("\n🎯 TEST PROGRESS")
        print("-" * 40)
        
        # Estimate remaining time
        if latest_results and 'error' not in latest_results:
            elapsed_hours = latest_results.get('metadata', {}).get('elapsed_hours', 0)
            remaining_hours = max(0, 48 - elapsed_hours)
            progress_percent = (elapsed_hours / 48) * 100
            
            print(f"📊 Progress: {progress_percent:.1f}% ({elapsed_hours:.1f}/48.0 hours)")
            print(f"⏳ Remaining: {remaining_hours:.1f} hours")
            
            if remaining_hours > 0:
                eta = datetime.now() + timedelta(hours=remaining_hours)
                print(f"🏁 Estimated Completion: {eta.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print("📊 Progress: Initializing...")
        
        print("\n" + "=" * 80)
        print("🔄 Refreshing every 30 seconds... Press Ctrl+C to exit monitoring")
        print("=" * 80)
        
        try:
            time.sleep(30)
        except KeyboardInterrupt:
            print("\n👋 Monitoring dashboard stopped.")
            break

if __name__ == "__main__":
    print("🚀 Starting SafeLine WAF 48-Hour Test Monitoring Dashboard...")
    print("⚠️  This will refresh every 30 seconds. Press Ctrl+C to stop.")
    time.sleep(2)
    display_dashboard()