#!/usr/bin/env python3
"""
Quick status check for 48-hour load test
"""

import subprocess
import os
import glob
import json
from datetime import datetime

def main():
    print("🔥 SafeLine WAF 48-Hour Load Test - Status Check")
    print("=" * 60)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Check if process is running
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        processes = result.stdout
        
        running = False
        for line in processes.split('\n'):
            if 'continuous_48hr_load_test.py' in line and 'grep' not in line:
                parts = line.split()
                print("✅ LOAD TEST STATUS: RUNNING")
                print(f"   PID: {parts[1]}")
                print(f"   CPU: {parts[2]}%")
                print(f"   Memory: {parts[3]}%")
                print(f"   Runtime: {parts[9]}")
                running = True
                break
        
        if not running:
            print("❌ LOAD TEST STATUS: NOT RUNNING")
    
    except Exception as e:
        print(f"❌ Error checking process: {e}")
    
    # Check SafeLine status
    try:
        result = subprocess.run(['docker-compose', '-f', 'docker-compose.yaml', 'ps', '-q', 'mgt'], 
                              capture_output=True, text=True, cwd='/home/pt/SafeLine')
        if result.stdout.strip():
            print("✅ SAFELINE STATUS: RUNNING")
        else:
            print("❌ SAFELINE STATUS: DOWN")
    except Exception as e:
        print(f"❌ Error checking SafeLine: {e}")
    
    # Check for results
    results_dir = "/home/pt/SafeLine/continuous_test_results"
    if os.path.exists(results_dir):
        files = os.listdir(results_dir)
        print(f"📁 RESULTS FILES: {len(files)} files")
        
        # Try to read latest intermediate results
        pattern = os.path.join(results_dir, "intermediate_*.json")
        result_files = glob.glob(pattern)
        
        if result_files:
            latest_file = max(result_files, key=os.path.getctime)
            try:
                with open(latest_file, 'r') as f:
                    data = json.load(f)
                    metadata = data.get('metadata', {})
                    print(f"📊 LATEST RESULTS:")
                    print(f"   Elapsed: {metadata.get('elapsed_hours', 0):.2f} hours")
                    print(f"   Total Requests: {metadata.get('total_requests', 0):,}")
                    
                    # Calculate progress
                    elapsed = metadata.get('elapsed_hours', 0)
                    progress = (elapsed / 48) * 100
                    remaining = 48 - elapsed
                    print(f"   Progress: {progress:.1f}% ({remaining:.1f} hours remaining)")
                    
            except Exception as e:
                print(f"❌ Error reading results: {e}")
        else:
            print("⏳ No intermediate results yet")
    else:
        print("📁 RESULTS DIRECTORY: Not created yet")
    
    print("=" * 60)

if __name__ == "__main__":
    main()