
### 10:46:41 - Comprehensive Testing Suite Initialized

### 10:46:41 - Starting comprehensive test execution

### 10:46:41 - Starting comprehensive test suite - 120s at 50 RPS

### 10:46:41 - Testing target availability

### 10:46:41 - ✅ vulnerable_app: http://localhost:3000 (Status: 200)

### 10:46:41 - ✅ proxy_waf: http://localhost (Status: 200)

### 10:46:41 - ✅ direct_test: http://httpbin.org/get (Status: 200)

### 10:46:41 - Testing against 3 available targets

### 10:48:43 - Test suite completed - 4083 total requests

### 10:48:43 - Analyzing test results

### 10:48:43 - Results saved to: /home/ptsec/SafeLine/full_test_results/comprehensive_test_20250704_104843.json

### 10:48:43 - === TEST EXECUTION SUMMARY ===

### 10:48:43 - Total Requests: 4,083

### 10:48:43 - Successful Requests: 4,083

### 10:48:43 - Blocked Requests: 962

### 10:48:43 - Overall Detection Rate: 23.6%

### 10:48:43 - Average Response Time: 223.0ms

### 10:48:43 - Actual RPS: 34.0

### 10:48:43 - === TARGET BREAKDOWN ===

### 10:48:43 - http://httpbin.org/get: 1/1348 blocked (0.1%)

### 10:48:43 - http://localhost:3000: 0/1343 blocked (0.0%)

### 10:48:43 - http://localhost: 961/1392 blocked (69.0%)

### 10:48:43 - === TOP ATTACK TYPES ===

### 10:48:43 - path_traversal_basic: 137/704 blocked (19.5%)

### 10:48:43 - xxe_injection_basic: 151/692 blocked (21.8%)

### 10:48:43 - command_injection_basic: 83/681 blocked (12.2%)

### 10:48:43 - ssrf_basic: 99/662 blocked (15.0%)

### 10:48:43 - sql_injection_union_based: 70/186 blocked (37.6%)

### 10:48:43 - xss_script_based: 55/176 blocked (31.2%)

### 10:48:43 - xss_advanced_vectors: 64/170 blocked (37.6%)

### 10:48:43 - sql_injection_time_based: 65/169 blocked (38.5%)

### 10:48:43 - xss_event_handlers: 70/167 blocked (41.9%)

### 10:48:43 - sql_injection_boolean_blind: 58/162 blocked (35.8%)

### 10:48:43 - Results saved to: /home/ptsec/SafeLine/full_test_results/comprehensive_test_20250704_104843.json

### 10:48:43 - Comprehensive testing completed successfully
