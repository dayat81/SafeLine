# SafeLine WAF API Endpoint Test Log

- **Test Started**: 2025-06-27 14:28:46
- **API Token**: nzUGQoFySj...WAwnAqjORS
- **Base URL**: https://localhost:9443/api/open

---

[2025-06-27 14:28:46.503] [START] Starting SafeLine API Endpoint Testing
[2025-06-27 14:28:46.503] [SECTION] === Testing System & Health Endpoints ===
[2025-06-27 14:28:46.504] [INFO] Testing: GET /health - System health check
[2025-06-27 14:28:46.629] [INFO] Response Status: 200
[2025-06-27 14:28:46.630] [INFO] Response Data: {
  "status": "ok"
}...
[2025-06-27 14:28:46.630] [INFO] Testing: GET /dashboard - Dashboard statistics
[2025-06-27 14:28:46.742] [INFO] Response Status: 404
[2025-06-27 14:28:46.743] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:46.743] [INFO] Testing: GET /system/info - System information
[2025-06-27 14:28:46.847] [INFO] Response Status: 404
[2025-06-27 14:28:46.848] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:46.848] [SECTION] 
=== Testing Website Management Endpoints ===
[2025-06-27 14:28:46.848] [INFO] Testing: GET /website - List all websites
[2025-06-27 14:28:46.932] [INFO] Response Status: 404
[2025-06-27 14:28:46.933] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:46.933] [INFO] Testing: GET /website/1 - Get specific website
[2025-06-27 14:28:47.043] [INFO] Response Status: 404
[2025-06-27 14:28:47.044] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:47.044] [INFO] Testing: POST /website - Create new website
[2025-06-27 14:28:47.151] [INFO] Response Status: 404
[2025-06-27 14:28:47.152] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:47.152] [SECTION] 
=== Testing Detection Rules & Policies ===
[2025-06-27 14:28:47.152] [INFO] Testing: GET /policy/rule - List all detection rules
[2025-06-27 14:28:47.233] [INFO] Response Status: 404
[2025-06-27 14:28:47.234] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:47.234] [INFO] Testing: GET /policy/rule/1 - Get specific rule
[2025-06-27 14:28:47.349] [INFO] Response Status: 404
[2025-06-27 14:28:47.350] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:47.350] [INFO] Testing: POST /policy/rule - Create detection rule
[2025-06-27 14:28:47.463] [INFO] Response Status: 404
[2025-06-27 14:28:47.464] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:47.464] [SECTION] 
=== Testing Attack Logs ===
[2025-06-27 14:28:47.464] [INFO] Testing: GET /detect/log?limit=10 - Recent attack logs
[2025-06-27 14:28:47.575] [INFO] Response Status: 404
[2025-06-27 14:28:47.576] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:47.576] [INFO] Testing: GET /detect/log?attack_type=sql_injection - SQL injection logs
[2025-06-27 14:28:47.688] [INFO] Response Status: 404
[2025-06-27 14:28:47.689] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:47.689] [INFO] Testing: GET /detect/log?start_time=2025-06-27T00:00:00Z - Logs by date
[2025-06-27 14:28:47.801] [INFO] Response Status: 404
[2025-06-27 14:28:47.802] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:47.802] [INFO] Testing: GET /detect/log/1 - Specific log entry
[2025-06-27 14:28:47.915] [INFO] Response Status: 404
[2025-06-27 14:28:47.915] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:47.916] [SECTION] 
=== Testing IP Management ===
[2025-06-27 14:28:47.916] [INFO] Testing: GET /ip/group - List IP groups
[2025-06-27 14:28:48.030] [INFO] Response Status: 404
[2025-06-27 14:28:48.030] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:48.030] [INFO] Testing: POST /ip/group - Create IP group
[2025-06-27 14:28:48.144] [INFO] Response Status: 404
[2025-06-27 14:28:48.145] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:48.145] [INFO] Testing: POST /ip/blacklist - Add IP to blacklist
[2025-06-27 14:28:48.257] [INFO] Response Status: 404
[2025-06-27 14:28:48.258] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:48.258] [SECTION] 
=== Testing Rate Limiting ===
[2025-06-27 14:28:48.258] [INFO] Testing: GET /frequency/rule - List rate limiting rules
[2025-06-27 14:28:48.371] [INFO] Response Status: 404
[2025-06-27 14:28:48.372] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:48.373] [INFO] Testing: POST /frequency/rule - Create rate limit rule
[2025-06-27 14:28:48.484] [INFO] Response Status: 404
[2025-06-27 14:28:48.484] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:48.485] [SECTION] 
=== Testing SSL Certificate Management ===
[2025-06-27 14:28:48.485] [INFO] Testing: GET /cert - List SSL certificates
[2025-06-27 14:28:48.605] [INFO] Response Status: 401
[2025-06-27 14:28:48.606] [INFO] Response Data: {
  "data": null,
  "err": "login-required",
  "msg": "Login required"
}...
[2025-06-27 14:28:48.606] [SECTION] 
=== Testing User Management ===
[2025-06-27 14:28:48.606] [INFO] Testing: GET /user - List all users
[2025-06-27 14:28:48.719] [INFO] Response Status: 404
[2025-06-27 14:28:48.719] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:48.719] [INFO] Testing: POST /user - Create new user
[2025-06-27 14:28:48.833] [INFO] Response Status: 404
[2025-06-27 14:28:48.834] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:48.834] [SECTION] 
=== Testing Statistics & Analytics ===
[2025-06-27 14:28:48.834] [INFO] Testing: GET /stats/attack?period=24h - Attack statistics (24h)
[2025-06-27 14:28:48.946] [INFO] Response Status: 404
[2025-06-27 14:28:48.947] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:48.947] [INFO] Testing: GET /stats/performance - Performance metrics
[2025-06-27 14:28:49.061] [INFO] Response Status: 404
[2025-06-27 14:28:49.061] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:49.061] [INFO] Testing: GET /stats/top/attackers?limit=10 - Top 10 attackers
[2025-06-27 14:28:49.174] [INFO] Response Status: 404
[2025-06-27 14:28:49.175] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:49.175] [SECTION] 
=== Testing Configuration Management ===
[2025-06-27 14:28:49.175] [INFO] Testing: GET /config/export - Export configuration
[2025-06-27 14:28:49.288] [INFO] Response Status: 404
[2025-06-27 14:28:49.288] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:49.289] [SECTION] 
=== Testing Additional Endpoints ===
[2025-06-27 14:28:49.289] [INFO] Testing: GET /version - API version
[2025-06-27 14:28:49.381] [INFO] Response Status: 404
[2025-06-27 14:28:49.381] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:49.382] [INFO] Testing: GET /license - License information
[2025-06-27 14:28:49.462] [INFO] Response Status: 404
[2025-06-27 14:28:49.462] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:49.462] [INFO] Testing: GET /backup - Backup status
[2025-06-27 14:28:49.546] [INFO] Response Status: 404
[2025-06-27 14:28:49.547] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:49.547] [INFO] Testing: GET /alert - Alert configurations
[2025-06-27 14:28:49.633] [INFO] Response Status: 404
[2025-06-27 14:28:49.633] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:49.634] [INFO] Testing: GET /notification - Notification settings
[2025-06-27 14:28:49.748] [INFO] Response Status: 404
[2025-06-27 14:28:49.749] [INFO] Response Text: 404 page not found...
[2025-06-27 14:28:49.750] [COMPLETE] 
=== Test Execution Complete ===

---

## Test Summary

- **Test Completed**: 2025-06-27 14:28:49
- **Log File**: SAFELINE_API_TEST_LOG_20250627_142846.md
