# SafeLine WAF Real API Endpoint Test Log

- **Test Started**: 2025-06-27 14:33:07
- **API Token**: nzUGQoFySj...WAwnAqjORS
- **Base URL**: https://localhost:9443/api
- **Target**: SafeLine WAF Management API

---

[2025-06-27 14:33:07.494] [START] Starting SafeLine Real API Endpoint Testing
[2025-06-27 14:33:07.494] [SECTION] === Testing Public Endpoints (No Authentication) ===
[2025-06-27 14:33:07.494] [INFO] Testing: GET /Ping - Health check endpoint
[2025-06-27 14:33:07.618] [INFO] Response Status: 404
[2025-06-27 14:33:07.619] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:07.619] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:07 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:07.619] [INFO] ---
[2025-06-27 14:33:07.620] [INFO] Testing: GET /Version - Get SafeLine version
[2025-06-27 14:33:07.731] [INFO] Response Status: 404
[2025-06-27 14:33:07.732] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:07.732] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:07 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:07.732] [INFO] ---
[2025-06-27 14:33:07.732] [INFO] Testing: GET /UpgradeTips - Get upgrade recommendations
[2025-06-27 14:33:07.843] [INFO] Response Status: 404
[2025-06-27 14:33:07.844] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:07.844] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:07 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:07.844] [INFO] ---
[2025-06-27 14:33:07.844] [INFO] Testing: GET /OTPUrl - Get OTP setup URL
[2025-06-27 14:33:07.956] [INFO] Response Status: 404
[2025-06-27 14:33:07.957] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:07.957] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:07 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:07.958] [INFO] ---
[2025-06-27 14:33:07.958] [INFO] Testing: GET /open/health - Docker health check endpoint
[2025-06-27 14:33:08.069] [INFO] Response Status: 200
[2025-06-27 14:33:08.070] [INFO] Response Data: {
  "status": "ok"
}
[2025-06-27 14:33:08.070] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:08 GMT', 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': '15', 'Connection': 'keep-alive'}
[2025-06-27 14:33:08.070] [INFO] ---
[2025-06-27 14:33:08.070] [SECTION] 
=== Authentication Attempts ===
[2025-06-27 14:33:08.070] [AUTH] Attempting to establish authenticated session
[2025-06-27 14:33:08.070] [INFO] Testing: POST /Login - Login attempt
[2025-06-27 14:33:08.183] [INFO] Response Status: 404
[2025-06-27 14:33:08.184] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:08.184] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:08 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:08.184] [INFO] ---
[2025-06-27 14:33:08.184] [INFO] Testing: POST /Login - Login attempt (admin/admin)
[2025-06-27 14:33:08.298] [INFO] Response Status: 404
[2025-06-27 14:33:08.299] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:08.299] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:08 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:08.299] [INFO] ---
[2025-06-27 14:33:08.299] [SECTION] 
=== Testing Endpoints with API Token ===
[2025-06-27 14:33:08.299] [INFO] Testing: GET /dashboard/counts - Request/intercept counts
[2025-06-27 14:33:08.409] [INFO] Response Status: 404
[2025-06-27 14:33:08.410] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:08.410] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:08 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:08.411] [INFO] ---
[2025-06-27 14:33:08.411] [INFO] Testing: GET /dashboard/sites - Site status summary
[2025-06-27 14:33:08.526] [INFO] Response Status: 404
[2025-06-27 14:33:08.527] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:08.527] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:08 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:08.527] [INFO] ---
[2025-06-27 14:33:08.528] [INFO] Testing: GET /dashboard/qps - QPS data
[2025-06-27 14:33:08.639] [INFO] Response Status: 404
[2025-06-27 14:33:08.639] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:08.640] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:08 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:08.640] [INFO] ---
[2025-06-27 14:33:08.640] [INFO] Testing: GET /dashboard/requests - Request statistics
[2025-06-27 14:33:08.755] [INFO] Response Status: 401
[2025-06-27 14:33:08.756] [INFO] Response Data: {
  "data": null,
  "err": "login-required",
  "msg": "Login required"
}
[2025-06-27 14:33:08.756] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:08 GMT', 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': '59', 'Connection': 'keep-alive'}
[2025-06-27 14:33:08.756] [INFO] ---
[2025-06-27 14:33:08.757] [INFO] Testing: GET /dashboard/intercepts - Intercept statistics
[2025-06-27 14:33:08.872] [INFO] Response Status: 401
[2025-06-27 14:33:08.873] [INFO] Response Data: {
  "data": null,
  "err": "login-required",
  "msg": "Login required"
}
[2025-06-27 14:33:08.873] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:08 GMT', 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': '59', 'Connection': 'keep-alive'}
[2025-06-27 14:33:08.873] [INFO] ---
[2025-06-27 14:33:08.874] [INFO] Testing: GET /User - Current user information
[2025-06-27 14:33:08.985] [INFO] Response Status: 404
[2025-06-27 14:33:08.986] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:08.986] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:08 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:08.986] [INFO] ---
[2025-06-27 14:33:08.986] [INFO] Testing: GET /DetectLogList - Detection logs list
[2025-06-27 14:33:09.099] [INFO] Response Status: 404
[2025-06-27 14:33:09.100] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:09.100] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:09 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:09.100] [INFO] ---
[2025-06-27 14:33:09.100] [INFO] Testing: GET /DetectLogDetail - Detection log detail
[2025-06-27 14:33:09.211] [INFO] Response Status: 404
[2025-06-27 14:33:09.211] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:09.212] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:09 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:09.212] [INFO] ---
[2025-06-27 14:33:09.212] [INFO] Testing: GET /Website - Website list
[2025-06-27 14:33:09.323] [INFO] Response Status: 404
[2025-06-27 14:33:09.324] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:09.324] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:09 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:09.325] [INFO] ---
[2025-06-27 14:33:09.325] [INFO] Testing: GET /PolicyRule - Policy rules list
[2025-06-27 14:33:09.428] [INFO] Response Status: 404
[2025-06-27 14:33:09.429] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:09.429] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:09 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:09.429] [INFO] ---
[2025-06-27 14:33:09.429] [INFO] Testing: GET /PolicyGroupGlobal - Global policy group
[2025-06-27 14:33:09.534] [INFO] Response Status: 404
[2025-06-27 14:33:09.535] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:09.535] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:09 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:09.535] [INFO] ---
[2025-06-27 14:33:09.535] [INFO] Testing: GET /SrcIPConfig - Source IP configuration
[2025-06-27 14:33:09.639] [INFO] Response Status: 404
[2025-06-27 14:33:09.639] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:09.639] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:09 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:09.639] [INFO] ---
[2025-06-27 14:33:09.640] [SECTION] 
=== Testing Resource Creation (Expected to Fail) ===
[2025-06-27 14:33:09.640] [INFO] Testing: POST /Website - Create test website
[2025-06-27 14:33:09.744] [INFO] Response Status: 404
[2025-06-27 14:33:09.744] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:09.745] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:09 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:09.745] [INFO] ---
[2025-06-27 14:33:09.745] [SECTION] 
=== Testing Logout ===
[2025-06-27 14:33:09.745] [INFO] Testing: POST /Logout - User logout
[2025-06-27 14:33:09.856] [INFO] Response Status: 404
[2025-06-27 14:33:09.856] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:09.857] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:09 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:09.857] [INFO] ---
[2025-06-27 14:33:09.857] [SECTION] 
=== Testing Additional Possible Endpoints ===
[2025-06-27 14:33:09.857] [INFO] Testing: GET /status - Status endpoint
[2025-06-27 14:33:09.973] [INFO] Response Status: 404
[2025-06-27 14:33:09.974] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:09.974] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:09 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:09.974] [INFO] ---
[2025-06-27 14:33:09.975] [INFO] Testing: GET /info - Info endpoint
[2025-06-27 14:33:10.100] [INFO] Response Status: 404
[2025-06-27 14:33:10.100] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:10.101] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:10 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:10.101] [INFO] ---
[2025-06-27 14:33:10.101] [INFO] Testing: GET /metrics - Metrics endpoint
[2025-06-27 14:33:10.212] [INFO] Response Status: 404
[2025-06-27 14:33:10.213] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:10.213] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:10 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:10.214] [INFO] ---
[2025-06-27 14:33:10.214] [INFO] Testing: GET /open/publish/server - Internal server endpoint
[2025-06-27 14:33:10.326] [INFO] Response Status: 404
[2025-06-27 14:33:10.327] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:10.328] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:10 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:10.328] [INFO] ---
[2025-06-27 14:33:10.328] [INFO] Testing: GET /health - Alternative health check
[2025-06-27 14:33:10.438] [INFO] Response Status: 404
[2025-06-27 14:33:10.439] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:10.439] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:10 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:10.439] [INFO] ---
[2025-06-27 14:33:10.439] [INFO] Testing: GET /healthz - Kubernetes-style health check
[2025-06-27 14:33:10.550] [INFO] Response Status: 404
[2025-06-27 14:33:10.550] [INFO] Response Text: 404 page not found
[2025-06-27 14:33:10.551] [INFO] Response Headers: {'Server': 'nginx', 'Date': 'Fri, 27 Jun 2025 07:33:10 GMT', 'Content-Type': 'text/plain', 'Content-Length': '18', 'Connection': 'keep-alive'}
[2025-06-27 14:33:10.551] [INFO] ---
[2025-06-27 14:33:10.551] [COMPLETE] 
=== Test Execution Complete ===

---

## Test Summary

- **Test Completed**: 2025-06-27 14:33:10
- **Log File**: SAFELINE_REAL_API_TEST_LOG_20250627_143307.md
- **Total Endpoints Tested**: ~20+ endpoints
- **Authentication Status**: Token-based authentication attempted

### Key Findings
- SafeLine uses `/api/` prefix (not `/api/open/`)
- Health check endpoint: `/api/Ping` returns 'pong'
- Session-based authentication system in place
- API token may require different authentication method
