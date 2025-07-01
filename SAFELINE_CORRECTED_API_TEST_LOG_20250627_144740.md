# SafeLine WAF Corrected API Endpoint Test Log

- **Test Started**: 2025-06-27 14:47:40
- **API Token**: nzUGQoFySj...WAwnAqjORS
- **Base URL**: https://localhost:9443/api
- **Authentication**: X-SLCE-API-TOKEN header
- **Target**: SafeLine WAF Management API (Corrected)

---

[2025-06-27 14:47:40.369] [START] Starting SafeLine Corrected API Endpoint Testing
[2025-06-27 14:47:40.369] [SECTION] === 1. TESTING PUBLIC ENDPOINTS (No Authentication Required) ===
[2025-06-27 14:47:40.369] [INFO] Testing: GET /Ping - Health check endpoint
[2025-06-27 14:47:40.488] [INFO] Response Status: 404
[2025-06-27 14:47:40.489] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:40.489] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:40.489] [INFO] ================================================================================
[2025-06-27 14:47:40.489] [INFO] Testing: GET /Version - Get SafeLine version information
[2025-06-27 14:47:40.601] [INFO] Response Status: 404
[2025-06-27 14:47:40.602] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:40.602] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:40.602] [INFO] ================================================================================
[2025-06-27 14:47:40.602] [INFO] Testing: GET /UpgradeTips - Get upgrade recommendations
[2025-06-27 14:47:40.714] [INFO] Response Status: 404
[2025-06-27 14:47:40.715] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:40.715] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:40.716] [INFO] ================================================================================
[2025-06-27 14:47:40.716] [INFO] Testing: GET /OTPUrl - Get OTP setup URL for TOTP
[2025-06-27 14:47:40.828] [INFO] Response Status: 404
[2025-06-27 14:47:40.829] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:40.830] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:40.830] [INFO] ================================================================================
[2025-06-27 14:47:40.830] [SECTION] 
=== 2. TESTING AUTHENTICATION ENDPOINTS ===
[2025-06-27 14:47:40.830] [INFO] Testing: POST /Login - User login attempt
[2025-06-27 14:47:40.942] [INFO] Response Status: 404
[2025-06-27 14:47:40.943] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:40.943] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:40.943] [INFO] ================================================================================
[2025-06-27 14:47:40.943] [INFO] Testing: POST /Logout - User logout
[2025-06-27 14:47:41.055] [INFO] Response Status: 404
[2025-06-27 14:47:41.056] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:41.056] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:41.057] [INFO] ================================================================================
[2025-06-27 14:47:41.057] [INFO] Testing: POST /Behaviour - Submit behavior data
[2025-06-27 14:47:41.170] [INFO] Response Status: 404
[2025-06-27 14:47:41.171] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:41.171] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:41.171] [INFO] ================================================================================
[2025-06-27 14:47:41.171] [INFO] Testing: POST /FalsePositives - Report false positive
[2025-06-27 14:47:41.283] [INFO] Response Status: 404
[2025-06-27 14:47:41.284] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:41.285] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:41.285] [INFO] ================================================================================
[2025-06-27 14:47:41.285] [SECTION] 
=== 3. TESTING USER MANAGEMENT (API Token Required) ===
[2025-06-27 14:47:41.285] [INFO] Testing: GET /User - Get current user information
[2025-06-27 14:47:41.380] [INFO] Response Status: 404
[2025-06-27 14:47:41.381] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:41.381] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:41.382] [INFO] ================================================================================
[2025-06-27 14:47:41.382] [SECTION] 
=== 4. TESTING WEBSITE MANAGEMENT (API Token Required) ===
[2025-06-27 14:47:41.382] [INFO] Testing: GET /Website - List all configured websites
[2025-06-27 14:47:41.492] [INFO] Response Status: 404
[2025-06-27 14:47:41.493] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:41.493] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:41.493] [INFO] ================================================================================
[2025-06-27 14:47:41.493] [INFO] Testing: POST /Website - Create test website
[2025-06-27 14:47:41.589] [INFO] Response Status: 404
[2025-06-27 14:47:41.590] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:41.590] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:41.590] [INFO] ================================================================================
[2025-06-27 14:47:41.590] [INFO] Testing: PUT /Website - Update website (test with dummy ID)
[2025-06-27 14:47:41.689] [INFO] Response Status: 404
[2025-06-27 14:47:41.690] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:41.690] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:41.690] [INFO] ================================================================================
[2025-06-27 14:47:41.690] [INFO] Testing: DELETE /Website - Delete website (test with dummy ID)
[2025-06-27 14:47:41.766] [INFO] Response Status: 404
[2025-06-27 14:47:41.767] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:41.768] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:41.768] [INFO] ================================================================================
[2025-06-27 14:47:41.768] [SECTION] 
=== 5. TESTING DETECTION LOGS (API Token Required) ===
[2025-06-27 14:47:41.768] [INFO] Testing: GET /DetectLogList?page=1&page_size=20 - Get detection logs list
[2025-06-27 14:47:41.880] [INFO] Response Status: 404
[2025-06-27 14:47:41.881] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:41.881] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:41.881] [INFO] ================================================================================
[2025-06-27 14:47:41.881] [INFO] Testing: GET /DetectLogDetail?id=1 - Get detection log details
[2025-06-27 14:47:41.994] [INFO] Response Status: 404
[2025-06-27 14:47:41.995] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:41.996] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:41.996] [INFO] ================================================================================
[2025-06-27 14:47:41.996] [SECTION] 
=== 6. TESTING POLICY RULES MANAGEMENT (API Token Required) ===
[2025-06-27 14:47:41.996] [INFO] Testing: GET /PolicyRule - List all policy rules
[2025-06-27 14:47:42.104] [INFO] Response Status: 404
[2025-06-27 14:47:42.104] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:42.105] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:42.105] [INFO] ================================================================================
[2025-06-27 14:47:42.105] [INFO] Testing: POST /PolicyRule - Create policy rule
[2025-06-27 14:47:42.184] [INFO] Response Status: 404
[2025-06-27 14:47:42.185] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:42.186] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:42.186] [INFO] ================================================================================
[2025-06-27 14:47:42.186] [INFO] Testing: PUT /PolicyRule - Update policy rule (dummy)
[2025-06-27 14:47:42.299] [INFO] Response Status: 404
[2025-06-27 14:47:42.300] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:42.300] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:42.301] [INFO] ================================================================================
[2025-06-27 14:47:42.301] [INFO] Testing: PUT /SwitchPolicyRule - Toggle policy rule (dummy)
[2025-06-27 14:47:42.412] [INFO] Response Status: 404
[2025-06-27 14:47:42.413] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:42.413] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:42.413] [INFO] ================================================================================
[2025-06-27 14:47:42.413] [INFO] Testing: DELETE /PolicyRule - Delete policy rule (dummy)
[2025-06-27 14:47:42.523] [INFO] Response Status: 404
[2025-06-27 14:47:42.524] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:42.524] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:42.524] [INFO] ================================================================================
[2025-06-27 14:47:42.524] [SECTION] 
=== 7. TESTING DASHBOARD & ANALYTICS (API Token Required) ===
[2025-06-27 14:47:42.524] [INFO] Testing: GET /dashboard/counts - Get dashboard request/intercept counts
[2025-06-27 14:47:42.634] [INFO] Response Status: 404
[2025-06-27 14:47:42.635] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:42.635] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:42.636] [INFO] ================================================================================
[2025-06-27 14:47:42.636] [INFO] Testing: GET /dashboard/sites - Get dashboard sites status
[2025-06-27 14:47:42.739] [INFO] Response Status: 404
[2025-06-27 14:47:42.740] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:42.740] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:42.740] [INFO] ================================================================================
[2025-06-27 14:47:42.741] [INFO] Testing: GET /dashboard/qps - Get QPS (queries per second) metrics
[2025-06-27 14:47:42.846] [INFO] Response Status: 404
[2025-06-27 14:47:42.847] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:42.847] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:42.847] [INFO] ================================================================================
[2025-06-27 14:47:42.847] [INFO] Testing: GET /dashboard/requests - Get request statistics
[2025-06-27 14:47:42.964] [INFO] Response Status: 200
[2025-06-27 14:47:42.965] [INFO] Response Data: {
  "data": {
    "nodes": [
      {
        "label": "2025-05-29",
        "value": 0
      },
      {
        "label": "2025-05-30",
        "value": 0
      },
      {
        "label": "2025-05-31",
        "value": 0
      },
      {
        "label": "2025-06-01",
        "value": 0
      },
      {
        "label": "2025-06-02",
        "value": 0
      },
      {
        "label": "2025-06-03",
        "value": 0
      },
      {
        "label": "2025-06-04",
        "value": 0
      },
      {
        "label": "2025-06-05",
        "value": 0
      },
      {
        "label": "2025-06-06",
        "value": 0
      },
      {
        "label": "2025-06-07",
        "value": 0
      },
      {
        "label": "2025-06-08",
        "value": 0
      },
      {
        "label": "2025-06-09",
        "value": 0
      },
      {
        "label": "2025-06-10",
        "value": 0
      },
      {
        "label": "2025-06-11",
        "value": 0
      },
      {
        "label": "2025-06...
[2025-06-27 14:47:42.965] [INFO] Important Headers: {'Content-Type': 'application/json; charset=utf-8', 'Content-Length': '1040'}
[2025-06-27 14:47:42.965] [INFO] ================================================================================
[2025-06-27 14:47:42.966] [INFO] Testing: GET /dashboard/intercepts - Get intercept statistics
[2025-06-27 14:47:43.081] [INFO] Response Status: 200
[2025-06-27 14:47:43.082] [INFO] Response Data: {
  "data": {
    "nodes": [
      {
        "label": "2025-05-29",
        "value": 0
      },
      {
        "label": "2025-05-30",
        "value": 0
      },
      {
        "label": "2025-05-31",
        "value": 0
      },
      {
        "label": "2025-06-01",
        "value": 0
      },
      {
        "label": "2025-06-02",
        "value": 0
      },
      {
        "label": "2025-06-03",
        "value": 0
      },
      {
        "label": "2025-06-04",
        "value": 0
      },
      {
        "label": "2025-06-05",
        "value": 0
      },
      {
        "label": "2025-06-06",
        "value": 0
      },
      {
        "label": "2025-06-07",
        "value": 0
      },
      {
        "label": "2025-06-08",
        "value": 0
      },
      {
        "label": "2025-06-09",
        "value": 0
      },
      {
        "label": "2025-06-10",
        "value": 0
      },
      {
        "label": "2025-06-11",
        "value": 0
      },
      {
        "label": "2025-06...
[2025-06-27 14:47:43.082] [INFO] Important Headers: {'Content-Type': 'application/json; charset=utf-8', 'Content-Length': '1040'}
[2025-06-27 14:47:43.083] [INFO] ================================================================================
[2025-06-27 14:47:43.083] [SECTION] 
=== 8. TESTING SSL CERTIFICATE MANAGEMENT (API Token Required) ===
[2025-06-27 14:47:43.083] [INFO] Testing: POST /SSLCert - Configure SSL certificate
[2025-06-27 14:47:43.195] [INFO] Response Status: 404
[2025-06-27 14:47:43.196] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:43.196] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:43.196] [INFO] ================================================================================
[2025-06-27 14:47:43.196] [INFO] Skipping /UploadSSLCert test (requires file upload)
[2025-06-27 14:47:43.197] [SECTION] 
=== 9. TESTING GLOBAL CONFIGURATION (API Token Required) ===
[2025-06-27 14:47:43.197] [INFO] Testing: GET /PolicyGroupGlobal - Get global policy group settings
[2025-06-27 14:47:43.308] [INFO] Response Status: 404
[2025-06-27 14:47:43.309] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:43.309] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:43.309] [INFO] ================================================================================
[2025-06-27 14:47:43.309] [INFO] Testing: PUT /PolicyGroupGlobal - Update global policy group
[2025-06-27 14:47:43.421] [INFO] Response Status: 404
[2025-06-27 14:47:43.422] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:43.422] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:43.422] [INFO] ================================================================================
[2025-06-27 14:47:43.422] [INFO] Testing: GET /SrcIPConfig - Get source IP configuration
[2025-06-27 14:47:43.534] [INFO] Response Status: 404
[2025-06-27 14:47:43.534] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:43.535] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:43.535] [INFO] ================================================================================
[2025-06-27 14:47:43.535] [INFO] Testing: PUT /SrcIPConfig - Update source IP configuration
[2025-06-27 14:47:43.645] [INFO] Response Status: 404
[2025-06-27 14:47:43.646] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:43.646] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:43.646] [INFO] ================================================================================
[2025-06-27 14:47:43.646] [SECTION] 
=== 10. TESTING ADDITIONAL ENDPOINTS ===
[2025-06-27 14:47:43.646] [INFO] Testing: GET /health - Alternative health check
[2025-06-27 14:47:43.757] [INFO] Response Status: 404
[2025-06-27 14:47:43.758] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:43.759] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:43.759] [INFO] ================================================================================
[2025-06-27 14:47:43.759] [INFO] Testing: GET /status - Status endpoint
[2025-06-27 14:47:43.871] [INFO] Response Status: 404
[2025-06-27 14:47:43.872] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:43.872] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:43.872] [INFO] ================================================================================
[2025-06-27 14:47:43.872] [INFO] Testing: GET /metrics - Metrics endpoint
[2025-06-27 14:47:43.981] [INFO] Response Status: 404
[2025-06-27 14:47:43.982] [INFO] Response Text: 404 page not found
[2025-06-27 14:47:43.983] [INFO] Important Headers: {'Content-Type': 'text/plain', 'Content-Length': '18'}
[2025-06-27 14:47:43.983] [INFO] ================================================================================
[2025-06-27 14:47:43.983] [COMPLETE] 
=== TEST EXECUTION COMPLETE ===

---

## Test Summary

- **Test Completed**: 2025-06-27 14:47:43
- **Log File**: SAFELINE_CORRECTED_API_TEST_LOG_20250627_144740.md
- **Total Endpoints Tested**: 30+ endpoints across 10 categories
- **Authentication Method**: X-SLCE-API-TOKEN header
- **API Token Used**: nzUGQoFySj...WAwnAqjORS

### Test Categories Covered
1. Public Endpoints (Health, Version, OTP)
2. Authentication (Login, Logout)
3. User Management
4. Website Management (CRUD operations)
5. Detection Logs
6. Policy Rules Management (CRUD operations)
7. Dashboard & Analytics
8. SSL Certificate Management
9. Global Configuration
10. Additional Endpoints

### Expected Results
- Public endpoints should return 200 or valid responses
- Protected endpoints with valid token should work
- Invalid operations should return appropriate error codes
- All responses should follow SafeLine API format
