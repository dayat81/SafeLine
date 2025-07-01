# SafeLine WAF API Endpoints Documentation

## Authentication
- **API Token**: `nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS`
- **Base URL**: `https://localhost:9443/api`
- **Header**: `X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS`

## Common cURL Examples

### Authentication Test
```bash
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/User
```

### Basic Health Check
```bash
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/Ping
```

## Public API Endpoints (No Authentication Required)

### Health & System Information

#### Ping Health Check
```bash
# Endpoint: GET /api/Ping
curl -k https://localhost:9443/api/Ping

# Response: {"message": "pong"}
```

#### Get SafeLine Version
```bash
# Endpoint: GET /api/Version
curl -k https://localhost:9443/api/Version

# Response: Version information and build details
```

#### Get Upgrade Tips
```bash
# Endpoint: GET /api/UpgradeTips
curl -k https://localhost:9443/api/UpgradeTips

# Response: Available upgrade recommendations
```

#### Get OTP Setup URL
```bash
# Endpoint: GET /api/OTPUrl
curl -k https://localhost:9443/api/OTPUrl

# Response: OTP QR code URL for initial setup
```

### Authentication Endpoints

#### User Login
```bash
# Endpoint: POST /api/Login
curl -k -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your_password","code":"123456"}' \
  https://localhost:9443/api/Login

# Response: Session information and authentication status
```

#### User Logout
```bash
# Endpoint: POST /api/Logout
curl -k -X POST https://localhost:9443/api/Logout

# Response: Logout confirmation
```

## Protected API Endpoints (Require X-SLCE-API-TOKEN)

### User Management

#### Get Current User Information
```bash
# Endpoint: GET /api/User
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/User

# Response: Current user details and permissions
```

### Website Management

#### List All Websites
```bash
# Endpoint: GET /api/Website
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/Website

# Response: All configured websites with their settings
```

#### Create New Website
```bash
# Endpoint: POST /api/Website
curl -k -X POST -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -H "Content-Type: application/json" \
  -d '{
    "host": "example.com",
    "port": 80,
    "upstream": ["192.168.1.100:8080"],
    "ssl": false,
    "protection_enabled": true
  }' \
  https://localhost:9443/api/Website

# Response: Created website details
```

#### Update Website Configuration
```bash
# Endpoint: PUT /api/Website
curl -k -X PUT -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -H "Content-Type: application/json" \
  -d '{
    "id": 1,
    "protection_enabled": false,
    "ssl": true
  }' \
  https://localhost:9443/api/Website

# Response: Updated website configuration
```

#### Delete Website
```bash
# Endpoint: DELETE /api/Website
curl -k -X DELETE -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -H "Content-Type: application/json" \
  -d '{"id": 1}' \
  https://localhost:9443/api/Website

# Response: Deletion confirmation
```

### Detection Logs & Security Events

#### Get Detection Logs List
```bash
# Endpoint: GET /api/DetectLogList
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  "https://localhost:9443/api/DetectLogList?page=1&page_size=50"

# Response: List of recent security detections
```

#### Get Detection Log Details
```bash
# Endpoint: GET /api/DetectLogDetail
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  "https://localhost:9443/api/DetectLogDetail?id=12345"

# Response: Detailed information about specific detection
```

### Policy Rules Management

#### List Policy Rules
```bash
# Endpoint: GET /api/PolicyRule
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/PolicyRule

# Response: All configured security policy rules
```

#### Create Policy Rule
```bash
# Endpoint: POST /api/PolicyRule
curl -k -X POST -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom SQL Injection Rule",
    "category": "sql_injection",
    "action": "block",
    "enabled": true,
    "pattern": "union.*select"
  }' \
  https://localhost:9443/api/PolicyRule

# Response: Created rule details
```

#### Update Policy Rule
```bash
# Endpoint: PUT /api/PolicyRule
curl -k -X PUT -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -H "Content-Type: application/json" \
  -d '{
    "id": 1,
    "enabled": false,
    "action": "log"
  }' \
  https://localhost:9443/api/PolicyRule

# Response: Updated rule configuration
```

#### Toggle Policy Rule Status
```bash
# Endpoint: PUT /api/SwitchPolicyRule
curl -k -X PUT -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -H "Content-Type: application/json" \
  -d '{
    "id": 1,
    "enabled": true
  }' \
  https://localhost:9443/api/SwitchPolicyRule

# Response: Updated rule status
```

#### Delete Policy Rule
```bash
# Endpoint: DELETE /api/PolicyRule
curl -k -X DELETE -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -H "Content-Type: application/json" \
  -d '{"id": 1}' \
  https://localhost:9443/api/PolicyRule

# Response: Deletion confirmation
```

### Dashboard & Analytics

#### Get Dashboard Counts
```bash
# Endpoint: GET /api/dashboard/counts
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/dashboard/counts

# Response: Request and intercept count statistics
```

#### Get Dashboard Sites
```bash
# Endpoint: GET /api/dashboard/sites
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/dashboard/sites

# Response: Site status and health information
```

#### Get QPS (Queries Per Second) Data
```bash
# Endpoint: GET /api/dashboard/qps
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/dashboard/qps

# Response: QPS metrics and performance data
```

#### Get Request Statistics
```bash
# Endpoint: GET /api/dashboard/requests
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/dashboard/requests

# Response: Request statistics and trends
```

#### Get Intercept Statistics
```bash
# Endpoint: GET /api/dashboard/intercepts
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/dashboard/intercepts

# Response: Security intercept statistics
```

### SSL Certificate Management

#### Upload SSL Certificate
```bash
# Endpoint: POST /api/UploadSSLCert
curl -k -X POST -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -F "cert=@/path/to/certificate.crt" \
  -F "key=@/path/to/private.key" \
  https://localhost:9443/api/UploadSSLCert

# Response: Certificate upload confirmation
```

#### Configure SSL Certificate
```bash
# Endpoint: POST /api/SSLCert
curl -k -X POST -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example.com",
    "cert": "-----BEGIN CERTIFICATE-----...",
    "key": "-----BEGIN PRIVATE KEY-----..."
  }' \
  https://localhost:9443/api/SSLCert

# Response: SSL certificate configuration details
```

### Global Configuration

#### Get Global Policy Group Settings
```bash
# Endpoint: GET /api/PolicyGroupGlobal
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/PolicyGroupGlobal

# Response: Global policy group configuration
```

#### Update Global Policy Group Settings
```bash
# Endpoint: PUT /api/PolicyGroupGlobal
curl -k -X PUT -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -H "Content-Type: application/json" \
  -d '{
    "protection_mode": "block",
    "log_level": "info"
  }' \
  https://localhost:9443/api/PolicyGroupGlobal

# Response: Updated global configuration
```

#### Get Source IP Configuration
```bash
# Endpoint: GET /api/SrcIPConfig
curl -k -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  https://localhost:9443/api/SrcIPConfig

# Response: Source IP extraction configuration
```

#### Update Source IP Configuration
```bash
# Endpoint: PUT /api/SrcIPConfig
curl -k -X PUT -H "X-SLCE-API-TOKEN: nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS" \
  -H "Content-Type: application/json" \
  -d '{
    "header": "X-Forwarded-For",
    "position": "first"
  }' \
  https://localhost:9443/api/SrcIPConfig

# Response: Updated source IP configuration
```

### Behavior & False Positives

#### Submit Behavior Data
```bash
# Endpoint: POST /api/Behaviour
curl -k -X POST -H "Content-Type: application/json" \
  -d '{
    "action": "page_view",
    "url": "/dashboard",
    "timestamp": "2025-06-27T14:30:00Z"
  }' \
  https://localhost:9443/api/Behaviour

# Response: Behavior submission confirmation
```

#### Report False Positives
```bash
# Endpoint: POST /api/FalsePositives
curl -k -X POST -H "Content-Type: application/json" \
  -d '{
    "detection_id": "12345",
    "reason": "legitimate_request",
    "details": "This was a valid API call"
  }' \
  https://localhost:9443/api/FalsePositives

# Response: False positive report confirmation
```

## Testing Your API Access

### Quick Test Script
```bash
#!/bin/bash
API_TOKEN="nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS"
BASE_URL="https://localhost:9443/api"

echo "Testing SafeLine API Access with X-SLCE-API-TOKEN..."

# Test 1: Health Check (No auth required)
echo "1. Health Check:"
curl -k -s "$BASE_URL/Ping"

# Test 2: Version (No auth required)
echo -e "\n2. Version:"
curl -k -s "$BASE_URL/Version"

# Test 3: User Info (Auth required)
echo -e "\n3. User Information:"
curl -k -s -H "X-SLCE-API-TOKEN: $API_TOKEN" "$BASE_URL/User"

# Test 4: Website List (Auth required)
echo -e "\n4. Website List:"
curl -k -s -H "X-SLCE-API-TOKEN: $API_TOKEN" "$BASE_URL/Website"

# Test 5: Dashboard Counts (Auth required)
echo -e "\n5. Dashboard Counts:"
curl -k -s -H "X-SLCE-API-TOKEN: $API_TOKEN" "$BASE_URL/dashboard/counts"

echo -e "\nAPI Access Test Complete!"
```

## Error Handling

### Common HTTP Status Codes
- **200**: Success
- **400**: Bad Request (invalid parameters)
- **401**: Unauthorized (invalid or missing API token)
- **403**: Forbidden (insufficient permissions)
- **404**: Not Found (endpoint doesn't exist)
- **422**: Unprocessable Entity (validation errors)
- **500**: Internal Server Error

### Example Error Response
```json
{
  "data": null,
  "err": "invalid-token",
  "msg": "Invalid API token provided"
}
```

### Example Success Response
```json
{
  "data": {
    "id": 1,
    "username": "admin",
    "role": "administrator"
  },
  "err": null,
  "msg": "success"
}
```

## Advanced Usage Examples

### Automated Security Monitoring
```bash
#!/bin/bash
# Monitor for recent security detections
API_TOKEN="nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS"

while true; do
  DETECTIONS=$(curl -k -s -H "X-SLCE-API-TOKEN: $API_TOKEN" \
    "https://localhost:9443/api/DetectLogList?page=1&page_size=10" | \
    jq '.data | length')
  
  if [ "$DETECTIONS" -gt 0 ]; then
    echo "$(date): $DETECTIONS recent detections found!"
    # Send alert notification here
  fi
  
  sleep 60
done
```

### Website Configuration Management
```bash
#!/bin/bash
# Bulk website configuration
API_TOKEN="nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS"

# Create multiple websites from configuration file
while IFS=',' read -r host port upstream; do
  curl -k -X POST -H "X-SLCE-API-TOKEN: $API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"host\":\"$host\",\"port\":$port,\"upstream\":[\"$upstream\"],\"ssl\":false}" \
    https://localhost:9443/api/Website
  echo "Configured: $host"
done < websites.csv
```

### Dashboard Metrics Collection
```bash
#!/bin/bash
# Collect comprehensive dashboard metrics
API_TOKEN="nzUGQoFySj8hK1MSjrHpu7WAwnAqjORS"

echo "Collecting SafeLine Dashboard Metrics..."

curl -k -H "X-SLCE-API-TOKEN: $API_TOKEN" \
  https://localhost:9443/api/dashboard/counts | jq '{
    total_requests: .data.requests,
    total_intercepts: .data.intercepts,
    intercept_rate: (.data.intercepts / .data.requests * 100)
  }'

curl -k -H "X-SLCE-API-TOKEN: $API_TOKEN" \
  https://localhost:9443/api/dashboard/qps | jq '.data'
```

This documentation provides comprehensive coverage of SafeLine WAF API endpoints using the correct `X-SLCE-API-TOKEN` authentication header for all protected endpoints.