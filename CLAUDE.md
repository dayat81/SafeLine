# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
## export GEMINI_API_KEY="AIzaSyDc5iF5xLH0iujbB3jo0h94tWKiFm6IGYo"

SafeLine is a self-hosted Web Application Firewall (WAF) that protects web applications from various attacks. It consists of multiple services orchestrated via Docker Compose:
- Management API (Go/Gin)
- Detection Engine (Tengine + Lua)
- PostgreSQL database
- MCP server for AI integration
- Supporting services (Luigi, FVM, Chaos)

## Common Development Commands

### Build Commands
```bash
# Build all management components
cd management && make all

# Build specific components
make build-webserver  # API server
make build-tcd       # Tengine controller daemon

# Generate protobuf files
make proto

# Run linting
make lint
```

### Testing
```bash
# Run all tests with coverage
cd management && make test

# Run yanshi unit tests
cd yanshi && mkdir -p build && cd build && cmake .. && make && ./unittest
```

### Docker Operations
```bash
# Start all services
docker compose -f compose.yaml up -d

# Stop all services
docker compose -f compose.yaml down

# View logs
docker compose -f compose.yaml logs -f [service-name]

# Restart specific service
docker compose -f compose.yaml restart safeline-mgt
```

### Installation Management
```bash
# Install SafeLine
python3 scripts/manage.py

# Upgrade SafeLine
python3 scripts/manage.py --upgrade

# Restart services
python3 scripts/manage.py --restart
```

## Architecture Overview

### Service Architecture
- **safeline-mgt**: Core management API (port 9443) - handles web UI, API endpoints, and business logic
- **safeline-detector**: Detection engine that analyzes traffic patterns
- **safeline-tengine**: Modified Nginx serving as reverse proxy with WAF capabilities
- **safeline-pg**: PostgreSQL database for persistent storage
- **safeline-luigi**: Handles log processing and analytics
- **safeline-fvm**: Feature version management
- **safeline-chaos**: Chaos engineering service

### Key Code Paths
- **API Layer**: `management/webserver/api/` - RESTful endpoints for all features
- **Models**: `management/webserver/model/` - Database models and business entities
- **Services**: `management/webserver/service/` - Business logic implementation
- **gRPC**: `management/webserver/rpc/` - Inter-service communication
- **MCP Tools**: `mcp_server/pkg/mcp/tools/` - AI integration tools

### Database Schema
Uses PostgreSQL with GORM ORM. Key entities:
- Users, Sessions, OTP
- Websites, Certificates
- Policy Rules, Detection Logs
- IP Groups, Frequency Rules

### Inter-Service Communication
- REST API: External communication (port 9443)
- gRPC: Internal service communication
- Unix sockets: Tengine controller communication
- MCP protocol: AI tool integration

## Development Guidelines

### Go Development
- Use Go 1.21 or higher
- Dependencies managed via go.mod with vendoring
- Follow standard Go project layout
- Use context for cancellation and timeouts
- Handle errors explicitly

### API Development
When adding new API endpoints:
1. Define route in appropriate router file
2. Implement handler in `api/` directory
3. Add service logic in `service/` directory
4. Update models if needed
5. Add appropriate middleware (auth, rate limiting)

### Database Changes
1. Create migration in `management/webserver/model/migration/`
2. Update GORM models
3. Test migration up/down paths
4. Document schema changes

### MCP Tool Development
When adding new MCP tools:
1. Create tool in `mcp_server/pkg/mcp/tools/`
2. Register in `pkg/mcp/registry.go`
3. Follow naming convention: lowercase with underscores
4. Include parameter validation
5. Add comprehensive documentation

### Testing Requirements
- Unit tests for business logic
- Integration tests for API endpoints
- Mock external dependencies
- Aim for >80% code coverage
- Test error paths explicitly

## Environment Configuration

Key environment variables (configured in `.env`):
- `SAFELINE_DIR`: Installation directory
- `MGT_PORT`: Management API port (default: 9443)
- `POSTGRES_PASSWORD`: Database password
- `SUBNET_PREFIX`: Docker network subnet
- `IMAGE_TAG`: Docker image version

## Debugging Tips

### View Service Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f safeline-mgt

# Check detection logs
docker exec -it safeline-mgt bash
cat /app/data/logs/webserver.log
```

### Database Access
```bash
# Connect to PostgreSQL
docker exec -it safeline-pg psql -U safeline

# Common queries
\dt  # List tables
SELECT * FROM websites;
SELECT * FROM detect_logs ORDER BY timestamp DESC LIMIT 10;
```

### API Testing
```bash
# Get auth token
curl -k https://localhost:9443/api/open/auth/login -d '{"username":"admin","password":"password"}'

# Test authenticated endpoint
curl -k -H "Authorization: Bearer <token>" https://localhost:9443/api/open/dashboard
```

## Common Tasks

### Adding a New Detection Rule
1. Define rule in `management/webserver/model/policy_rule.go`
2. Add API endpoint in `api/policyrule.go`
3. Implement service logic in `service/policy_rule_service.go`
4. Update Tengine configuration via tcontrollerd

### Updating MCP Tools
1. Modify tool implementation in `mcp_server/pkg/mcp/tools/`
2. Update tool schema if parameters change
3. Test with MCP client
4. Update documentation

### Performance Optimization
- Use database indexes for frequent queries
- Implement caching for static data
- Use connection pooling
- Monitor goroutine leaks
- Profile CPU/memory usage with pprof