#!/bin/bash

# SafeLine WAF Service Startup Script
# This script starts all SafeLine services using Docker Compose

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

echo -e "${BLUE}SafeLine WAF Service Startup Script${NC}"
echo "======================================"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null 2>&1; then
    echo -e "${RED}Error: Docker Compose is not available.${NC}"
    exit 1
fi

# Function to use docker compose (newer) or docker-compose (legacy)
docker_compose_cmd() {
    if docker compose version &> /dev/null 2>&1; then
        docker compose "$@"
    else
        docker-compose "$@"
    fi
}

# Check if .env file exists
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo -e "${RED}Error: .env file not found. Please create .env file with required variables.${NC}"
    echo "Required variables:"
    echo "  SAFELINE_DIR=/data/safeline"
    echo "  POSTGRES_PASSWORD=your_password"
    echo "  SUBNET_PREFIX=172.22.222"
    echo "  MGT_PORT=9443"
    echo "  IMAGE_PREFIX=chaitin"
    echo "  IMAGE_TAG=latest"
    exit 1
fi

# Load environment variables
source "$SCRIPT_DIR/.env"

# Check if required directories exist
echo -e "${YELLOW}Checking SafeLine directories...${NC}"
if [ ! -d "$SAFELINE_DIR" ]; then
    echo -e "${YELLOW}Creating SafeLine directory: $SAFELINE_DIR${NC}"
    sudo mkdir -p "$SAFELINE_DIR"
    sudo mkdir -p "$SAFELINE_DIR/resources/postgres/data"
    sudo mkdir -p "$SAFELINE_DIR/resources/mgt"
    sudo mkdir -p "$SAFELINE_DIR/resources/nginx"
    sudo mkdir -p "$SAFELINE_DIR/resources/detector"
    sudo mkdir -p "$SAFELINE_DIR/resources/chaos"
    sudo mkdir -p "$SAFELINE_DIR/resources/luigi"
    sudo mkdir -p "$SAFELINE_DIR/resources/cache"
    sudo mkdir -p "$SAFELINE_DIR/resources/sock"
    sudo mkdir -p "$SAFELINE_DIR/logs/nginx"
    sudo mkdir -p "$SAFELINE_DIR/logs/detector"
    echo -e "${GREEN}SafeLine directories created.${NC}"
fi

# Function to check service health
check_service_health() {
    local service_name=$1
    local container_name=$2
    local max_attempts=30
    local attempt=1

    echo -e "${YELLOW}Checking health of $service_name...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if docker_compose_cmd -f "$SCRIPT_DIR/compose.yaml" ps "$service_name" 2>/dev/null | grep -q "Up"; then
            if docker exec "$container_name" sh -c 'exit 0' 2>/dev/null; then
                echo -e "${GREEN}✓ $service_name is healthy${NC}"
                return 0
            fi
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    echo -e "${RED}✗ $service_name health check failed${NC}"
    return 1
}

# Function to reset admin password
reset_admin_password() {
    echo -e "${YELLOW}Resetting SafeLine admin password...${NC}"
    
    # Wait for management service to be fully ready
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker exec safeline-mgt sh -c 'test -f /app/mgt' 2>/dev/null; then
            break
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
        
        if [ $attempt -gt $max_attempts ]; then
            echo -e "${RED}✗ Failed to find mgt command${NC}"
            return 1
        fi
    done
    
    echo ""
    
    # Execute reset-admin command and capture output
    local reset_output
    if reset_output=$(docker exec safeline-mgt /app/mgt reset-admin 2>&1); then
        echo -e "${GREEN}✓ Admin password reset successfully!${NC}"
        echo ""
        echo -e "${BLUE}Admin Credentials:${NC}"
        echo "$reset_output"
        echo ""
        return 0
    else
        echo -e "${RED}✗ Failed to reset admin password${NC}"
        echo "Error: $reset_output"
        return 1
    fi
}

# Stop any existing services
echo -e "${YELLOW}Stopping any existing SafeLine services...${NC}"
docker_compose_cmd -f "$SCRIPT_DIR/compose.yaml" down 2>/dev/null || true

# Pull latest images
echo -e "${YELLOW}Pulling latest Docker images...${NC}"
docker_compose_cmd -f "$SCRIPT_DIR/compose.yaml" pull

# Start services
echo -e "${YELLOW}Starting SafeLine services...${NC}"
docker_compose_cmd -f "$SCRIPT_DIR/compose.yaml" up -d

# Wait a moment for services to initialize
sleep 5

# Check service status
echo -e "${BLUE}Checking service status...${NC}"
echo ""

services=(
    "postgres:safeline-pg"
    "mgt:safeline-mgt"
    "detect:safeline-detector"
    "tengine:safeline-tengine"
    "luigi:safeline-luigi"
    "fvm:safeline-fvm"
    "chaos:safeline-chaos"
)

all_healthy=true
for service_info in "${services[@]}"; do
    IFS=':' read -r service container <<< "$service_info"
    if ! check_service_health "$service" "$container"; then
        all_healthy=false
    fi
done

echo ""
if [ "$all_healthy" = true ]; then
    echo -e "${GREEN}✓ All SafeLine services started successfully!${NC}"
    
    # Reset admin password and display credentials
    reset_admin_password
    
    echo -e "${BLUE}Access Information:${NC}"
    echo "  Web Interface: https://localhost:$MGT_PORT"
    echo "  Use the credentials shown above"
    echo ""
    echo -e "${BLUE}Service Management:${NC}"
    echo "  View logs: docker compose -f compose.yaml logs -f [service-name]"
    echo "  Stop services: docker compose -f compose.yaml down"
    echo "  Restart services: docker compose -f compose.yaml restart"
    echo "  Reset admin password: docker exec safeline-mgt /app/mgt reset-admin"
else
    echo -e "${RED}✗ Some services failed to start properly.${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "  1. Check logs: docker compose -f compose.yaml logs"
    echo "  2. Check system resources (CPU, memory, disk space)"
    echo "  3. Verify network connectivity"
    echo "  4. Ensure all required ports are available"
    exit 1
fi

# Show running containers
echo -e "${BLUE}Running containers:${NC}"
docker_compose_cmd -f "$SCRIPT_DIR/compose.yaml" ps

echo ""
echo -e "${GREEN}SafeLine WAF is now running!${NC}"