#!/bin/bash

# DVWA (Damn Vulnerable Web Application) Startup Script
# This script starts DVWA in Docker for security testing purposes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}DVWA Startup Script${NC}"
echo "==================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

# Configuration
CONTAINER_NAME="dvwa-app"
IMAGE_NAME="vulnerables/web-dvwa"
HOST_PORT=3000
CONTAINER_PORT=80

# Stop and remove existing container if it exists
echo -e "${YELLOW}Stopping any existing DVWA container...${NC}"
if docker ps -a --format 'table {{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
    echo -e "${GREEN}Existing container removed.${NC}"
fi

# Check if port is already in use
if netstat -tuln 2>/dev/null | grep -q ":${HOST_PORT} " || ss -tuln 2>/dev/null | grep -q ":${HOST_PORT} "; then
    echo -e "${RED}Error: Port ${HOST_PORT} is already in use.${NC}"
    echo "Please stop the service using this port or choose a different port."
    exit 1
fi

# Pull the latest DVWA image
echo -e "${YELLOW}Pulling DVWA Docker image...${NC}"
docker pull "$IMAGE_NAME"

# Start DVWA container
echo -e "${YELLOW}Starting DVWA container...${NC}"
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "${HOST_PORT}:${CONTAINER_PORT}" \
    --restart unless-stopped \
    "$IMAGE_NAME"

# Wait for container to be ready
echo -e "${YELLOW}Waiting for DVWA to initialize...${NC}"
sleep 10

# Check if container is running
if docker ps --format 'table {{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${GREEN}✓ DVWA container started successfully!${NC}"
    
    # Health check
    echo -e "${YELLOW}Performing health check...${NC}"
    max_attempts=30
    attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -o /dev/null -w "%{http_code}" "http://localhost:${HOST_PORT}" | grep -q "200\|302"; then
            echo -e "${GREEN}✓ DVWA is responding on port ${HOST_PORT}${NC}"
            break
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
        
        if [ $attempt -gt $max_attempts ]; then
            echo -e "${YELLOW}Warning: Health check timeout. DVWA may still be initializing.${NC}"
        fi
    done
    
    echo ""
    echo -e "${BLUE}DVWA Access Information:${NC}"
    echo "  URL: http://localhost:${HOST_PORT}"
    echo "  Default credentials: admin / password"
    echo ""
    echo -e "${BLUE}Initial Setup:${NC}"
    echo "  1. Navigate to http://localhost:${HOST_PORT}/setup.php"
    echo "  2. Click 'Create / Reset Database'"
    echo "  3. Login with admin/password"
    echo "  4. Configure security level as needed"
    echo ""
    echo -e "${BLUE}Container Management:${NC}"
    echo "  View logs: docker logs ${CONTAINER_NAME}"
    echo "  Stop DVWA: docker stop ${CONTAINER_NAME}"
    echo "  Start DVWA: docker start ${CONTAINER_NAME}"
    echo "  Remove DVWA: docker rm -f ${CONTAINER_NAME}"
    echo ""
    echo -e "${YELLOW}Note: DVWA is intentionally vulnerable and should only be used in isolated environments for security testing.${NC}"
    
else
    echo -e "${RED}✗ Failed to start DVWA container${NC}"
    echo "Check logs with: docker logs ${CONTAINER_NAME}"
    exit 1
fi

echo -e "${GREEN}DVWA is now running on port ${HOST_PORT}!${NC}"