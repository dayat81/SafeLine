#!/bin/bash

# Stop DVWA (Damn Vulnerable Web Application) script

echo "Stopping DVWA services..."

# Check if DVWA container is running
if docker ps --format "table {{.Names}}" | grep -q "dvwa-app"; then
    echo "Found running DVWA container: dvwa-app"
    
    # Stop the container
    echo "Stopping DVWA container..."
    docker stop dvwa-app
    
    if [ $? -eq 0 ]; then
        echo "✓ DVWA container stopped successfully"
    else
        echo "✗ Error stopping DVWA container"
        exit 1
    fi
else
    echo "DVWA container (dvwa-app) is not running"
fi

# Check for backend-webapp services (if using docker-compose)
if [ -f "backend-webapp.yaml" ]; then
    # Check if any services from backend-webapp.yaml are running
    if docker ps --format "table {{.Names}}" | grep -q -E "dvwa|mysql"; then
        echo ""
        echo "Found backend webapp services running..."
        echo "Stopping services from backend-webapp.yaml..."
        docker compose -f backend-webapp.yaml down
        
        if [ $? -eq 0 ]; then
            echo "✓ Backend webapp services stopped successfully"
        else
            echo "✗ Error stopping backend webapp services"
        fi
    fi
fi

# Optional: Remove the container
read -p "Do you want to remove the DVWA container? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker rm dvwa-app 2>/dev/null
    echo "✓ DVWA container removed"
fi

echo ""
echo "DVWA has been stopped."

# Show current Docker status
echo ""
echo "Current Docker containers:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "NAME|dvwa|mysql" || echo "No DVWA-related containers running"