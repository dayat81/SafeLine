#!/bin/bash

# Stop SafeLine services script

echo "Stopping SafeLine services..."

# Check if docker-compose file exists
if [ ! -f "compose.yaml" ]; then
    echo "Error: compose.yaml not found in current directory"
    echo "Please run this script from the SafeLine directory"
    exit 1
fi

# Stop all services
echo "Stopping all SafeLine containers..."
docker compose -f compose.yaml down

# Check if services stopped successfully
if [ $? -eq 0 ]; then
    echo "✓ SafeLine services stopped successfully"
    
    # Show stopped containers
    echo ""
    echo "Stopped services:"
    echo "- safeline-mgt (Management API)"
    echo "- safeline-detector (Detection Engine)"
    echo "- safeline-tengine (WAF Proxy)"
    echo "- safeline-pg (PostgreSQL Database)"
    echo "- safeline-luigi (Log Processing)"
    echo "- safeline-fvm (Feature Version Management)"
    echo "- safeline-chaos (Chaos Engineering)"
else
    echo "✗ Error stopping SafeLine services"
    exit 1
fi

# Optional: Remove volumes (uncomment if needed)
# read -p "Do you want to remove data volumes? (y/N): " -n 1 -r
# echo
# if [[ $REPLY =~ ^[Yy]$ ]]; then
#     docker compose -f compose.yaml down -v
#     echo "Data volumes removed"
# fi

echo ""
echo "SafeLine has been stopped."