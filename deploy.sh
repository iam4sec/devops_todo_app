#!/bin/bash

# Build and deploy with nginx load balancing
docker-compose down
docker-compose build
docker-compose up -d

echo "Deployment complete. Services running:"
echo "- Nginx: https://localhost (load balancer)"
echo "- App instances: localhost:8000, localhost:8001"
echo "- PostgreSQL: localhost:5432"