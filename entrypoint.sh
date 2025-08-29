#!/bin/bash
set -e

echo "Running makemigrations..."
python manage.py makemigrations

echo "Running migrations..."
python manage.py migrate

echo "Starting application..."
exec "$@"