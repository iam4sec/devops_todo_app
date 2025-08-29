FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt django-sslserver

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p /app/logs

# Make entrypoint script executable
RUN chmod +x entrypoint.sh

# Collect static files
RUN python manage.py collectstatic --noinput

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app
USER app

EXPOSE 8000 8443

ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "manage.py", "runsslserver", "0.0.0.0:8443", "--certificate", "ssl/cert.pem", "--key", "ssl/key.pem"]