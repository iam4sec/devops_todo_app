# devops_todo_app

Minimal Django todo app with cookie-based authentication, PostgreSQL, and REST API.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Setup PostgreSQL:
```bash
psql -U postgres -f setup.sql
```

3. Run migrations:
```bash
python manage.py migrate
```

4. Create superuser:
```bash
python manage.py createsuperuser
```

5. Run server:
```bash
python manage.py runserver
```

## HTTPS Development Setup

### Generate SSL Certificate
```bash
./generate_cert.sh
```

### Run with HTTPS
```bash
python manage.py runsslserver 0.0.0.0:8443 --certificate ssl/cert.pem --key ssl/key.pem
```

### Docker HTTPS
```bash
docker-compose up --build
```
Access: `https://localhost:8443`

### Bypass SSL Warnings

**curl:**
```bash
curl -k https://localhost:8443/
```

**Browser Trust (Optional):**
- **Chrome/Edge**: `chrome://settings/certificates` → Import `ssl/cert.pem`
- **Firefox**: `about:preferences#privacy` → View Certificates → Import

**System Trust:**
```bash
sudo cp ssl/cert.pem /usr/local/share/ca-certificates/localhost.crt
sudo update-ca-certificates
```

## API Documentation

Swagger UI is available at: `http://localhost:8000/api/docs/`
OpenAPI schema: `http://localhost:8000/api/schema/`

## API Endpoints

### Auth
- `GET /auth/csrf/` - Get CSRF token
- `POST /auth/login/` - Login (sets cookies)
- `POST /auth/refresh/` - Refresh session
- `POST /auth/logout/` - Logout

### API
- `GET /me/` - Current user profile
- `GET/POST /lists/` - Lists management
- `GET/PATCH/DELETE /lists/{id}/` - List operations
- `GET/POST /todos/` - Todos management
- `GET/PATCH/DELETE /todos/{id}/` - Todo operations
- `POST /todos/{id}/toggle/` - Toggle todo status
- `POST /todos/bulk/` - Bulk operations

## Security Features

- Argon2 password hashing
- HttpOnly, Secure cookies
- CSRF protection
- Rate limiting
- Security headers (HSTS, X-Frame-Options, etc.)
- Request validation
- Idempotency keys

## Nginx Deployment

### Features
- Reverse proxy with load balancing
- SSL/TLS termination
- Static/media file serving
- Rate limiting (5/min login, 10/min auth, 100/min API)
- Security headers (HSTS, X-Frame-Options, etc.)
- Gzip compression
- HTTP/2 support

### Deploy with Docker
```bash
./deploy.sh
```

**Ports:**
- HTTP: `http://localhost:8000`
- HTTPS: `https://localhost:8443`

### Manual Setup
1. Copy nginx config: `cp nginx/nginx.conf /etc/nginx/sites-available/todoapp`
2. Enable site: `ln -s /etc/nginx/sites-available/todoapp /etc/nginx/sites-enabled/`
3. Copy SSL certs to `/etc/nginx/ssl/`
4. Restart nginx: `systemctl restart nginx`