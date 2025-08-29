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
- HttpOnly cookies
- CSRF protection
- Rate limiting
- Security headers (X-Frame-Options, etc.)
- Request validation
- Idempotency keys

## Nginx Deployment

### Features
- Reverse proxy with load balancing
- Static/media file serving
- Rate limiting (5/min login, 10/min auth, 100/min API)
- Security headers (X-Frame-Options, etc.)
- Gzip compression

### Deploy with Docker
```bash
./deploy.sh
```

**Port:**
- HTTP: `http://localhost:8000`

### Manual Setup
1. Copy nginx config: `cp nginx/nginx.conf /etc/nginx/sites-available/todoapp`
2. Enable site: `ln -s /etc/nginx/sites-available/todoapp /etc/nginx/sites-enabled/`
3. Restart nginx: `systemctl restart nginx`