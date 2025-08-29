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

## AWS Infrastructure (Terraform)

### Prerequisites
- AWS CLI configured with appropriate credentials
- Terraform 1.6+ installed (or use Docker method below)

### Setup AWS Infrastructure

```bash
# Set AWS credentials
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1

# Navigate to infra directory
cd infra/

# Initialize and apply setup (creates S3 bucket and DynamoDB for state)
docker-compose run --rm terraform -chdir=setup init
docker-compose run --rm terraform -chdir=setup plan
docker-compose run --rm terraform -chdir=setup apply

# Initialize and apply deployment infrastructure
export TF_WORKSPACE=dev  # or staging/prod
docker-compose run --rm terraform -chdir=deploy init
docker-compose run --rm terraform -chdir=deploy workspace select -or-create $TF_WORKSPACE
docker-compose run --rm terraform -chdir=deploy plan
docker-compose run --rm terraform -chdir=deploy apply
```

### Configuration
Update these files before deployment:
- `infra/setup/variables.tf` - S3 bucket and DynamoDB table names
- `infra/deploy/variables.tf` - Project settings and resource prefix
- `infra/setup/main.tf` - Backend S3 bucket name
- `infra/deploy/main.tf` - Backend S3 bucket name

### Environments
- **dev**: Development environment
- **staging**: Staging environment  
- **prod**: Production environment

Use Terraform workspaces to manage multiple environments:
```bash
terraform workspace list
terraform workspace select dev
```