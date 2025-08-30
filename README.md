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

**Access:**
- Application: `http://localhost:80` (via Nginx)
- API Documentation: `http://localhost:80/api/docs/`
- Direct Django: `http://localhost:8000` (development only)

### Manual Setup
1. Copy nginx config: `cp nginx/nginx.conf /etc/nginx/sites-available/todoapp`
2. Enable site: `ln -s /etc/nginx/sites-available/todoapp /etc/nginx/sites-enabled/`
3. Restart nginx: `systemctl restart nginx`

## AWS Infrastructure (Terraform)

### Prerequisites
- AWS CLI configured with appropriate credentials
- Docker and Docker Compose installed
- Route53 hosted zone for `aidevstack.org`

### Setup AWS Infrastructure

```bash
# Set AWS credentials
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1

# Navigate to infra directory
cd infra/

# Initialize and apply setup (creates S3 bucket, DynamoDB table, IAM user for CD, and ECR repositories)
docker compose run --rm terraform -chdir=setup init
docker compose run --rm terraform -chdir=setup plan
docker compose run --rm terraform -chdir=setup apply

# Get CD user credentials (needed for CI/CD)
docker compose run --rm terraform -chdir=setup output cd_user_access
docker compose run --rm terraform -chdir=setup output -raw cd_user_access_key_secret

# Get ECR repository URLs
docker compose run --rm terraform -chdir=setup output ecr_repo_app
docker compose run --rm terraform -chdir=setup output ecr_repo_proxy

# Initialize and apply deployment infrastructure
export TF_WORKSPACE=dev  # or staging/prod
docker compose run --rm terraform -chdir=deploy init
docker compose run --rm terraform -chdir=deploy workspace select -or-create $TF_WORKSPACE
docker compose run --rm terraform -chdir=deploy plan
docker compose run --rm terraform -chdir=deploy apply
```

### Infrastructure Components

#### Setup Module (`infra/setup/`)
- **S3 Bucket**: `devops-todo-api-tf-state` for Terraform state storage
- **DynamoDB Table**: `devops-todo-api-tf-lock` for state locking
- **IAM User**: `todo-app-api-cd` with comprehensive policies for CI/CD access
- **ECR Repositories**: 
  - `devops-todo-api` for application Docker images
  - `devops-todo-proxy` for proxy Docker images
- **IAM Policies**: EC2, RDS, ECS, ELB, EFS, Route53, CloudWatch, and SSM access

#### Deploy Module (`infra/deploy/`)
**Network Infrastructure:**
- **VPC**: 10.1.0.0/16 with DNS support
- **Public Subnets**: 10.1.1.0/24, 10.1.2.0/24 (ALB access)
- **Private Subnets**: 10.1.10.0/24, 10.1.11.0/24 (ECS, RDS)
- **Internet Gateway**: Public internet access
- **VPC Endpoints**: ECR, CloudWatch, SSM, S3 (private access)

**Database:**
- **RDS PostgreSQL 15.3**: db.t4g.micro instance
- **Multi-AZ**: Disabled (cost optimization)
- **Storage**: 20GB GP2 with auto-scaling
- **Security**: VPC security groups, private subnets

**Container Platform:**
- **Application Load Balancer**: HTTP/HTTPS with SSL termination
- **Target Groups**: Health checks on `/api/health-check/`
- **Security Groups**: Controlled access between services

**Storage:**
- **EFS**: Encrypted file system for media storage
- **Access Points**: Configured for application media
- **Mount Targets**: Multi-AZ availability

**DNS & SSL:**
- **Route53**: Domain management for `aidevstack.org`
- **ACM Certificates**: Automatic SSL certificate provisioning
- **Subdomains**: 
  - `api.aidevstack.org` (prod)
  - `api.staging.aidevstack.org` (staging)
  - `api.dev.aidevstack.org` (dev)

### Configuration Files
- `infra/setup/variables.tf` - S3 bucket and DynamoDB table names
- `infra/deploy/variables.tf` - Resource prefix (`raa`), project name, domain configuration
- `infra/docker-compose.yml` - Terraform 1.6.2 container configuration
- `infra/deploy/templates/ecs/` - ECS task role policies

### Environments
Managed via Terraform workspaces with prefix `raa-{workspace}`:
- **dev**: Development environment (`api.dev.aidevstack.org`)
- **staging**: Staging environment (`api.staging.aidevstack.org`)
- **prod**: Production environment (`api.aidevstack.org`)

```bash
# List workspaces
docker compose run --rm terraform -chdir=deploy workspace list

# Select workspace
export TF_WORKSPACE=dev
docker compose run --rm terraform -chdir=deploy workspace select $TF_WORKSPACE
```

### CI/CD Integration

**GitHub Actions Workflows:**
- `checks.yml` - PR validation (test and lint)
- `deploy.yml` - Automated deployment to staging/prod
- `destroy.yml` - Manual environment cleanup
- `test-and-lint.yml` - Reusable test workflow

**Required Secrets:**
- `AWS_ACCESS_KEY_ID` - CD user access key
- `AWS_SECRET_ACCESS_KEY` - CD user secret key
- `TF_VAR_DB_PASSWORD` - Database password
- `TF_VAR_DJANGO_SECRET_KEY` - Django secret key
- `DOCKERHUB_TOKEN` - Docker Hub authentication

**Required Variables:**
- `ECR_REPO_APP` - Application ECR repository URL
- `ECR_REPO_PROXY` - Proxy ECR repository URL
- `DOCKERHUB_USER` - Docker Hub username

### Access AWS Deployment

**Production URLs:**
- **Production**: `https://api.aidevstack.org`
- **Staging**: `https://api.staging.aidevstack.org`
- **Development**: `https://api.dev.aidevstack.org`

**API Documentation:**
- Swagger UI: `https://{domain}/api/docs/`
- OpenAPI Schema: `https://{domain}/api/schema/`

**Health Check:**
- Health endpoint: `https://{domain}/api/health-check/`

### Cleanup Resources

```bash
# Destroy deployment infrastructure (run for each workspace)
export TF_WORKSPACE=dev  # or staging/prod
docker compose run --rm terraform -chdir=deploy destroy

# Destroy setup infrastructure (S3, DynamoDB, IAM, ECR)
docker compose run --rm terraform -chdir=setup destroy
```