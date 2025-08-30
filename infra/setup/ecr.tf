###
# Create Ecr repos for storing docker images
###

resource "aws_ecr_repository" "app" {
  name                 = "devops-todo-api"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = false
  }
}

output "ecr_repo_app" {
  description = "ECR repository URL for app image"
  value          = aws_ecr_repository.app.repository_url
}

output "ecr_repo_proxy" {
  description = "ECR repository URL for proxy image"
  value       = aws_ecr_repository.proxy.repository_url
}
