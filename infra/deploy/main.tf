terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.99.1"
    }
  }

  backend "s3" {
    bucket = "devops-todo-api-tf-state"
    key = "tf-state-deploy"
    workspace_key_prefix = "tf-state-deploy-env"
    region = "us-east-1"
    dynamodb_table = "devops-todo-api-tf-lock"
    encrypt = true
  }
}


provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Environment = terraform.workspace
      Project = var.project
      contact = var.contact
      ManageBy = "Terraform/deploy"
    }
  }
}

locals {
  prefix ="${var.prefix}-${terraform.workspace}"
}

data "aws_region" "current" {}