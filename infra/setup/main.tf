terrafrom {
    required_providers{
      aws ={
        source = "hashicorp/aws"
        version = "5.23.0"
      }
    }

  backend "s3" {
    bucket = "bucket-name"
    key = "tf-state-setup"
    region = "us-east-1"
    encrypt = true
    dynamodb_table = "dynamodb-table-name"
  }
}

provider "aws" {
  region = "us-east-1"
  default_tags{
    tags = {
      Environment = terraform.workspace
      Project = var.project
      contact = var.contact
      ManageBy = "Terraform/setup"
    }
  }
}