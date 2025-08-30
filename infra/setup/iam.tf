###
# IAM roles and policies for the infrastructure CD account
###

resource "aws_iam_user" "cd" {
  name = "todo-app-api-cd"
}

resource "aws_iam_access_key" "cd" {
  user = aws_iam_user.cd.name
}

###
# Policy for Terraform backend to S3 and Dynamo DB access
###

data "aws_iam_policy_document" "tf_backend" {
  statement {
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.tf_state_bucket}"]
  }
  statement {
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::${var.tf_state_bucket}/tf-state-deploy/*",
      "arn:aws:s3:::${var.tf_state_bucket}/tf-state-deploy-env/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:UpdateItem",
      "dynamodb:PutItem"
    ]

    resources = ["arn:aws:dynamodb:*:*:table/${var.tf_state_lock_table}"]
  }
}


resource "aws_iam_policy" "tf_backend" {
  name        = "${aws_iam_user.cd.name}-tf-s3-dynamodb"
  description = "Allow user to use the S3 and DynamoDB resources for Terraform backend"
  policy      = data.aws_iam_policy_document.tf_backend.json
}

resource "aws_iam_user_policy_attachment" "tf_backend" {
  user       = aws_iam_user.cd.name
  policy_arn = aws_iam_policy.tf_backend.arn
}

###
# Policy for ECR access
###

data "aws_iam_policy_document" "ecr" {
  statement {
    effect = "Allow"
    actions = [
      "ecr:GetAuthorizationToken",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [

      "ecr:PutImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload"
    ]
    resources = [
      aws_ecr_repository.app.arn,
      aws_ecr_repository.proxy.arn
    ]
  }
}


resource "aws_iam_policy" "ecr" {
  name        = "${aws_iam_user.cd.name}-ecr"
  description = "Allow user to Manage the ECR resources"
  policy      = data.aws_iam_policy_document.ecr.json
}


resource "aws_iam_user_policy_attachment" "ecr" {
  user       = aws_iam_user.cd.name
  policy_arn = aws_iam_policy.ecr.arn
}