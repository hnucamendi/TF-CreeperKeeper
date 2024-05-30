resource "aws_lambda_function" "ck_create_server" {
  function_name = "ck-create-server"
  role          = aws_iam_role.creeper_keeper_role.arn
  architectures = ["arm64"]
  filename      = "./bootstrap.zip"
  handler       = "main.HandleRequest"
  runtime       = "provided.al2"
}

resource "aws_lambda_function" "ck_get_server" {
  function_name = "ck-get-server"
  role          = aws_iam_role.creeper_keeper_role.arn
  architectures = ["arm64"]
  filename      = "./bootstrap.zip"
  handler       = "main.HandleRequest"
  runtime       = "provided.al2"
}

resource "aws_lambda_function" "ck_update_server" {
  function_name = "ck-update-server"
  role          = aws_iam_role.creeper_keeper_role.arn
  architectures = ["arm64"]
  filename      = "./bootstrap.zip"
  handler       = "main.HandleRequest"
  runtime       = "provided.al2"
}

resource "aws_lambda_function" "ck_authorizer" {
  function_name = "ck-authorizer"
  role          = aws_iam_role.creeper_keeper_role.arn
  architectures = ["arm64"]
  filename      = "./bootstrap.zip"
  handler       = "main.HandleRequest"
  runtime       = "provided.al2"
}

data "aws_iam_policy_document" "creeper_keeper_lambda_policy_document" {
  statement {
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = ["lambda.amazonaws.com", "scheduler.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "creeper_keeper_role" {
  name               = "creeper-keeper-role"
  assume_role_policy = data.aws_iam_policy_document.creeper_keeper_lambda_policy_document.json
}
