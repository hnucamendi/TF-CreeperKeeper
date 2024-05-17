resource "aws_lambda_function" "creeper_keeper_config_loader" {
  function_name = "creeper-keeper-config-loader"
  role          = aws_iam_role.creeper_keeper_config_loader_role.arn
  architectures = ["arm64"]
  filename      = "./bootstrap.zip"
  handler       = "main.HandleRequest"
  runtime       = "provided.al2"
}

resource "aws_iam_role" "creeper_keeper_config_loader_role" {
  name               = "creeper-keeper-config-loader-role"
  assume_role_policy = data.aws_iam_policy_document.creeper_keeper_config_loader_policy_document.json
}

data "aws_iam_policy_document" "creeper_keeper_config_loader_policy_document" {
  statement {
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = ["lambda.amazonaws.com", "scheduler.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}
