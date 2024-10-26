# Lambda Function
resource "aws_lambda_function" "ec2_state_manager" {
  function_name = local.ec2_app_name
  role          = aws_iam_role.main_role.arn
  architectures = ["x86_64"]
  filename      = "./bootstrap.zip"
  handler       = "bootstrap"
  runtime       = "provided.al2023"
}


# API Gateway
resource "aws_apigatewayv2_api" "ec2_state_manager" {
  name          = local.ec2_app_name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_authorizer" "ec2_state_manager_authorizer" {
  api_id                            = aws_apigatewayv2_api.ec2_state_manager.id
  name                              = "${local.ec2_app_name}-api-authorizer"
  authorizer_type                   = "JWT"
  identity_sources                  = ["$request.header.Authorization"]

  jwt_configuration {
    audience = local.jwt_audience
    issuer   = local.jwt_issuer 
  }
}

resource "aws_apigatewayv2_route" "ec2_state_manager_route" {
  api_id          = aws_apigatewayv2_api.ec2_state_manager.id
  route_key       = "POST /ec2"
  target          = "integrations/${aws_apigatewayv2_integration.ec2_state_manager.id}"
  authorization_scopes = ["read:all", "write:all"]
  authorizer_id   = aws_apigatewayv2_authorizer.ec2_state_manager_authorizer.id
  authorization_type = "JWT"
}

resource "aws_apigatewayv2_stage" "ec2_state_manager_stage"{
  api_id      = aws_apigatewayv2_api.ec2_state_manager.id
  name        = "${local.ec2_app_name}-stage"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_main.arn
    format = jsonencode({
      requestId: "$context.requestId",
      ip: "$context.identity.sourceIp",
      caller: "$context.identity.caller",
      user: "$context.identity.user",
      requestTime: "$context.requestTime",
      httpMethod: "$context.httpMethod",
      resourcePath: "$context.resourcePath",
      status: "$context.status",
      protocol: "$context.protocol",
      responseLength: "$context.responseLength",
      requestTimeEpoch: "$context.requestTimeEpoch",
      errorMessage: "$context.error.message"
    })
  }

  default_route_settings {
    logging_level            = "INFO"
    data_trace_enabled       = true
    detailed_metrics_enabled = true
    throttling_burst_limit   = 5000
    throttling_rate_limit    = 10000
  }
}

resource "aws_apigatewayv2_deployment" "ec2_state_manager_deployment" {
  api_id      = aws_apigatewayv2_api.ec2_state_manager.id
  description = "Main Deployment"
  depends_on  = [aws_apigatewayv2_route.ec2_state_manager_route]
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_apigatewayv2_integration" "ec2_state_manager" {
  api_id                    = aws_apigatewayv2_api.ec2_state_manager.id
  integration_type          = "AWS_PROXY"
  description               = "EC2 State Manager Lambda Integration"
  payload_format_version    = "2.0"
  integration_method        = "POST"
  integration_uri           = aws_lambda_function.ec2_state_manager.invoke_arn
  depends_on                = [aws_lambda_function.ec2_state_manager]
}

# IAM Role
resource "aws_iam_role" "main_role" {
  name               = "${local.ec2_app_name}-role"
  assume_role_policy = data.aws_iam_policy_document.main_lambda_policy_document.json
}

data "aws_iam_policy_document" "main_lambda_policy_document" {
  statement {
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = ["lambda.amazonaws.com", "scheduler.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# IAM Role Policies
resource "aws_iam_role_policy" "main_role_policy" {
  name   = "${local.ec2_app_name}-role-policy"
  role   = aws_iam_role.main_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ],
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow",
        Action = [
          "lambda:InvokeFunction"
        ],
        Resource = [
          aws_lambda_function.ec2_state_manager.arn
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstanceStatus",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances",
        ],
        Resource = [
          "*"
        ]
      }
    ]
  })
}

# Lambda Permissions for API Gateway
resource "aws_lambda_permission" "api_gateway_get_projects" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ec2_state_manager.arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.ec2_state_manager.execution_arn}/*/*"
}

# CloudWatch Log Group

resource "aws_cloudwatch_log_group" "apigw_main" {
  name              = "/aws/apigateway/${aws_apigatewayv2_api.ec2_state_manager.name}-access-logs"
  retention_in_days = 7
}