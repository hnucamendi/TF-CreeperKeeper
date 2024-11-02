locals {
  ck_domain_uri       = "creeperkeeper"
  ck_domain_name      = "${local.ck_domain_uri}.com"


  ck_app_domain_uri       = "app"
  ck_app_domain_name      = "${local.ck_app_domain_uri}.${local.ck_domain_name}"

  ck_app_name     = "creeper-keeper"
  ck_jwt_audience = ["creeper-keeper-resource"]
  ck_jwt_issuer   = "https://${var.environment}-bxn245l6be2yzhil.us.auth0.com/"
}

# Lambda Function
resource "aws_lambda_function" "creeper_keeper" {
  function_name = local.ck_app_name
  role          = aws_iam_role.creeper_keeper_role.arn
  architectures = ["x86_64"]
  filename      = "./bootstrap.zip"
  handler       = "bootstrap"
  runtime       = "provided.al2023"
}


# API Gateway
resource "aws_apigatewayv2_api" "creeper_keeper" {
  name          = local.ck_app_name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_authorizer" "creeper_keeper_authorizer" {
  api_id                            = aws_apigatewayv2_api.creeper_keeper.id
  name                              = "${local.ck_app_name}-api-authorizer"
  authorizer_type                   = "JWT"
  identity_sources                  = ["$request.header.Authorization"]

  jwt_configuration {
    audience = local.ck_jwt_audience
    issuer   = local.ck_jwt_issuer 
  }
}

resource "aws_apigatewayv2_route" "creeper_keeper_start_route" {
  api_id          = aws_apigatewayv2_api.creeper_keeper.id
  route_key       = "POST /start"
  target          = "integrations/${aws_apigatewayv2_integration.creeper_keeper.id}"
  authorization_scopes = ["read:all", "write:all"]
  authorizer_id   = aws_apigatewayv2_authorizer.creeper_keeper_authorizer.id
  authorization_type = "JWT"
}

resource "aws_apigatewayv2_route" "creeper_keeper_stop_route" {
  api_id          = aws_apigatewayv2_api.creeper_keeper.id
  route_key       = "POST /stop"
  target          = "integrations/${aws_apigatewayv2_integration.creeper_keeper.id}"
  authorization_scopes = ["read:all", "write:all"]
  authorizer_id   = aws_apigatewayv2_authorizer.creeper_keeper_authorizer.id
  authorization_type = "JWT"
}

resource "aws_apigatewayv2_stage" "creeper_keeper_stage"{
  api_id      = aws_apigatewayv2_api.creeper_keeper.id
  name        = "ck"
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

resource "aws_apigatewayv2_domain_name" "creeper_keeper_api_domain" {
  domain_name = local.ck_app_domain_name  
  domain_name_configuration {
    certificate_arn = aws_acm_certificate.cert.arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
  depends_on = [aws_acm_certificate.cert]
}

resource "aws_apigatewayv2_api_mapping" "creeper_keeper_mapping" {
  api_id      = aws_apigatewayv2_api.creeper_keeper.id
  domain_name = aws_apigatewayv2_domain_name.creeper_keeper_api_domain.domain_name
  stage       = aws_apigatewayv2_stage.creeper_keeper_stage.name
}

resource "aws_apigatewayv2_deployment" "creeper_keeper_deployment" {
  api_id      = aws_apigatewayv2_api.creeper_keeper.id
  description = "Main Deployment"
  depends_on  = [aws_apigatewayv2_route.creeper_keeper_start_route, aws_apigatewayv2_route.creeper_keeper_stop_route]
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_apigatewayv2_integration" "creeper_keeper" {
  api_id                    = aws_apigatewayv2_api.creeper_keeper.id
  integration_type          = "AWS_PROXY"
  description               = "Creeper Keeper Server Manager"
  payload_format_version    = "2.0"
  integration_method        = "POST"
  integration_uri           = aws_lambda_function.creeper_keeper.invoke_arn
  depends_on                = [aws_lambda_function.creeper_keeper]
}

# IAM Role
resource "aws_iam_role" "creeper_keeper_role" {
  name               = "${local.ck_app_name}-role"
  assume_role_policy = data.aws_iam_policy_document.creeper_keeper_lambda_policy_document.json
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

# IAM Role Policies
resource "aws_iam_role_policy" "creeper_keeper_role_policy" {
  name   = "${local.ck_app_name}-role-policy"
  role   = aws_iam_role.creeper_keeper_role.id
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
          aws_lambda_function.creeper_keeper.arn
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "ssm:SendCommand",
        ],
        Resource = [
          "*"
        ]
      }
    ]
  })
}

# Lambda Permissions for API Gateway
resource "aws_lambda_permission" "creeper_keeper_perms" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.creeper_keeper.arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.creeper_keeper.execution_arn}/*/*"
}

# CloudWatch Log Group

resource "aws_cloudwatch_log_group" "creeper_keeper_apigw" {
  name              = "/aws/apigateway/${aws_apigatewayv2_api.creeper_keeper.name}-access-logs"
  retention_in_days = 7
}