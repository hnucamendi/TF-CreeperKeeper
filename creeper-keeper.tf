locals {
  ck_domain_uri       = "creeperkeeper"
  ck_domain_name      = "${local.ck_domain_uri}.com"


  ck_app_domain_uri       = "app"
  ck_app_domain_name      = "${local.ck_app_domain_uri}.${local.ck_domain_name}"

  ck_web_domain_uri       = "www"
  ck_web_domain_name      = "${local.ck_web_domain_uri}.${local.ck_domain_name}"

  ck_web_cdn_domain_name  = "cdn.${local.ck_domain_name}"

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
  cors_configuration {
    allow_methods = ["POST", "GET", "OPTIONS"]
    allow_origins = ["http://localhost:5173", "https://creeperkeeper.com", "https://www.creeperkeeper.com"]
    allow_headers = ["authorization", "access-control-allow-origin", "content-type"]
  }
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
resource "aws_apigatewayv2_route" "creeper_keeper_add_instance_route" {
  api_id          = aws_apigatewayv2_api.creeper_keeper.id
  route_key       = "POST /addInstance"
  target          = "integrations/${aws_apigatewayv2_integration.creeper_keeper.id}"
  authorization_scopes = ["read:all", "write:all"]
  authorizer_id   = aws_apigatewayv2_authorizer.creeper_keeper_authorizer.id
  authorization_type = "JWT"
}
resource "aws_apigatewayv2_route" "creeper_keeper_get_instances_route" {
  api_id          = aws_apigatewayv2_api.creeper_keeper.id
  route_key       = "GET /getInstances"
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

# ################
# # WEBSOCKET API
# ################
# resource "aws_apigatewayv2_api" "creeper_keeper_websocket" {
#   name                       = "creeper-keeper-websocket"
#   protocol_type              = "WEBSOCKET"
#   route_selection_expression = "$request.body.action"
# }

# resource "aws_apigatewayv2_route" "connect_route" {
#   api_id    = aws_apigatewayv2_api.creeper_keeper_websocket.id
#   route_key = "$connect"
#   authorization_type = "NONE"
#   target = "integrations/${aws_apigatewayv2_integration.connect_integration.id}"
# }

# resource "aws_apigatewayv2_route" "disconnect_route" {
#   api_id    = aws_apigatewayv2_api.creeper_keeper_websocket.id
#   route_key = "$disconnect"
#   authorization_type = "NONE"
#   target = "integrations/${aws_apigatewayv2_integration.disconnect_integration.id}"
# }

# resource "aws_apigatewayv2_route" "default_route" {
#   api_id    = aws_apigatewayv2_api.creeper_keeper_websocket.id
#   route_key = "$default"
#   authorization_type = "NONE"
#   target = "integrations/${aws_apigatewayv2_integration.default_integration.id}"
# }

# resource "aws_apigatewayv2_integration" "connect_integration" {
#   api_id             = aws_apigatewayv2_api.creeper_keeper_websocket.id
#   integration_type   = "AWS_PROXY"
#   integration_uri    = aws_lambda_function.creeper_keeper_connect_function.invoke_arn
#   integration_method = "POST"
# }

# resource "aws_apigatewayv2_integration" "disconnect_integration" {
#   api_id             = aws_apigatewayv2_api.creeper_keeper_websocket.id
#   integration_type   = "AWS_PROXY"
#   integration_uri    = aws_lambda_function.creeper_keeper_disconnect_function.invoke_arn
#   integration_method = "POST"
# }

# resource "aws_apigatewayv2_integration" "default_integration" {
#   api_id             = aws_apigatewayv2_api.creeper_keeper_websocket.id
#   integration_type   = "AWS_PROXY"
#   integration_uri    = aws_lambda_function.creeper_keeper_default_function.invoke_arn
#   integration_method = "POST"
# }

# resource "aws_apigatewayv2_deployment" "websocket_deployment" {
#   api_id = aws_apigatewayv2_api.creeper_keeper_websocket.id
# }

# resource "aws_apigatewayv2_stage" "websocket_stage" {
#   api_id      = aws_apigatewayv2_api.creeper_keeper_websocket.id
#   name        = "prod"
#   deployment_id = aws_apigatewayv2_deployment.websocket_deployment.id
# }

# resource "aws_lambda_function" "creeper_keeper_connect_function" {
#   function_name = local.ck_app_name
#   role          = aws_iam_role.creeper_keeper_role.arn
#   architectures = ["x86_64"]
#   filename      = "./bootstrap.zip"
#   handler       = "bootstrap"
#   runtime       = "provided.al2023"
# }
# resource "aws_lambda_function" "creeper_keeper_disconnect_function" {
#   function_name = local.ck_app_name
#   role          = aws_iam_role.creeper_keeper_role.arn
#   architectures = ["x86_64"]
#   filename      = "./bootstrap.zip"
#   handler       = "bootstrap"
#   runtime       = "provided.al2023"
# }

# resource "aws_lambda_function" "creeper_keeper_default_function" {
#   function_name = local.ck_app_name
#   role          = aws_iam_role.creeper_keeper_role.arn
#   architectures = ["x86_64"]
#   filename      = "./bootstrap.zip"
#   handler       = "bootstrap"
#   runtime       = "provided.al2023"
# }

# resource "aws_iam_role" "lambda_execution_role" {
#   name = "lambda_execution_role"

#   assume_role_policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [
#       {
#         Effect = "Allow",
#         Principal = {
#           Service = "lambda.amazonaws.com"
#         },
#         Action = "sts:AssumeRole"
#       }
#     ]
#   })
# }

# resource "aws_iam_policy" "lambda_execution_policy" {
#   name = "lambda_execution_policy"

#   policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [
#       {
#         Effect = "Allow",
#         Action = [
#           "logs:CreateLogGroup",
#           "logs:CreateLogStream",
#           "logs:PutLogEvents"
#         ],
#         Resource = "arn:aws:logs:*:*:*"
#       },
#       {
#         Effect = "Allow",
#         Action = [
#           "execute-api:ManageConnections"
#         ],
#         Resource = "arn:aws:execute-api:*:*:*/@connections/*"
#       },
#       {
#         Effect = "Allow",
#         Action = [
#           "ec2:DescribeInstances"
#         ],
#         Resource = "*"
#       }
#     ]
#   })
# }

# resource "aws_iam_role_policy_attachment" "lambda_execution_policy_attachment" {
#   role       = aws_iam_role.lambda_execution_role.name
#   policy_arn = aws_iam_policy.lambda_execution_policy.arn
# }

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
          "ssm:GetParameters"
        ],
        Resource = [
          "*",
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "dynamodb:PutItem",
          "dynamodb:Scan",
        ],
        Resource = [
          aws_dynamodb_table.instances.arn,
        ]
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

data "aws_iam_policy_document" "amplify_creeper_keeper_SSR_policy_document" {
  statement {
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = ["amplify.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
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

resource "aws_dynamodb_table" "instances" {
  name           = "CreeperKeeper"
  billing_mode   = "PAY_PER_REQUEST"

  hash_key        = "PK"
  range_key       = "SK"

  attribute {
    name = "PK"
    type = "S"
  }
  attribute {
    name = "SK"
    type = "S"
  }
}

## Cloudfront

resource "aws_s3_bucket" "ck_web_app_bucket" {
  bucket = local.ck_domain_name
}

resource "aws_s3_bucket_website_configuration" "ck_web_app" {
  bucket = aws_s3_bucket.ck_web_app_bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

resource "aws_s3_bucket_public_access_block" "ck_web_app_access_block" {
  bucket = aws_s3_bucket.ck_web_app_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "ck_web_app" {
  bucket = aws_s3_bucket.ck_web_app_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_policy" "ck_web_app_policy" {
  bucket = aws_s3_bucket.ck_web_app_bucket.id
  policy = data.aws_iam_policy_document.ck_web_app_policy_document.json
}

data "aws_iam_policy_document" "ck_web_app_policy_document" {
  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["${aws_s3_bucket.ck_web_app_bucket.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
    ]
  }
}

resource "aws_cloudfront_distribution" "app" {
  origin {
    domain_name = "${local.ck_domain_name}.s3-website-us-east-1.amazonaws.com"
    origin_id   = local.ck_app_name

    custom_origin_config {
      http_port = "80"
      https_port = "443"
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1", "TLSv1.1", "TLSv1.2"]
    }
  }
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "creeperkeeper.com cloudfront distro"
  default_root_object = "index.html"

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
}
  aliases = [local.ck_domain_name, local.ck_web_domain_name]

    default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.ck_app_name

    forwarded_values {
      query_string = true
      cookies {
        forward = "all"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  price_class = "PriceClass_100"

  restrictions {
    geo_restriction {
      locations        = []
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = false
    acm_certificate_arn            = aws_acm_certificate_validation.validation.certificate_arn
    ssl_support_method             = "sni-only"
  }
}

resource "aws_route53_record" "records" {
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.domain_name
      alias  = {
        name = aws_cloudfront_distribution.app.domain_name
        zone_id = aws_cloudfront_distribution.app.hosted_zone_id
      }
    }
  }

  allow_overwrite = true
  name            = each.value.name
  type            = "A"
  zone_id         = data.aws_route53_zone.zone.zone_id

  alias {
    name                   = each.value.alias.name
    zone_id                = each.value.alias.zone_id
    evaluate_target_health = false
  }
}

resource "aws_ssm_parameter" "ck_jwt_audience" {
  name  = "/ck/jwt/audience"
  type  = "SecureString"
  value = "changeme"

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "ck_jwt_client_secret" {
  name  = "/ck/jwt/client_secret"
  type  = "SecureString"
  value = "changeme"

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "ck_jwt_client_id" {
  name  = "/ck/jwt/client_id"
  type  = "SecureString"
  value = "changeme"

  lifecycle {
    ignore_changes = [value]
  }
}