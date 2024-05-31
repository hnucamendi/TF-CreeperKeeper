resource "aws_apigatewayv2_api" "creeper_keeper" {
  name          = local.app_name
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_route" "ck_create_route" {
  api_id          = aws_apigatewayv2_api.creeper_keeper.id
  route_key       = "POST /ck"
  target          = "integrations/${aws_apigatewayv2_integration.ck_api_create_server.id}"
  authorizer_id   = aws_apigatewayv2_authorizer.creeper_keeper_authorizer.id
  authorization_type = "CUSTOM"
}

resource "aws_apigatewayv2_route" "ck_get_route" {
  api_id          = aws_apigatewayv2_api.creeper_keeper.id
  route_key       = "GET /ck"
  target          = "integrations/${aws_apigatewayv2_integration.ck_api_get_server.id}"
  authorizer_id   = aws_apigatewayv2_authorizer.creeper_keeper_authorizer.id
  authorization_type = "CUSTOM"
}

resource "aws_apigatewayv2_route" "ck_update_route" {
  api_id          = aws_apigatewayv2_api.creeper_keeper.id
  route_key       = "PUT /ck"
  target          = "integrations/${aws_apigatewayv2_integration.ck_api_update_server.id}"
  authorizer_id   = aws_apigatewayv2_authorizer.creeper_keeper_authorizer.id
  authorization_type = "CUSTOM"
}

resource "aws_apigatewayv2_stage" "creeper_keeper_stage"{
  api_id = aws_apigatewayv2_api.creeper_keeper.id
  name   = "${local.app_name}-stage"

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigateway_access_log_group.arn
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
      responseLength: "$context.responseLength"
    })
  }

  default_route_settings {
    logging_level = "INFO"
    data_trace_enabled = true
  }
}

resource "aws_apigatewayv2_domain_name" "creeper_keeper_domain" {
  domain_name = "ckapi.${local.domain_name}"
  
  domain_name_configuration {
    certificate_arn = aws_acm_certificate.api_cert.arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
}

resource "aws_apigatewayv2_api_mapping" "creeper_keeper_api_mapping" {
  api_id      = aws_apigatewayv2_api.creeper_keeper.id
  domain_name = aws_apigatewayv2_domain_name.creeper_keeper_domain.id
  stage       = aws_apigatewayv2_stage.creeper_keeper_stage.id
}

resource "aws_apigatewayv2_deployment" "creeper_keeper_deployment" {
  api_id      = aws_apigatewayv2_api.creeper_keeper.id
  description = "Main Deployment"

  triggers = {
    redployment = sha1(join(",", tolist([
      jsonencode(aws_apigatewayv2_integration.ck_api_create_server),
      jsonencode(aws_apigatewayv2_integration.ck_api_get_server),
      jsonencode(aws_apigatewayv2_integration.ck_api_update_server),
    ])))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_apigatewayv2_route.ck_create_route,
    aws_apigatewayv2_route.ck_get_route,
    aws_apigatewayv2_route.ck_update_route,
  ]
}

resource "aws_apigatewayv2_authorizer" "creeper_keeper_authorizer" {
  api_id                            = aws_apigatewayv2_api.creeper_keeper.id
  authorizer_type                   = "REQUEST"
  authorizer_uri                    = aws_lambda_function.ck_authorizer.invoke_arn
  identity_sources                  = ["$request.header.Authorization"]
  name                              = "ckapi-authorizer"
  authorizer_payload_format_version = "2.0"
  depends_on                        = [aws_lambda_function.ck_authorizer]
}

resource "aws_apigatewayv2_integration" "ck_api_create_server" {
  api_id                    = aws_apigatewayv2_api.creeper_keeper.id
  integration_type          = "AWS_PROXY"
  connection_type           = "INTERNET"
  description               = "Creeper Keeper Lambda Integration"
  integration_method        = "POST"
  integration_uri           = aws_lambda_function.ck_create_server.invoke_arn
  passthrough_behavior      = "WHEN_NO_MATCH"
  depends_on                = [aws_lambda_function.ck_create_server]
}

resource "aws_apigatewayv2_integration" "ck_api_get_server" {
  api_id                    = aws_apigatewayv2_api.creeper_keeper.id
  integration_type          = "AWS_PROXY"
  connection_type           = "INTERNET"
  description               = "Creeper Keeper Lambda Integration"
  integration_method        = "POST"
  integration_uri           = aws_lambda_function.ck_get_server.invoke_arn
  passthrough_behavior      = "WHEN_NO_MATCH"
  depends_on                = [aws_lambda_function.ck_get_server]
}

resource "aws_apigatewayv2_integration" "ck_api_update_server" {
  api_id                    = aws_apigatewayv2_api.creeper_keeper.id
  integration_type          = "AWS_PROXY"
  connection_type           = "INTERNET"
  description               = "Creeper Keeper Lambda Integration"
  integration_method        = "POST"
  integration_uri           = aws_lambda_function.ck_update_server.invoke_arn
  passthrough_behavior      = "WHEN_NO_MATCH"
  depends_on                = [aws_lambda_function.ck_update_server]
}
