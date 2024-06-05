resource "aws_cloudwatch_log_group" "create_server_log_group" {
  name  = "/aws/lambda/ck-create-server"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "get_server_log_group" {
  name  = "/aws/lambda/ck-get-server"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "update_server_log_group" {
  name  = "/aws/lambda/ck-update-server"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "ck_authorizer_log_group" {
  name  = "/aws/lambda/ck-authorizer"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "apigateway_access_log_group" {
  name              = "/aws/apigateway/${aws_apigatewayv2_api.creeper_keeper.name}-access-logs"
  retention_in_days = 7
}
