# resource "aws_cognito_user_pool" "main" {
#   name = "${local.app_name}-user-pool"
# 
#   schema {
#     name                = "email"
#     attribute_data_type = "String"
#     mutable             = true
#     required            = true
#   }
# 
#   auto_verified_attributes = ["email"]
#   username_attributes      = ["email"]
# 
#   email_configuration {
#     email_sending_account = "DEVELOPER"
#     from_email_address    = "CreeperKeeper <no-reply@creeperkeeper.com>"
#     source_arn            = aws_ses_domain_identity.identity.arn
#   }
# }
# 
# resource "aws_cognito_user_pool_client" "client" {
#   name                                 = "${local.app_name}-user-pool-client"
#   user_pool_id                         = aws_cognito_user_pool.main.id
#   callback_urls                        = ["https://creeperkeeper.com/home/", "http://localhost:5173/home/"]
#   logout_urls                          = ["https://creeperkeeper.com/", "http://localhost:5173/"]
#   explicit_auth_flows                  = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
#   allowed_oauth_flows_user_pool_client = true
#   generate_secret                      = false
#   refresh_token_validity               = 1
#   access_token_validity                = 60
#   id_token_validity                    = 60
#   token_validity_units {
#     refresh_token = "days"
#     access_token  = "minutes"
#     id_token      = "minutes"
#   }
# 
#   supported_identity_providers = ["COGNITO"]
# }
# 
# resource "aws_cognito_user_pool_domain" "main" {
#   domain          = local.auth_domain_name
#   certificate_arn = aws_acm_certificate.auth_cert.arn
#   user_pool_id    = aws_cognito_user_pool.main.id
# }
# 
# resource "aws_route53_record" "cognito_auth" {
#   name = aws_cognito_user_pool_domain.main.domain
#   type = "A"
#   zone_id = data.aws_route53_zone.zone.zone_id
#   alias {
#     evaluate_target_health = false
#     name                   = aws_cognito_user_pool_domain.main.cloudfront_distribution
#     zone_id                = aws_cognito_user_pool_domain.main.cloudfront_distribution_zone_id
#   }
# }
# 
# //data "aws_ses_domain_identity" "identity" {
# //  domain = local.domain_name
# //}
# resource "aws_ses_domain_identity" "identity" {
#   domain = local.domain_name
# }
