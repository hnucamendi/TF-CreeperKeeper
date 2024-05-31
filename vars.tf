locals {
  domain_uri       = "creeperkeeper"
  domain_name      = "${local.domain_uri}.com"
  cdn_domain_name  = "cdn.${local.domain_name}"
  auth_domain_name = "auth.${local.domain_name}"
  api_domain_name  = "api.${local.domain_name}"
  
  app_name = "creeper-keeper"
  app_resource_name = "creeper_keeper"
}
