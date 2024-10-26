locals {
  domain_uri       = "creeperkeeper"
  domain_name      = "${local.domain_uri}.com"

  statemanager_api_subdomain = "statemanager"
  statemanager_api_domain_name = "${local.statemanager_api_subdomain}.${local.domain_name}"
  
  app_name = "creeper-keeper"

  ec2_app_name = "ec2-statemanager"
  jwt_audience = ["ec2-instance-manager-api-resource"]
  jwt_issuer = "https://${var.environment}-bxn245l6be2yzhil.us.auth0.com/"

  ec2_subdomain = "statemanager"
  ec2_domain_name = "${local.ec2_subdomain}.creeperkeeper.com"
}

variable "environment" {
  type = string
  default = "dev"
}