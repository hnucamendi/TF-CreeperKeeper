resource "aws_acm_certificate" "cert" {
  domain_name       = local.ck_domain_name
  subject_alternative_names = ["*.${local.ck_domain_name}"]
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}
resource "aws_acm_certificate" "cdn_cert" {
  domain_name       = local.ck_web_cdn_domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

data "aws_route53_zone" "zone" {
  name         = local.ck_domain_name
  private_zone = false
}

resource "aws_route53_record" "validation_record" {
  for_each = {
    for dvo in aws_acm_certificate.cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.zone.zone_id
}

resource "aws_route53_record" "cdn_validation_record" {
  for_each = {
    for dvo in aws_acm_certificate.cdn_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.zone.zone_id
}

resource "aws_acm_certificate_validation" "validation" {
  certificate_arn = aws_acm_certificate.cert.arn
  validation_record_fqdns = [for record in aws_route53_record.validation_record : record.fqdn]
}

resource "aws_acm_certificate_validation" "cdn_validation" {
  certificate_arn = aws_acm_certificate.cdn_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.cdn_validation_record : record.fqdn]
}

resource "aws_apigatewayv2_domain_name" "statemanager_api_domain" {
  domain_name = local.statemanager_api_domain_name  
  domain_name_configuration {
    certificate_arn = aws_acm_certificate.cert.arn
    endpoint_type   = "REGIONAL"
    security_policy = "TLS_1_2"
  }
  depends_on = [aws_acm_certificate.cert]
}
resource "aws_route53_record" "statemanager_api_record" {
  zone_id = data.aws_route53_zone.zone.zone_id
  name    = local.statemanager_api_domain_name
  type    = "A"
  alias {
    name                   = aws_apigatewayv2_domain_name.statemanager_api_domain.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.statemanager_api_domain.domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "creeper_app_keeper_record" {
  zone_id = data.aws_route53_zone.zone.zone_id
  name    = local.ck_app_domain_name
  type    = "A"
  alias {
    name                   = aws_apigatewayv2_domain_name.creeper_keeper_api_domain.domain_name_configuration[0].target_domain_name
    zone_id                = aws_apigatewayv2_domain_name.creeper_keeper_api_domain.domain_name_configuration[0].hosted_zone_id
    evaluate_target_health = false
  }
}
