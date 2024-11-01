resource "aws_s3_bucket" "creeper_keeper" {
  bucket = local.app_name
}
