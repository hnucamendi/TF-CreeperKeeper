resource "aws_s3_bucket" "creeper_keeper" {
  bucket = local.ck_app_name
}
