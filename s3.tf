resource "aws_s3_bucket" "creeper_keeper_scripts" {
  bucket = "${local.ck_app_name}-scripts"
}
