resource "aws_s3_bucket" "creeper_keeper" {
  bucket = local.domain_name
}

resource "aws_s3_bucket_website_configuration" "creeper_keeper" {
  bucket = aws_s3_bucket.creeper_keeper.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

resource "aws_s3_bucket_public_access_block" "creeper_keeper_access_block" {
  bucket = aws_s3_bucket.creeper_keeper.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "creeper_keeper" {
  bucket = aws_s3_bucket.creeper_keeper.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_policy" "creeper_keeper_policy" {
  bucket = aws_s3_bucket.creeper_keeper.id
  policy = data.aws_iam_policy_document.creeper_keeper_policy_document.json
}

data "aws_iam_policy_document" "creeper_keeper_policy_document" {
  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["${aws_s3_bucket.creeper_keeper.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
    ]
  }
}
