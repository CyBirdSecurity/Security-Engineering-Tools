# Backup bucket: versioned, Object Lock (default retention on every version),
# SSE-KMS with a customer-managed key, no public access, TLS only, and
# lifecycle tiering. Apply this in a dedicated backup AWS account if you can,
# so a compromise of your main account can't touch the backups.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  partition     = data.aws_partition.current.partition
  prefix        = trim(var.s3_prefix, "/")
  backed_up_org = coalesce(var.backed_up_org, var.github_owner)
  bucket_arn    = aws_s3_bucket.backup.arn
}

# ---------------------------------------------------------------------------
# KMS key
# ---------------------------------------------------------------------------

resource "aws_kms_key" "backup" {
  description             = "Encrypts GitHub org backups in s3://${var.bucket_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  # Deleting this key makes every backup unreadable.
  lifecycle {
    prevent_destroy = true
  }

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # Standard statement: lets IAM policies in this account grant key use
      # (the backup/restore roles below get only what they need).
      Sid       = "EnableIAMPolicies"
      Effect    = "Allow"
      Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_kms_alias" "backup" {
  name          = "alias/github-org-backup"
  target_key_id = aws_kms_key.backup.key_id
}

# ---------------------------------------------------------------------------
# Bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "backup" {
  bucket              = var.bucket_name
  object_lock_enabled = true # also turns on versioning; can't be disabled later

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_ownership_controls" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "backup" {
  bucket                  = aws_s3_bucket.backup.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "backup" {
  bucket = aws_s3_bucket.backup.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.object_lock_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.backup]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.backup.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id

  # Weekly snapshots: tier down, then expire. Versions still under Object
  # Lock are kept until their retention ends, whatever these rules say.
  rule {
    id     = "snapshots"
    status = "Enabled"
    filter {
      prefix = "${local.prefix}/snapshots/"
    }
    transition {
      days          = var.snapshot_glacier_ir_days
      storage_class = "GLACIER_IR"
    }
    transition {
      days          = var.snapshot_deep_archive_days
      storage_class = "DEEP_ARCHIVE"
    }
    expiration {
      days = var.snapshot_expiration_days
    }
    # A version that gets overwritten (by a retried upload, or by someone
    # misusing the writer role) is kept as long as a current one would be,
    # so overwriting can't shorten how long a backup survives.
    noncurrent_version_expiration {
      noncurrent_days = var.snapshot_expiration_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  # Permanent final copies of archived repos: Deep Archive, and nothing ever
  # expires, not even non-current versions. If the writer role overwrites a
  # final-copy object, the original version is still kept forever.
  rule {
    id     = "archived-final"
    status = "Enabled"
    filter {
      prefix = "${local.prefix}/archived-final/"
    }
    transition {
      days          = var.final_copy_deep_archive_days
      storage_class = "DEEP_ARCHIVE"
    }
    noncurrent_version_transition {
      noncurrent_days = var.final_copy_deep_archive_days
      storage_class   = "DEEP_ARCHIVE"
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  # Small state files are overwritten every run; keep recent history only.
  rule {
    id     = "state"
    status = "Enabled"
    filter {
      prefix = "${local.prefix}/state/"
    }
    noncurrent_version_expiration {
      noncurrent_days = var.object_lock_days + 30
    }
  }

  rule {
    id     = "expired-delete-markers"
    status = "Enabled"
    filter {
      prefix = "${local.prefix}/"
    }
    expiration {
      expired_object_delete_marker = true
    }
  }

  lifecycle {
    precondition {
      condition     = var.snapshot_expiration_days > var.object_lock_days
      error_message = "snapshot_expiration_days must be greater than object_lock_days."
    }
    precondition {
      condition     = var.snapshot_deep_archive_days > var.snapshot_glacier_ir_days
      error_message = "snapshot_deep_archive_days must be greater than snapshot_glacier_ir_days."
    }
  }

  depends_on = [aws_s3_bucket_versioning.backup]
}

resource "aws_s3_bucket_policy" "backup" {
  bucket = aws_s3_bucket.backup.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        # Only explicitly listed break-glass principals may bypass GOVERNANCE
        # retention (no effect in COMPLIANCE mode, which nobody can bypass).
        Sid       = "DenyGovernanceBypass"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:BypassGovernanceRetention"
        Resource  = "${local.bucket_arn}/*"
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = length(var.break_glass_principal_arns) > 0 ? var.break_glass_principal_arns : ["arn:${local.partition}:iam::${local.account_id}:role/no-break-glass-configured"]
          }
        }
      },
    ]
  })
  # Object Lock can't be turned off and versioning can't be suspended on an
  # Object Lock bucket, so no extra deny is needed for those settings.
  depends_on = [aws_s3_bucket_public_access_block.backup]
}
