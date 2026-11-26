# GitHub Actions OIDC -> two IAM roles:
#   backup  : write-only into the backup prefixes, can read only its own state
#             files, and is explicitly denied every delete / retention change.
#   restore : read-only, for the restore drill and real restores.

locals {
  oidc_host = "token.actions.githubusercontent.com"
  oidc_arn  = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
}

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_oidc_provider ? 1 : 0
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  # AWS validates GitHub's OIDC certificates itself; these well-known values
  # are only here for provider versions that still require the argument.
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://${local.oidc_host}"
}

# Default GitHub OIDC subject for a job that uses an environment:
#   repo:<owner>/<repo>:environment:<name>
# If your org customised the OIDC subject template, adjust these conditions.
data "aws_iam_policy_document" "trust_backup" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_owner}/${var.backup_repo}:environment:${var.backup_environment}"]
    }
  }
}

data "aws_iam_policy_document" "trust_restore" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_owner}/${var.backup_repo}:environment:${var.restore_environment}"]
    }
  }
}

# ---------------------------------------------------------------------------
# Backup role (write-only)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "backup" {
  name                 = "github-org-backup-writer"
  description          = "Assumed by the GitHub org backup workflow via OIDC. Can add backups, never delete them."
  assume_role_policy   = data.aws_iam_policy_document.trust_backup.json
  max_session_duration = 21600 # 6h: long shard jobs request 6h sessions
}

data "aws_iam_policy_document" "backup" {
  statement {
    sid     = "WriteBackups"
    actions = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = [
      "${local.bucket_arn}/${local.prefix}/snapshots/*",
      "${local.bucket_arn}/${local.prefix}/archived-final/*",
      "${local.bucket_arn}/${local.prefix}/state/*",
    ]
  }

  statement {
    sid       = "ReadOwnState"
    actions   = ["s3:GetObject"]
    resources = ["${local.bucket_arn}/${local.prefix}/state/*"]
  }

  # Lets the scripts tell "state file not created yet" (first run) apart from
  # a real permission error, by listing exactly that key.
  statement {
    sid       = "ListStatePrefix"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${local.prefix}/state/*"]
    }
  }

  statement {
    sid = "UseBackupKey"
    # Decrypt is required for multipart uploads with SSE-KMS.
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.backup.arn]
  }

  statement {
    sid    = "NeverDeleteOrWeaken"
    effect = "Deny"
    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:DeleteObjectTagging",
      "s3:DeleteObjectVersionTagging",
      "s3:BypassGovernanceRetention",
      "s3:PutObjectRetention",
      "s3:PutObjectLegalHold",
      "s3:PutBucket*",
      "s3:DeleteBucket*",
      "s3:PutLifecycleConfiguration",
      "s3:PutEncryptionConfiguration",
      "s3:PutReplicationConfiguration",
    ]
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]
  }

  statement {
    sid       = "NeverTouchKey"
    effect    = "Deny"
    actions   = ["kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:PutKeyPolicy", "kms:CreateGrant"]
    resources = [aws_kms_key.backup.arn]
  }
}

resource "aws_iam_role_policy" "backup" {
  name   = "github-org-backup-write"
  role   = aws_iam_role.backup.id
  policy = data.aws_iam_policy_document.backup.json
}

# ---------------------------------------------------------------------------
# Restore role (read-only)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "restore" {
  name                 = "github-org-backup-reader"
  description          = "Read-only access to GitHub org backups for restore drills and restores."
  assume_role_policy   = data.aws_iam_policy_document.trust_restore.json
  max_session_duration = 21600
}

data "aws_iam_policy_document" "restore" {
  statement {
    sid = "ReadBackups"
    # RestoreObject thaws Deep Archive objects (final copies, old snapshots).
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:RestoreObject"]
    resources = ["${local.bucket_arn}/${local.prefix}/*"]
  }

  statement {
    sid       = "ListBackups"
    actions   = ["s3:ListBucket", "s3:ListBucketVersions"]
    resources = [local.bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${local.prefix}/*"]
    }
  }

  statement {
    sid       = "DecryptBackups"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.backup.arn]
  }
}

resource "aws_iam_role_policy" "restore" {
  name   = "github-org-backup-read"
  role   = aws_iam_role.restore.id
  policy = data.aws_iam_policy_document.restore.json
}
