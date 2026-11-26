output "bucket_name" {
  description = "Set as the BACKUP_S3_BUCKET repository variable."
  value       = aws_s3_bucket.backup.id
}

output "aws_region" {
  description = "Set as the BACKUP_AWS_REGION repository variable."
  value       = var.aws_region
}

output "backup_role_arn" {
  description = "Set as the BACKUP_AWS_ROLE_ARN repository variable."
  value       = aws_iam_role.backup.arn
}

output "restore_role_arn" {
  description = "Set as the BACKUP_AWS_RESTORE_ROLE_ARN repository variable (restore drill)."
  value       = aws_iam_role.restore.arn
}

output "kms_key_arn" {
  description = "KMS key encrypting the backups. Losing it makes every backup unreadable."
  value       = aws_kms_key.backup.arn
}

output "github_variables" {
  description = "Paste-ready repository variables for the backup repo."
  value = {
    BACKUP_S3_BUCKET            = aws_s3_bucket.backup.id
    BACKUP_AWS_REGION           = var.aws_region
    BACKUP_AWS_ROLE_ARN         = aws_iam_role.backup.arn
    BACKUP_AWS_RESTORE_ROLE_ARN = aws_iam_role.restore.arn
    BACKUP_S3_PREFIX            = local.prefix
  }
}
