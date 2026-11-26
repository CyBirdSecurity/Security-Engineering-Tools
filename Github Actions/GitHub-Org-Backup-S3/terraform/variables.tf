variable "aws_region" {
  description = "Region for the backup bucket and KMS key."
  type        = string
}

variable "bucket_name" {
  description = "Globally unique name for the backup bucket."
  type        = string
}

variable "github_owner" {
  description = "Owner (org or user) of the repository that RUNS the backup workflow. Case-sensitive, as shown on GitHub."
  type        = string
}

variable "backup_repo" {
  description = "Name of the repository that runs the backup workflow (e.g. org-backup)."
  type        = string
}

variable "backed_up_org" {
  description = "Org being backed up (used for the freshness check key). Defaults to github_owner."
  type        = string
  default     = null
}

variable "backup_environment" {
  description = "GitHub environment the backup jobs run in; the backup role trusts only this environment."
  type        = string
  default     = "backup"
}

variable "restore_environment" {
  description = "GitHub environment the restore drill runs in; the read-only restore role trusts only this environment."
  type        = string
  default     = "restore"
}

variable "s3_prefix" {
  description = "Key prefix inside the bucket. Must match the BACKUP_S3_PREFIX repo variable."
  type        = string
  default     = "github-backup"
}

variable "object_lock_mode" {
  description = "GOVERNANCE (can be bypassed by principals in break_glass_principal_arns) or COMPLIANCE (no one can shorten or remove it)."
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "object_lock_days" {
  description = "Default Object Lock retention applied to every object version."
  type        = number
  default     = 90
}

variable "snapshot_glacier_ir_days" {
  description = "Days before weekly snapshots move to Glacier Instant Retrieval."
  type        = number
  default     = 30
}

variable "snapshot_deep_archive_days" {
  description = "Days before weekly snapshots move to Glacier Deep Archive. Keep >= glacier_ir_days + 90 to avoid Glacier IR early-deletion fees."
  type        = number
  default     = 120
}

variable "snapshot_expiration_days" {
  description = "Days before weekly snapshots expire. Must be greater than object_lock_days."
  type        = number
  default     = 365

  validation {
    condition     = var.snapshot_expiration_days > 0
    error_message = "snapshot_expiration_days must be positive."
  }
}

variable "final_copy_deep_archive_days" {
  description = "Days before permanent archived-repo final copies move to Deep Archive (they never expire)."
  type        = number
  default     = 30
}

variable "create_oidc_provider" {
  description = "Create the GitHub Actions OIDC provider. Set false if the AWS account already has one for token.actions.githubusercontent.com."
  type        = bool
  default     = true
}

variable "break_glass_principal_arns" {
  description = "IAM principal ARNs allowed to bypass GOVERNANCE retention (e.g. a tightly held admin role). Empty = nobody, via bucket policy."
  type        = list(string)
  default     = []
}

variable "enable_freshness_alarm" {
  description = "Deploy a daily Lambda that emails (via SNS) when no successful full backup has landed recently. Covers the case where the workflow never runs at all."
  type        = bool
  default     = false
}

variable "alarm_email" {
  description = "Email address subscribed to the freshness alarm topic (confirm the subscription email). Required when enable_freshness_alarm = true."
  type        = string
  default     = ""
}

variable "freshness_max_age_hours" {
  description = "Alert when the last successful full backup is older than this. Default 8 days for a weekly schedule."
  type        = number
  default     = 192
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default = {
    Purpose = "github-org-backup"
  }
}
