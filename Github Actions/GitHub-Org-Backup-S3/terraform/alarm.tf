# Optional (enable_freshness_alarm = true): a daily Lambda checks how old
# state/<org>/last-success.json is and emails via SNS when the last successful
# full backup is older than freshness_max_age_hours. GitHub issues can only
# report runs that happen; this catches a workflow that stopped running at all
# (disabled, deleted, broken cron, expired App key before discovery, ...).

locals {
  alarm_count   = var.enable_freshness_alarm ? 1 : 0
  freshness_key = "${local.prefix}/state/${local.backed_up_org}/last-success.json"
}

resource "aws_sns_topic" "freshness" {
  count             = local.alarm_count
  name              = "github-org-backup-freshness"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "freshness_email" {
  count     = local.alarm_count
  topic_arn = aws_sns_topic.freshness[0].arn
  protocol  = "email"
  endpoint  = var.alarm_email

  lifecycle {
    precondition {
      condition     = var.alarm_email != ""
      error_message = "Set alarm_email when enable_freshness_alarm = true."
    }
  }
}

data "archive_file" "freshness" {
  count       = local.alarm_count
  type        = "zip"
  source_file = "${path.module}/lambda/freshness_check.py"
  output_path = "${path.module}/.build/freshness_check.zip"
}

data "aws_iam_policy_document" "freshness_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "freshness" {
  count              = local.alarm_count
  name               = "github-org-backup-freshness-check"
  assume_role_policy = data.aws_iam_policy_document.freshness_trust.json
}

data "aws_iam_policy_document" "freshness" {
  count = local.alarm_count
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${local.bucket_arn}/${local.freshness_key}"]
  }
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.freshness[0].arn]
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.freshness[0].arn}:*"]
  }
}

resource "aws_iam_role_policy" "freshness" {
  count  = local.alarm_count
  name   = "freshness-check"
  role   = aws_iam_role.freshness[0].id
  policy = data.aws_iam_policy_document.freshness[0].json
}

resource "aws_cloudwatch_log_group" "freshness" {
  count             = local.alarm_count
  name              = "/aws/lambda/github-org-backup-freshness-check"
  retention_in_days = 90
}

resource "aws_lambda_function" "freshness" {
  count            = local.alarm_count
  function_name    = "github-org-backup-freshness-check"
  role             = aws_iam_role.freshness[0].arn
  runtime          = "python3.13"
  handler          = "freshness_check.handler"
  filename         = data.archive_file.freshness[0].output_path
  source_code_hash = data.archive_file.freshness[0].output_base64sha256
  timeout          = 30

  environment {
    variables = {
      BUCKET        = aws_s3_bucket.backup.id
      KEY           = local.freshness_key
      MAX_AGE_HOURS = tostring(var.freshness_max_age_hours)
      TOPIC_ARN     = aws_sns_topic.freshness[0].arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.freshness, aws_iam_role_policy.freshness]
}

resource "aws_cloudwatch_event_rule" "freshness_daily" {
  count               = local.alarm_count
  name                = "github-org-backup-freshness-daily"
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "freshness_daily" {
  count = local.alarm_count
  rule  = aws_cloudwatch_event_rule.freshness_daily[0].name
  arn   = aws_lambda_function.freshness[0].arn
}

resource "aws_lambda_permission" "freshness_daily" {
  count         = local.alarm_count
  statement_id  = "AllowDailyEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.freshness[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.freshness_daily[0].arn
}
