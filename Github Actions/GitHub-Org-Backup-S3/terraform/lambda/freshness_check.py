"""Daily check: alert when the last successful full GitHub org backup is too old."""

import datetime as dt
import os

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")


def handler(event, context):
    bucket, key = os.environ["BUCKET"], os.environ["KEY"]
    max_age_h = float(os.environ["MAX_AGE_HOURS"])
    problem = None
    try:
        head = s3.head_object(Bucket=bucket, Key=key)
        age_h = (dt.datetime.now(dt.timezone.utc) - head["LastModified"]).total_seconds() / 3600
        if age_h > max_age_h:
            problem = f"The last successful full backup finished {age_h:.0f} hours ago (limit {max_age_h:.0f}h)."
    except ClientError as e:
        problem = f"Could not read s3://{bucket}/{key} ({e.response['Error'].get('Code')}). No successful backup recorded yet?"

    if problem:
        sns.publish(
            TopicArn=os.environ["TOPIC_ARN"],
            Subject="GitHub org backup is stale",
            Message=f"{problem}\n\nCheck the backup workflow's recent runs and any open `backup-failure` issue.",
        )
        print(problem)
        return {"ok": False, "problem": problem}
    return {"ok": True}
