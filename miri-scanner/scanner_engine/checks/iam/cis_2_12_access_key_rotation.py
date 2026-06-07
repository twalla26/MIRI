from botocore.exceptions import ClientError
from datetime import datetime, timezone

ROTATION_WINDOW_DAYS = 90


def run(iam_client, user):
    user_name = user['UserName']
    finding = {
        "check_id": "CIS-AWS-v7.0.0-2.12",
        "check_name": "Access Keys Rotated < 90 Days",
        "service": "IAM",
        "resource_type": "User",
        "resource_id": user_name,
        "status": "PASS",
        "reason": "All active access keys are rotated within 90 days"
    }

    now = datetime.now(timezone.utc)
    reasons = []

    try:
        paginator = iam_client.get_paginator('list_access_keys')
        for page in paginator.paginate(UserName=user_name):
            for key in page.get('AccessKeyMetadata', []):
                if key.get('Status') != 'Active':
                    continue

                access_key_id = key.get('AccessKeyId')
                create_date = key.get('CreateDate')
                if not create_date:
                    reasons.append(f"Active access key {access_key_id} has no CreateDate")
                    continue

                age_days = (now - create_date).days
                if age_days > ROTATION_WINDOW_DAYS:
                    reasons.append(f"Active access key {access_key_id} is {age_days} days old")

        if reasons:
            finding["status"] = "FAIL"
            finding["reason"] = " | ".join(reasons)

    except ClientError as e:
        finding["status"] = "ERROR"
        finding["reason"] = str(e)

    return finding
