from botocore.exceptions import ClientError
from datetime import datetime, timezone

def run(iam_client, user):
    user_name = user['UserName']
    finding = {
        "check_id": "CIS-AWS-v7.0.0-2.11",
        "check_name": "Ensure credentials unused for 45 days or more are disabled (Automated)",
        "service": "IAM",
        "resource_type": "User",
        "resource_id": user_name,
        "status": "PASS",
        "reason": "No active credentials unused for 45+ days"
    }

    now = datetime.now(timezone.utc)
    reasons = []

    try:
        # 1. 콘솔 패스워드 미사용 확인 (login profile + PasswordLastUsed)
        try:
            login_profile = iam_client.get_login_profile(UserName=user_name)
            has_login = True
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'NoSuchEntity':
                has_login = False
            else:
                raise

        if has_login:
            pwd_last_used = user.get('PasswordLastUsed')
            if pwd_last_used:
                days_unused = (now - pwd_last_used).days
                if days_unused >= 45:
                    reasons.append(f"Password unused for {days_unused} days")
            else:
                create_date = login_profile.get('LoginProfile', {}).get('CreateDate')
                if create_date:
                    days_unused = (now - create_date).days
                    if days_unused >= 45:
                        reasons.append(f"Password created {days_unused} days ago and never used")
                else:
                    reasons.append("Password exists but no usage info")

        # 2. 액세스 키 미사용 확인 (paginator + get_access_key_last_used)
        paginator = iam_client.get_paginator('list_access_keys')
        for page in paginator.paginate(UserName=user_name):
            for key in page.get('AccessKeyMetadata', []):
                if key.get('Status') != 'Active':
                    continue
                access_key_id = key.get('AccessKeyId')
                try:
                    last_used_resp = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                    last_used_info = last_used_resp.get('AccessKeyLastUsed', {})
                    last_used_date = last_used_info.get('LastUsedDate') or key.get('CreateDate')
                    if not last_used_date:
                        reasons.append(f"Access key ({access_key_id}) has no last-used or create date")
                        continue
                    key_days_unused = (now - last_used_date).days
                    if last_used_info.get('LastUsedDate'):
                        if key_days_unused >= 45:
                            reasons.append(f"Access key ({access_key_id}) unused for {key_days_unused} days (last used)")
                    else:
                        if key_days_unused >= 45:
                            reasons.append(f"Access key ({access_key_id}) never used; age {key_days_unused} days")
                except ClientError as e:
                    reasons.append(f"Error checking access key ({access_key_id}): {e}")

        if reasons:
            finding["status"] = "FAIL"
            finding["reason"] = " | ".join(reasons)

    except ClientError as e:
        finding["status"] = "ERROR"
        finding["reason"] = str(e)

    return finding