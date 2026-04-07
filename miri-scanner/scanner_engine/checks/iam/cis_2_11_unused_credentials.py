from botocore.exceptions import ClientError
from datetime import datetime, timezone

def run(iam_client, user):
    user_name = user['UserName']
    finding = {
        "check_id": "CIS-2.11",
        "check_name": "Credentials Unused for 45 Days",
        "service": "IAM",
        "resource_type": "User",
        "resource_id": user_name,
        "status": "PASS",
        "reason": "No active credentials unused for 45+ days"
    }

    now = datetime.now(timezone.utc)
    reasons = []

    try:
        # 1. 콘솔 패스워드 미사용 확인 (PasswordLastUsed)
        if 'PasswordLastUsed' in user:
            days_unused = (now - user['PasswordLastUsed']).days
            if days_unused >= 45:
                reasons.append(f"Password unused for {days_unused} days")
        
        # 2. 액세스 키 미사용 확인 (get_access_key_last_used API 사용)
        keys_resp = iam_client.list_access_keys(UserName=user_name)
        for key in keys_resp.get('AccessKeyMetadata', []):
            if key['Status'] == 'Active':
                last_used_resp = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                last_used_info = last_used_resp.get('AccessKeyLastUsed', {})
                
                # 사용한 적이 있으면 LastUsedDate 기준, 없으면 CreateDate 기준
                last_used_date = last_used_info.get('LastUsedDate', key['CreateDate'])
                key_days_unused = (now - last_used_date).days
                
                if key_days_unused >= 45:
                    reasons.append(f"Access key ({key['AccessKeyId']}) unused for {key_days_unused} days")

        if reasons:
            finding["status"] = "FAIL"
            finding["reason"] = " | ".join(reasons)

    except ClientError as e:
        finding["status"] = "ERROR"
        finding["reason"] = str(e)

    return finding