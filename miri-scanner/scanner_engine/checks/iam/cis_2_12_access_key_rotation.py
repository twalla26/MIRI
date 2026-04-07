from botocore.exceptions import ClientError
from datetime import datetime, timezone

def run(iam_client, user):
    user_name = user['UserName']
    finding = {
        "check_id": "CIS-2.12",
        "check_name": "Access Keys Rotated < 90 Days",
        "service": "IAM",
        "resource_type": "User",
        "resource_id": user_name,
        "status": "PASS",
        "reason": "All active access keys are under 90 days old"
    }

    try:
        keys_resp = iam_client.list_access_keys(UserName=user_name)
        now = datetime.now(timezone.utc)
        
        reasons = []
        for key in keys_resp.get('AccessKeyMetadata', []):
            if key['Status'] == 'Active':
                age = (now - key['CreateDate']).days
                if age > 90:
                    reasons.append(f"Key {key['AccessKeyId']} is {age} days old")

        if reasons:
            finding["status"] = "FAIL"
            finding["reason"] = " | ".join(reasons)
                    
    except ClientError as e:
        finding["status"] = "ERROR"
        finding["reason"] = str(e)

    return finding