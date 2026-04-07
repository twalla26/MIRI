from botocore.exceptions import ClientError

def run(iam_client):
    finding = {
        "check_id": "CIS-2.9",
        "check_name": "IAM Password Policy Prevents Reuse",
        "service": "IAM",
        "resource_type": "Account",
        "resource_id": "PasswordPolicy",
        "status": "PASS",
        "reason": "Password reuse prevention is set to 24 or more"
    }

    try:
        resp = iam_client.get_account_password_policy()
        p = resp.get('PasswordPolicy', {})
        
        # CIS 권고: 최소 24개의 이전 비밀번호 기억
        reuse_prevention = p.get('PasswordReusePrevention', 0)
        if reuse_prevention < 24:
            finding["status"] = "FAIL"
            finding["reason"] = f"Reuse prevention is {reuse_prevention} (Needs to be >= 24)"

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        
        if error_code == 'NoSuchEntity':
            finding["status"] = "FAIL"
            finding["reason"] = "Custom password policy is not configured"
        else:
            finding["status"] = "ERROR"
            finding["reason"] = str(e)

    return finding