from botocore.exceptions import ClientError

def run(iam_client):
    finding = {
        "check_id": "CIS-2.5",
        "check_name": "Root Account MFA Enabled",
        "service": "IAM",
        "resource_type": "Account",
        "resource_id": "Root",
        "status": "PASS",
        "reason": "Root account has MFA enabled"
    }

    try:
        summary = iam_client.get_account_summary()
        mfa_enabled = summary.get('SummaryMap', {}).get('AccountMFAEnabled', 0)
        
        if mfa_enabled == 0:
            finding["status"] = "FAIL"
            finding["reason"] = "Root account does not have MFA enabled"
            
    except ClientError as e:
        finding["status"] = "ERROR"
        finding["reason"] = str(e)

    return finding