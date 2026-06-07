from botocore.exceptions import ClientError


def run(iam_client):
    finding = {
        "check_id": "CIS-AWS-v7.0.0-2.4",
        "check_name": "Ensure no root account access key exists (Automated)",
        "service": "IAM",
        "resource_type": "Account",
        "resource_id": "Root",
        "status": "PASS",
        "reason": "Root account has no access keys"
    }

    try:
        summary = iam_client.get_account_summary()
        access_keys_present = summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)

        if access_keys_present != 0:
            finding["status"] = "FAIL"
            finding["reason"] = "Root account has access keys present"

    except ClientError as e:
        finding["status"] = "ERROR"
        finding["reason"] = str(e)

    return finding
