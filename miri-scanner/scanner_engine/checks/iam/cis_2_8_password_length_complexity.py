from botocore.exceptions import ClientError

def run(iam_client):
    finding = {
        "check_id": "CIS-AWS-v7.0.0-2.8",
        "check_name": "Ensure IAM password policy requires minimum length of 14 or greater (Automated)",
        "service": "IAM",
        "resource_type": "Account",
        "resource_id": "PasswordPolicy",
        "status": "PASS",
        "reason": "Password policy meets length (14+) and complexity requirements"
    }

    try:
        resp = iam_client.get_account_password_policy()
        p = resp.get('PasswordPolicy', {})
        
        reasons = []
        # 길이 및 복잡도 4종 세트 검사
        if p.get('MinimumPasswordLength', 0) < 14: 
            reasons.append("Length < 14")
        if not p.get('RequireUppercaseCharacters', False): 
            reasons.append("No Uppercase")
        if not p.get('RequireLowercaseCharacters', False): 
            reasons.append("No Lowercase")
        if not p.get('RequireNumbers', False): 
            reasons.append("No Numbers")
        if not p.get('RequireSymbols', False): 
            reasons.append("No Symbols")

        if reasons:
            finding["status"] = "FAIL"
            finding["reason"] = f"Missing requirements: {', '.join(reasons)}"

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        
        if error_code == 'NoSuchEntity':
            finding["status"] = "FAIL"
            finding["reason"] = "Custom password policy is not configured"
        else:
            finding["status"] = "ERROR"
            finding["reason"] = str(e)

    return finding