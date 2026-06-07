from botocore.exceptions import ClientError


def run(iam_client, user):
    user_name = user['UserName']
    finding = {
        "check_id": "CIS-AWS-v7.0.0-2.13",
        "check_name": "Ensure IAM users receive permissions only through groups (Automated)",
        "service": "IAM",
        "resource_type": "User",
        "resource_id": user_name,
        "status": "PASS",
        "reason": "User permissions are only granted through IAM groups"
    }

    try:
        direct_policies = []
        paginator = iam_client.get_paginator('list_user_policies')
        for page in paginator.paginate(UserName=user_name):
            direct_policies.extend(page.get('PolicyNames', []))

        attached_policies = []
        paginator = iam_client.get_paginator('list_attached_user_policies')
        for page in paginator.paginate(UserName=user_name):
            for policy in page.get('AttachedPolicies', []):
                attached_policies.append(policy.get('PolicyName', '<unknown>'))

        reasons = []
        if direct_policies:
            reasons.append(f"Inline user policies attached: {', '.join(direct_policies)}")
        if attached_policies:
            reasons.append(f"Managed policies attached directly: {', '.join(attached_policies)}")

        if reasons:
            finding["status"] = "FAIL"
            finding["reason"] = " | ".join(reasons)

    except ClientError as e:
        finding["status"] = "ERROR"
        finding["reason"] = str(e)

    return finding
