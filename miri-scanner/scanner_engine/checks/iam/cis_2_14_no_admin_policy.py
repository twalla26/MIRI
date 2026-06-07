from botocore.exceptions import ClientError
import json


def _check_policy_document(policy_doc, policy_name):
    """
    정책 문서에서 "*:*" (Action: "*", Resource: "*") 조합이 있는지 확인
    """
    if isinstance(policy_doc, str):
        try:
            policy_doc = json.loads(policy_doc)
        except (json.JSONDecodeError, TypeError):
            return None

    statements = policy_doc.get('Statement', [])
    for statement in statements:
        effect = statement.get('Effect', '').upper()
        if effect != 'ALLOW':
            continue

        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]

        # Action과 Resource 모두 "*"인 경우 위험
        if '*' in actions and '*' in resources:
            return True

    return False


def run(iam_client):
    finding = {
        "check_id": "CIS-AWS-v7.0.0-2.14",
        "check_name": "Ensure IAM policies that allow full '*:*' administrative privileges are not attached (Automated)",
        "service": "IAM",
        "resource_type": "Account",
        "resource_id": "Policies",
        "status": "PASS",
        "reason": "No IAM policies with full '*:*' administrative privileges found"
    }

    dangerous_policies = []

    try:
        # Managed Policies만 확인 (성능 최적화)
        paginator = iam_client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for policy in page.get('Policies', []):
                policy_name = policy.get('PolicyName')
                policy_arn = policy.get('Arn')
                
                try:
                    default_version = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy.get('DefaultVersionId')
                    )
                    policy_doc = default_version.get('PolicyVersion', {}).get('Document')
                    if _check_policy_document(policy_doc, policy_name):
                        dangerous_policies.append(f"Managed policy: {policy_name}")
                except ClientError:
                    pass

        if dangerous_policies:
            finding["status"] = "FAIL"
            finding["reason"] = f"Policies with '*:*' found: {', '.join(dangerous_policies)}"

    except ClientError as e:
        finding["status"] = "ERROR"
        finding["reason"] = str(e)

    return finding
