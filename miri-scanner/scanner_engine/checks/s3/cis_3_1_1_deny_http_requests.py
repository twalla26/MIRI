from botocore.exceptions import ClientError
import json


def _is_https_only_bucket_policy(policy_doc, bucket_name):
    if isinstance(policy_doc, str):
        try:
            policy_doc = json.loads(policy_doc)
        except (json.JSONDecodeError, TypeError):
            return False

    statements = policy_doc.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    bucket_objects_arn = f"{bucket_arn}/*"

    for statement in statements:
        if statement.get('Effect', '').upper() != 'DENY':
            continue

        condition = statement.get('Condition', {})
        if not condition:
            continue

        bool_condition = condition.get('Bool') or condition.get('BoolIfExists')
        if not bool_condition:
            continue

        secure_transport = bool_condition.get('aws:SecureTransport')
        if secure_transport not in [False, 'false', 'False']:
            continue

        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]

        resources = statement.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]

        action_matches = any(action in ['s3:*', '*'] or action.startswith('s3:') for action in actions)
        resource_matches = any(resource == bucket_arn or resource == bucket_objects_arn or resource == '*' for resource in resources)

        if action_matches and resource_matches:
            return True

    return False


def run(s3_client, bucket_name):
    finding = {
        "check_id": "CIS-AWS-v7.0.0-3.1.1",
        "check_name": "Ensure S3 Bucket Policy denies HTTP requests",
        "service": "S3",
        "resource_type": "Bucket",
        "resource_id": bucket_name,
        "status": "PASS",
        "reason": "Bucket policy denies insecure HTTP requests"
    }

    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = response.get('Policy')

        if not policy or not _is_https_only_bucket_policy(policy, bucket_name):
            finding["status"] = "FAIL"
            finding["reason"] = "Bucket policy does not deny insecure HTTP requests"

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'NoSuchBucketPolicy':
            finding["status"] = "FAIL"
            finding["reason"] = "Bucket policy is not configured"
        else:
            finding["status"] = "ERROR"
            finding["reason"] = str(e)

    return finding
