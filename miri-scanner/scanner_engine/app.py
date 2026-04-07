import json
import boto3

from checks.s3 import run_all_s3_checks
from checks.ec2 import run_all_ec2_checks
from checks.iam import run_all_iam_checks

def lambda_handler(event, context):

    body = json.loads(event.get('body'))

    target_account_id = body.get('target_account_id')
    external_id = body.get('external_id')

    if not target_account_id or not external_id:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "target_account_id와 external_id가 필수입니다."})
        }
    
    try:
        # 권한 획득 및 클라이언트 생성
        target_session = get_assumed_session(target_account_id, external_id)

        findings = []

        s3_client = target_session.client('s3')
        s3_findings = run_all_s3_checks(s3_client)
        findings.extend(s3_findings)
        
        ec2_client = target_session.client('ec2')
        ec2_findings = run_all_ec2_checks(ec2_client)
        findings.extend(ec2_findings)

        iam_client = target_session.client('iam')
        iam_findings = run_all_iam_checks(iam_client)
        findings.extend(iam_findings)

        summary = {
            "total_checks_evaluated": len(findings),
            "passed_checks": sum(1 for f in findings if f.get("status") == "PASS"),
            "failed_checks": sum(1 for f in findings if f.get("status") == "FAIL")
        }

        return {
            "statusCode": 200,
            "body": json.dumps({
                "account": target_account_id,
                "summary": summary,
                "findings": findings
            }, default=str)
        }
    
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }

def get_assumed_session(target_account_id, external_id):
    
    sts_client = boto3.client('sts')
    target_role_arn = f"arn:aws:iam::{target_account_id}:role/miri-scanner-role"
    
    assumed_role = sts_client.assume_role(
        RoleArn=target_role_arn,
        RoleSessionName="MIRI_Scan_Session",
        ExternalId=external_id
    )
    
    creds = assumed_role['Credentials']
    return boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )