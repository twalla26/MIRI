import json
import boto3
import os
from datetime import datetime

from checks.s3 import run_all_s3_checks
from checks.ec2 import run_all_ec2_checks
from checks.iam import run_all_iam_checks
from checks.rds import run_all_rds_checks
from checks.cloudtrail import run_all_cloudtrail_checks
from checks.vpc import run_all_vpc_checks
from checks.isms_p_mapping import enrich

DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME", "")

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table("miri")

def lambda_handler(event, context):

    body = json.loads(event.get('body'))
    user_id = body.get('user_id')

    if not user_id:
        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": "user_id가 필요합니다."
            })
        }
    
    try:
        user_info = table.get_item(
            Key={'PK': f'USER#{user_id}',
                 'SK': 'METADATA'}
        ).get('Item')
    
        if not user_info:
            return {
                "statusCode": 403,
                "body": json.dumps({
                    "error": "등록되지 않은 사용자입니다."
                })
            }

        target_account_id = user_info.get('AccountID')
        external_id = user_info.get('ExternalID')
    
        # 권한 획득 및 클라이언트 생성
        target_session = get_assumed_session(target_account_id, external_id)

        findings = []

        iam_client = target_session.client('iam')
        iam_findings = run_all_iam_checks(iam_client)
        findings.extend(iam_findings)

        s3_client = target_session.client('s3')
        s3_findings = run_all_s3_checks(s3_client)
        findings.extend(s3_findings)
        
        ec2_client = target_session.client('ec2')
        ec2_findings = run_all_ec2_checks(ec2_client)
        findings.extend(ec2_findings)

        # RDS checks
        rds_client = target_session.client('rds')
        rds_findings = run_all_rds_checks(rds_client)
        findings.extend(rds_findings)

        # CloudTrail checks
        cloudtrail_client = target_session.client('cloudtrail')
        cloudtrail_findings = run_all_cloudtrail_checks(cloudtrail_client)
        findings.extend(cloudtrail_findings)

        # VPC checks (ec2_client 재사용)
        vpc_findings = run_all_vpc_checks(ec2_client)
        findings.extend(vpc_findings)

        findings = enrich(findings)

        total = len(findings)
        passed = sum(1 for f in findings if f.get("status") == "PASS")
        failed = sum(1 for f in findings if f.get("status") == "FAIL")

        summary = {
            "total_checks_evaluated": total,
            "passed_checks": passed,
            "failed_checks": failed,
            "score": int((passed / total) * 100) if total > 0 else 0
        }

        timestamp = datetime.now().isoformat()
        expires_at = int(datetime.now().timestamp()) + (90 * 24 * 60 * 60)

        table.put_item(
            Item={
                'PK': f'USER#{user_id}',
                'SK': f'SCAN#{timestamp}',
                'AccountID': target_account_id,
                'Summary': summary,
                'Findings': findings,
                'ExpiresAt': expires_at
            }
        )

        return {
            "statusCode": 200,
            "body": json.dumps({
                "account": target_account_id,
                "scan_id": f'SCAN#{timestamp}'
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