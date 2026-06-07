from botocore.exceptions import ClientError
from . import cis_4_2_log_file_validation


def run_all_cloudtrail_checks(cloudtrail_client):
    findings = []

    try:
        # includeShadowTrails=False: 현재 리전 트레일만 평가 (다른 리전 shadow trail 중복 제외)
        trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get('trailList', [])

        if not trails:
            findings.append({
                "check_id": "CIS-AWS-v7.0.0-4.2",
                "check_name": "Ensure CloudTrail log file validation is enabled",
                "service": "CloudTrail",
                "resource_type": "Trail",
                "resource_id": "N/A",
                "status": "FAIL",
                "reason": "No CloudTrail trails found in this region"
            })
            return findings

        for trail in trails:
            findings.append(cis_4_2_log_file_validation.run(trail))

    except ClientError as e:
        findings.append({
            "check_id": "CIS-AWS-v7.0.0-4.2",
            "check_name": "Ensure CloudTrail log file validation is enabled",
            "service": "CloudTrail",
            "resource_type": "Trail",
            "resource_id": "N/A",
            "status": "ERROR",
            "reason": str(e)
        })

    return findings
