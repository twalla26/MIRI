from botocore.exceptions import ClientError
from . import cis_4_7_vpc_flow_logging


def run_all_vpc_checks(ec2_client):
    findings = []

    try:
        paginator_vpc = ec2_client.get_paginator('describe_vpcs')
        vpcs = [
            vpc
            for page in paginator_vpc.paginate()
            for vpc in page.get('Vpcs', [])
        ]

        # ACTIVE 상태인 VPC flow log의 resource ID를 한 번에 수집
        paginator_fl = ec2_client.get_paginator('describe_flow_logs')
        vpcs_with_flow_logs = {
            fl['ResourceId']
            for page in paginator_fl.paginate(
                Filters=[{'Name': 'resource-type', 'Values': ['VPC']}]
            )
            for fl in page.get('FlowLogs', [])
            if fl.get('FlowLogStatus') == 'ACTIVE'
        }

        for vpc in vpcs:
            findings.append(cis_4_7_vpc_flow_logging.run(vpc, vpcs_with_flow_logs))

    except ClientError as e:
        findings.append({
            "check_id": "CIS-AWS-v7.0.0-4.7",
            "check_name": "Ensure VPC flow logging is enabled in all VPCs",
            "service": "EC2",
            "resource_type": "VPC",
            "resource_id": "N/A",
            "status": "ERROR",
            "reason": str(e)
        })

    return findings
