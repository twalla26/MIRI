def run(vpc, vpcs_with_flow_logs):
    vpc_id = vpc['VpcId']
    finding = {
        "check_id": "CIS-AWS-v7.0.0-4.7",
        "check_name": "Ensure VPC flow logging is enabled in all VPCs",
        "service": "EC2",
        "resource_type": "VPC",
        "resource_id": vpc_id,
        "status": "PASS",
        "reason": "VPC flow logging is enabled"
    }

    if vpc_id not in vpcs_with_flow_logs:
        finding["status"] = "FAIL"
        finding["reason"] = "VPC flow logging is not enabled"

    return finding
