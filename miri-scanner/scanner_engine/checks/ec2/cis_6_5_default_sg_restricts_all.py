def run(sg):
    sg_id = sg['GroupId']
    finding = {
        "check_id": "CIS-AWS-v7.0.0-6.5",
        "check_name": "Ensure the default security group of every VPC restricts all traffic",
        "service": "EC2",
        "resource_type": "SecurityGroup",
        "resource_id": sg_id,
        "status": "PASS",
        "reason": "Not a default security group"
    }

    if sg.get('GroupName') != 'default':
        return finding

    reasons = []
    if sg.get('IpPermissions'):
        reasons.append("has inbound rules")
    if sg.get('IpPermissionsEgress'):
        reasons.append("has outbound rules")

    if reasons:
        finding["status"] = "FAIL"
        finding["reason"] = f"Default security group {sg_id} {' and '.join(reasons)}"
    else:
        finding["reason"] = f"Default security group {sg_id} has no rules"

    return finding
