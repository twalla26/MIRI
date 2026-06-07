def run(instance):
    instance_id = instance['InstanceId']

    # 종료된 인스턴스는 평가 대상 아님
    if instance.get('State', {}).get('Name') == 'terminated':
        return None

    finding = {
        "check_id": "CIS-AWS-v7.0.0-6.7",
        "check_name": "Ensure that EC2 Metadata Service only allows IMDSv2",
        "service": "EC2",
        "resource_type": "Instance",
        "resource_id": instance_id,
        "status": "PASS",
        "reason": "IMDSv2 is enforced (HttpTokens=required)"
    }

    if instance.get('MetadataOptions', {}).get('HttpTokens') != 'required':
        finding["status"] = "FAIL"
        finding["reason"] = "IMDSv2 is not enforced (HttpTokens != required). Vulnerable to SSRF."

    return finding