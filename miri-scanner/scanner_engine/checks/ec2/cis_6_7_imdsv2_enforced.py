def run(instance):
    instance_id = instance['InstanceId']
    finding = {
        "check_id": "CIS-5.1",
        "check_name": "EC2 Instance IMDSv2 Enforced",
        "service": "EC2",
        "resource_type": "Instance",
        "resource_id": instance_id,
        "status": "PASS",
        "reason": "IMDSv2 is enforced (HttpTokens=required)"
    }

    # 종료(Terminated)된 인스턴스는 스캔 패스
    if instance.get('State', {}).get('Name') == 'terminated':
        finding["status"] = "PASS"
        finding["reason"] = "Instance is terminated"
        return finding

    metadata_options = instance.get('MetadataOptions', {})
    
    # HttpTokens가 'required'여야 IMDSv2가 강제된 것
    if metadata_options.get('HttpTokens') != 'required':
        finding["status"] = "FAIL"
        finding["reason"] = "IMDSv2 is not enforced. Vulnerable to SSRF."

    return finding