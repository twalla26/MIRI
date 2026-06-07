def run(trail):
    trail_arn = trail.get('TrailARN')
    finding = {
        "check_id": "CIS-AWS-v7.0.0-4.2",
        "check_name": "Ensure CloudTrail log file validation is enabled",
        "service": "CloudTrail",
        "resource_type": "Trail",
        "resource_id": trail_arn,
        "status": "PASS",
        "reason": "CloudTrail log file validation is enabled"
    }

    if not trail.get('LogFileValidationEnabled'):
        finding["status"] = "FAIL"
        finding["reason"] = "CloudTrail log file validation is disabled"

    return finding
