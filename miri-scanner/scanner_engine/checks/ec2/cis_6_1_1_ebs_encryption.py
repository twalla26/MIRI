def run(volume):
    volume_id = volume['VolumeId']
    finding = {
        "check_id": "CIS-5.2",
        "check_name": "EBS Volume Encryption",
        "service": "EC2",
        "resource_type": "Volume",
        "resource_id": volume_id,
        "status": "PASS",
        "reason": "Volume is encrypted"
    }

    is_encrypted = volume.get('Encrypted', False)
    
    if not is_encrypted:
        finding["status"] = "FAIL"
        finding["reason"] = "Volume is unencrypted (Data at rest is vulnerable)"

    return finding