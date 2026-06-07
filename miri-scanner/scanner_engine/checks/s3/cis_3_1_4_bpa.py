from botocore.exceptions import ClientError

def run(s3_client, bucket_name):
    """
    [CIS 3.1.4] S3 버킷에 모든 퍼블릭 액세스 차단(BPA)이 설정되어 있는지 점검합니다.
    """
    finding = {
        "check_id": "CIS-AWS-v7.0.0-3.1.4",
        "check_name": "S3 Bucket Public Access Block",
        "service": "S3",
        "resource_type": "Bucket",
        "resource_id": bucket_name,
        "status": "PASS",
        "reason": "BPA is correctly configured"
    }

    try:
        bpa = s3_client.get_public_access_block(Bucket=bucket_name)
        bpa_config = bpa['PublicAccessBlockConfiguration']
        
        # 4가지 설정이 모두 True여야 PASS
        if not all(bpa_config.values()):
            finding["status"] = "FAIL"
            finding["reason"] = "BPA is partially disabled"
            
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == 'NoSuchPublicAccessBlockConfiguration':
            finding["status"] = "FAIL"
            finding["reason"] = "BPA is not configured (Vulnerable)"
        else:
            finding["status"] = "ERROR"
            finding["reason"] = str(e)

    return finding