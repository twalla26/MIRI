from . import cis_3_1_4_bpa

def run_all_s3_checks(s3_client):
    findings = []
    
    # 1. AWS API 호출 최소화: 버킷 리스트는 여기서 딱 한 번만 가져옵니다!
    buckets_resp = s3_client.list_buckets()
    bucket_names = [b['Name'] for b in buckets_resp.get('Buckets', [])]

    # 2. 각 버킷마다 모든 체크(룰)를 실행합니다.
    for bucket_name in bucket_names:
        
        # Check 1: BPA 검사
        finding_bpa = cis_3_1_4_bpa.run(s3_client, bucket_name)
        findings.append(finding_bpa)

    return findings