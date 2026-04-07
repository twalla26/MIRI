from botocore.exceptions import ClientError
from . import cis_6_3_sg_admin_ports
from . import cis_6_7_imdsv2_enforced
from . import cis_6_1_1_ebs_encryption

def run_all_ec2_checks(ec2_client):
    findings = []

    try:
        # 1. Security Groups 리스트업 (한 번만 호출!)
        paginator_sg = ec2_client.get_paginator('describe_security_groups')
        for page in paginator_sg.paginate():
            for sg in page.get('SecurityGroups', []):
                findings.append(cis_6_3_sg_admin_ports.run(sg))

        # 2. EC2 Instances 리스트업 (한 번만 호출!)
        paginator_inst = ec2_client.get_paginator('describe_instances')
        for page in paginator_inst.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    findings.append(cis_6_7_imdsv2_enforced.run(instance))

        # 3. EBS Volumes 리스트업 (한 번만 호출!)
        paginator_vol = ec2_client.get_paginator('describe_volumes')
        for page in paginator_vol.paginate():
            for volume in page.get('Volumes', []):
                findings.append(cis_6_1_1_ebs_encryption.run(volume))

    except ClientError as e:
        # 권한 오류 등으로 통째로 실패할 경우를 대비한 안전망
        findings.append({
            "check_id": "EC2-GENERAL-ERROR",
            "check_name": "EC2 Resource Data Fetch",
            "service": "EC2",
            "resource_type": "Multiple",
            "resource_id": "FetchError",
            "status": "ERROR",
            "reason": f"API Error: {str(e)}"
        })

    return findings