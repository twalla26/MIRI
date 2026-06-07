from botocore.exceptions import ClientError
from . import cis_6_3_sg_admin_ports
from . import cis_6_4_sg_admin_ports_ipv6
from . import cis_6_5_default_sg_restricts_all
from . import cis_6_7_imdsv2_enforced

def run_all_ec2_checks(ec2_client):
    findings = []

    try:
        # 1. Security Groups 리스트업 (한 번만 호출!)
        paginator_sg = ec2_client.get_paginator('describe_security_groups')
        for page in paginator_sg.paginate():
            for sg in page.get('SecurityGroups', []):
                findings.append(cis_6_3_sg_admin_ports.run(sg))
                findings.append(cis_6_4_sg_admin_ports_ipv6.run(sg))
                findings.append(cis_6_5_default_sg_restricts_all.run(sg))

        # 2. EC2 Instances 리스트업 (한 번만 호출!)
        paginator_inst = ec2_client.get_paginator('describe_instances')
        for page in paginator_inst.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    result = cis_6_7_imdsv2_enforced.run(instance)
                    if result is not None:
                        findings.append(result)

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