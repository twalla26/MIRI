from . import cis_2_8_password_length_complexity
from . import cis_2_9_password_reuse
from . import cis_2_11_unused_credentials
from . import cis_2_12_access_key_rotation

def run_all_iam_checks(iam_client):
    findings = []

    # 1. Account Level Checks (계정 전역 설정)
    findings.append(cis_2_8_password_length_complexity.run(iam_client))
    findings.append(cis_2_9_password_reuse.run(iam_client))

    # 2. User Level Checks (유저별 설정)
    paginator = iam_client.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            
            # 2.11 미사용 크리덴셜(45일) 체크
            findings.append(cis_2_11_unused_credentials.run(iam_client, user))
            
            # 2.12 액세스 키 수명(90일) 체크
            findings.append(cis_2_12_access_key_rotation.run(iam_client, user))

    return findings