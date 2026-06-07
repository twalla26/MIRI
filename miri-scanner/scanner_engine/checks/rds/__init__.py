from . import cis_3_2_1_rds_encryption_at_rest
from . import cis_3_2_3_rds_not_publicly_accessible


def run_all_rds_checks(rds_client):
    findings = []

    # Check 1: RDS encryption at rest (CIS 3.2.1)
    results = cis_3_2_1_rds_encryption_at_rest.run(rds_client)
    if isinstance(results, list):
        findings.extend(results)
    else:
        findings.append(results)

    # Check 2: RDS not publicly accessible (CIS 3.2.3)
    results = cis_3_2_3_rds_not_publicly_accessible.run(rds_client)
    if isinstance(results, list):
        findings.extend(results)
    else:
        findings.append(results)

    return findings
