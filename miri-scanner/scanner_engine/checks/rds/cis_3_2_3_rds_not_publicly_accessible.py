from botocore.exceptions import ClientError


def _instance_finding(instance):
    db_identifier = instance.get('DBInstanceIdentifier')
    finding = {
        "check_id": "CIS-AWS-v7.0.0-3.2.3",
        "check_name": "Ensure that RDS instances are not publicly accessible",
        "service": "RDS",
        "resource_type": "DBInstance",
        "resource_id": db_identifier,
        "status": "PASS",
        "reason": "RDS DB instance is not publicly accessible"
    }

    if instance.get('PubliclyAccessible'):
        finding["status"] = "FAIL"
        finding["reason"] = "RDS DB instance is publicly accessible"

    return finding


def _cluster_finding(cluster):
    cluster_id = cluster.get('DBClusterIdentifier')
    finding = {
        "check_id": "CIS-AWS-v7.0.0-3.2.3",
        "check_name": "Ensure that RDS (Aurora) clusters are not publicly accessible",
        "service": "RDS",
        "resource_type": "DBCluster",
        "resource_id": cluster_id,
        "status": "PASS",
        "reason": "RDS DB cluster is not publicly accessible"
    }

    if cluster.get('PubliclyAccessible'):
        finding["status"] = "FAIL"
        finding["reason"] = "RDS DB cluster is publicly accessible"

    return finding


def run(rds_client):
    findings = []

    try:
        # DB Instances
        paginator = rds_client.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for instance in page.get('DBInstances', []):
                findings.append(_instance_finding(instance))

        # DB Clusters (Aurora)
        try:
            clusters_resp = rds_client.describe_db_clusters()
            for cluster in clusters_resp.get('DBClusters', []):
                findings.append(_cluster_finding(cluster))
        except ClientError:
            pass

    except ClientError as e:
        return [{
            "check_id": "CIS-AWS-v7.0.0-3.2.3",
            "check_name": "Ensure that RDS instances are not publicly accessible",
            "service": "RDS",
            "resource_type": "Account",
            "resource_id": "RDS",
            "status": "ERROR",
            "reason": str(e)
        }]

    return findings
