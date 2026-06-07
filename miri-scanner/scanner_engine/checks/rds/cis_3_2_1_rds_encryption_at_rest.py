from botocore.exceptions import ClientError


def _instance_finding(instance):
    db_identifier = instance.get('DBInstanceIdentifier')
    finding = {
        "check_id": "CIS-AWS-v7.0.0-3.2.1",
        "check_name": "Ensure RDS encryption at rest is enabled",
        "service": "RDS",
        "resource_type": "DBInstance",
        "resource_id": db_identifier,
        "status": "PASS",
        "reason": "StorageEncrypted is True"
    }

    if not instance.get('StorageEncrypted'):
        finding["status"] = "FAIL"
        finding["reason"] = "RDS DB instance does not have encryption at rest enabled"

    return finding


def _cluster_finding(cluster):
    cluster_id = cluster.get('DBClusterIdentifier')
    finding = {
        "check_id": "CIS-AWS-v7.0.0-3.2.1",
        "check_name": "Ensure RDS (Aurora) encryption at rest is enabled",
        "service": "RDS",
        "resource_type": "DBCluster",
        "resource_id": cluster_id,
        "status": "PASS",
        "reason": "StorageEncrypted is True"
    }

    if not cluster.get('StorageEncrypted'):
        finding["status"] = "FAIL"
        finding["reason"] = "RDS DB cluster does not have encryption at rest enabled"

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
        # describe_db_clusters may not have a paginator in all botocore versions; handle gracefully
        try:
            clusters_resp = rds_client.describe_db_clusters()
            for cluster in clusters_resp.get('DBClusters', []):
                findings.append(_cluster_finding(cluster))
        except ClientError:
            pass

    except ClientError as e:
        return [{
            "check_id": "CIS-AWS-v7.0.0-3.2.1",
            "check_name": "Ensure RDS encryption at rest is enabled",
            "service": "RDS",
            "resource_type": "Account",
            "resource_id": "RDS",
            "status": "ERROR",
            "reason": str(e)
        }]

    return findings
