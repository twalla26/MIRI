def run(sg):
    sg_id = sg['GroupId']
    finding = {
        "check_id": "CIS-AWS-v7.0.0-6.4",
        "check_name": "Ensure no security groups allow ingress from ::/0 to admin ports (SSH/RDP)",
        "service": "EC2",
        "resource_type": "SecurityGroup",
        "resource_id": sg_id,
        "status": "PASS",
        "reason": "Admin ports are not exposed to ::/0 (IPv6)"
    }

    reasons = []
    for rule in sg.get('IpPermissions', []):
        is_anywhere_v6 = any(ipv6.get('CidrIpv6') == '::/0' for ipv6 in rule.get('Ipv6Ranges', []))

        if not is_anywhere_v6:
            continue

        ip_protocol = rule.get('IpProtocol')
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')

        if ip_protocol == '-1':
            reasons.append("All traffic allowed from ::/0 (covers SSH/RDP)")
        elif ip_protocol == 'tcp' and from_port is not None and to_port is not None:
            if from_port <= 22 <= to_port:
                reasons.append("SSH (port 22) allowed from ::/0")
            if from_port <= 3389 <= to_port:
                reasons.append("RDP (port 3389) allowed from ::/0")

    if reasons:
        finding["status"] = "FAIL"
        finding["reason"] = " | ".join(reasons)

    return finding
