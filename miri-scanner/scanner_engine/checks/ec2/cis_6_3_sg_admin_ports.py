def run(sg):
    sg_id = sg['GroupId']
    finding = {
        "check_id": "CIS-6.3",
        "check_name": "Security Group Admin Ports (SSH/RDP) Anywhere",
        "service": "EC2",
        "resource_type": "SecurityGroup",
        "resource_id": sg_id,
        "status": "PASS",
        "reason": "Admin ports are securely restricted"
    }

    reasons = []
    for rule in sg.get('IpPermissions', []):
        # 0.0.0.0/0 (IPv4) 또는 ::/0 (IPv6) 허용 여부
        is_anywhere = any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', []))
        is_anywhere_v6 = any(ipv6.get('CidrIpv6') == '::/0' for ipv6 in rule.get('Ipv6Ranges', []))

        if is_anywhere or is_anywhere_v6:
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            ip_protocol = rule.get('IpProtocol')

            # 모든 트래픽 허용('-1')이거나 22, 3389 포트가 포함된 경우
            if ip_protocol == '-1':
                reasons.append("All Traffic allowed from Anywhere")
            elif from_port is not None and to_port is not None:
                if (from_port <= 22 <= to_port):
                    reasons.append("SSH(22) allowed from Anywhere")
                if (from_port <= 3389 <= to_port):
                    reasons.append("RDP(3389) allowed from Anywhere")

    if reasons:
        finding["status"] = "FAIL"
        finding["reason"] = " | ".join(reasons)

    return finding