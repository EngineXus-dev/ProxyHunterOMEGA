"""Evidence-limited network categories. No residential/mobile proof from ISP-name keywords.

The HTTP echo checks prove only observed proxy forwarding, not ownership,
consent, residential access, anonymity, or future uptime.
"""

ISP_UNVERIFIED = 'ISP_NETWORK_UNVERIFIED'
CARRIER_UNVERIFIED = 'CARRIER_NETWORK_UNVERIFIED'
LEGACY_ISP = 'CLEAN_RESIDENTIAL'
LEGACY_CARRIER = 'CLEAN_MOBILE'


def evidence_tag(record):
    """Make legacy cached successes safe to display/export without trusting old tags."""
    tag = record.get('threat_tag', '') if isinstance(record, dict) else ''
    if tag == LEGACY_ISP:
        return ISP_UNVERIFIED
    if tag == LEGACY_CARRIER:
        # Historical "mobile" was triggered by generic words like "wireless";
        # carrier-specific infrastructure, let alone a cellular device, was unproven.
        return ISP_UNVERIFIED
    return tag


def category(record):
    tag = evidence_tag(record)
    if tag == ISP_UNVERIFIED:
        return 'isp'
    if tag == CARRIER_UNVERIFIED:
        return 'carrier'
    if tag in ('DATACENTER', 'SPOOFED_DC', 'DC_METADATA_CONFLICT'):
        return 'datacenter'
    if tag in ('BOTNET_RELAY', 'SDK_MONETIZED', 'IOC_STRING_MATCH', 'PERFORMANCE_FLAGGED', 'OVERSUBSCRIBED'):
        return 'risk'
    return 'other'


def candidate_groups(rows):
    groups = {'isp': [], 'carrier': [], 'other': []}
    for entry in rows:
        cat = category(entry)
        groups[cat if cat in ('isp', 'carrier') else 'other'].append(entry)
    return groups


def distinct_exit_count(rows):
    """Only count observed exit IPs; missing exits are NOT guessed from proxy hosts."""
    import ipaddress
    ips = set()
    for row in rows:
        ip = row.get('exit_ip') if isinstance(row, dict) else None
        try:
            if ip and ipaddress.ip_address(ip).is_global:
                ips.add(ip)
        except ValueError:
            continue
    return len(ips)
