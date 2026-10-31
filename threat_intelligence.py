#!/usr/bin/env python3
"""Network metadata and best-effort caution flags.

No live BGP verification, TLS-device fingerprinting, device-count estimate,
or confirmed malware attribution is performed. Provider fields and text pattern
matches are hints only; they must not be presented as verified findings.
"""

import re
from ui import cp, dim, P, C, G, R, Y, DIM, B, RST
from constants import (KNOWN_DC_ASNS, DC_ASN_NAMES, BOTNET_C2_IOCS,
                       UPNP_RELAY_SIGNATURES, RESIDENTIAL_KEYWORDS, MOBILE_KEYWORDS, DC_KEYWORDS)

ASN_REGEX = re.compile(r"^AS(\d+)\s*(.*)$", re.IGNORECASE)

def parse_asn(as_field):
    """
    Parses 'as' field from ip-api (e.g., 'AS16509 Amazon.com, Inc.')
    Returns (asn_num: int or None, asn_org: str)
    """
    if not as_field or not isinstance(as_field, str):
        return None, ""
    m = ASN_REGEX.match(as_field.strip())
    if m:
        try:
            return int(m.group(1)), m.group(2).strip()
        except ValueError:
            return None, as_field.strip()
    return None, as_field.strip()

def check_asn_datacenter_mismatch(asn_num, asn_org, isp, org, hosting):
    """Compare provider-supplied ASN and ISP text for possible conflicts.

    This code does NOT perform a live WHOIS or BGP verification and cannot
    detect actual spoofing, only inconsistent metadata labels.
    """
    txt_isp = f"{isp} {org}".lower()
    txt_asn = f"{asn_org}".lower()

    # Is claimed ISP residential or mobile?
    claimed_res = any(k in txt_isp for k in RESIDENTIAL_KEYWORDS)
    claimed_mob = any(k in txt_isp for k in MOBILE_KEYWORDS)

    # Is the actual BGP ASN a known datacenter?
    is_dc_asn_num = asn_num in KNOWN_DC_ASNS if asn_num else False
    is_dc_asn_name = any(k in txt_asn for k in DC_ASN_NAMES)
    is_dc_asn = is_dc_asn_num or is_dc_asn_name or hosting

    if (claimed_res or claimed_mob) and is_dc_asn:
        return {
            "mismatch": True,
            "severity": "HIGH",
            "reason": f"ISP-name keyword conflicts with DC ASN (AS{asn_num or '?'} {asn_org[:25]}); not proof of spoofing",
            "tag": "DC_METADATA_CONFLICT",
        }

    if is_dc_asn and not (claimed_res or claimed_mob):
        return {
            "mismatch": False,
            "severity": "LOW",
            "reason": f"Datacenter-like ASN metadata (AS{asn_num or '?'} {asn_org[:25]})",
            "tag": "DATACENTER",
        }

    return {
        "mismatch": False,
        "severity": "NONE",
        "reason": "No known datacenter mismatch found; access type and authorization unknown",
        "tag": "ACCESS_TYPE_UNKNOWN",
    }

def evaluate_device_heuristics(ip, latency, ptype, port):
    """Flag performance concerns only; port/latency cannot reveal device counts."""
    flags = []
    # Commercial proxy pool common ports
    pool_ports = {8080, 3128, 8888, 1080, 9050, 4444, 20000, 30000, 40000, 50000}
    is_common_farm_port = int(port) in pool_ports if str(port).isdigit() else False

    # Jitter / oversubscription proxy indicator
    if latency > 3.5:
        flags.append("HIGH_CONCURRENCY_LATENCY")
    if is_common_farm_port:
        flags.append("COMMERCIAL_POOL_PORT")

    performance_flagged = len(flags) >= 2 or (latency > 4.5 and is_common_farm_port)
    return {
        "oversubscribed": None,  # Not measurable from latency/port alone.
        "performance_flagged": performance_flagged,
        "device_count_est": None,  # Cannot infer device counts from a port and latency.
        "evidence_note": "Performance/port heuristic only; not evidence of device count or pool size",
        "flags": flags,
    }

def scan_threat_ioc_correlation(ip, isp, org, asn_org):
    """Look for IOC *strings* in metadata only; no host behavior is observed.

    Matches are never proof that an endpoint is infected or malicious.
    """
    combined = f"{ip} {isp} {org} {asn_org}".lower()
    matched_iocs = []

    for name, ioc in BOTNET_C2_IOCS.items():
        for d in ioc.get("domains", []):
            if d.lower() in combined:
                matched_iocs.append({
                    "family": name,
                    "actor": ioc["threat_actor"],
                    "desc": ioc["description"],
                })

    # UPnP RELAY pattern heuristic
    if "relay" in combined and ("asus" in combined or "broadband" in combined):
        matched_iocs.append({
            "family": "upnp_relay",
            "actor": "Jackskid / trees4sale UPnP Router Hijack",
            "desc": UPNP_RELAY_SIGNATURES["signature_note"],
        })

    return matched_iocs

def enrich_proxy_intel(proxy_entry, geo_data):
    """Annotate from third-party provider metadata and unverified heuristics."""
    raw_as = geo_data.get("as", "")
    asn_num, asn_org = parse_asn(raw_as)
    isp = geo_data.get("isp", "Unknown")
    org = geo_data.get("org", "")
    hosting = geo_data.get("hosting", False)

    proxy_str = proxy_entry.get("proxy", "")
    from urllib.parse import urlsplit
    endpoint = urlsplit(proxy_str if "://" in proxy_str else "http://" + proxy_str)
    ip = proxy_entry.get("exit_ip") or endpoint.hostname or ""
    port = str(endpoint.port or 80)
    latency = proxy_entry.get("latency", 2.0)

    # 1. ASN vs WHOIS Mismatch
    mismatch_info = check_asn_datacenter_mismatch(asn_num, asn_org, isp, org, hosting)

    # 2. Device count & Oversubscription Heuristic
    device_info = evaluate_device_heuristics(ip, latency, proxy_entry.get("type", "unknown"), port)

    # 3. Threat IOC correlation
    threat_iocs = scan_threat_ioc_correlation(ip, isp, org, asn_org)

    # 4. Final Threat Classification Tag
    if threat_iocs:
        threat_tag = "IOC_STRING_MATCH"  # An ISP/org substring is NOT proof of malicious infrastructure
    elif mismatch_info["mismatch"]:
        threat_tag = "DC_METADATA_CONFLICT"
    elif hosting or mismatch_info["tag"] == "DATACENTER":
        threat_tag = "DATACENTER"
    elif device_info["performance_flagged"]:
        threat_tag = "PERFORMANCE_FLAGGED"
    elif proxy_entry.get("type") == "carrier_unverified":
        threat_tag = "CARRIER_NETWORK_UNVERIFIED"
    elif proxy_entry.get("type") == "isp_unverified":
        threat_tag = "ISP_NETWORK_UNVERIFIED"
    else:
        threat_tag = "UNKNOWN_COMMUNITY"

    # 5. Adjusted Trust Score Calculation (0-100)
    base_score = proxy_entry.get("score", 50)
    trust_adjustment = 0

    if threat_tag == "BOTNET_RELAY":
        trust_adjustment -= 45
    elif threat_tag == "SDK_MONETIZED":
        trust_adjustment -= 25
    elif threat_tag == "DC_METADATA_CONFLICT":
        trust_adjustment -= 35
    elif threat_tag == "PERFORMANCE_FLAGGED":
        trust_adjustment -= 15

    final_trust_score = max(5, min(100, base_score + trust_adjustment))

    return {
        **proxy_entry,
        "asn": asn_num,
        "asn_org": asn_org,
        "asn_full": raw_as,
        "mismatch_detected": mismatch_info["mismatch"],
        "mismatch_reason": mismatch_info["reason"],
        "device_count_est": device_info["device_count_est"],
        "oversubscribed": None,
        "threat_tag": threat_tag,
        "threat_iocs": threat_iocs,
        "trust_score": final_trust_score,
        "is_clean_residential": False,
        "access_type_verified": False,
        "access_type_evidence": "ISP/ASN names and hosting flag cannot prove residential or cellular last-mile access",
    }

def threat_badge(tag):
    """Returns a styled color badge for threat classification."""
    badges = {
        "ISP_NETWORK_UNVERIFIED": f"{Y}{B}[ISP?]{RST}",
        "CLEAN_RESIDENTIAL": f"{Y}{B}[LEGACY-ISP?]{RST}",
        "CARRIER_NETWORK_UNVERIFIED": f"{C}{B}[CARRIER?]{RST}",
        "CLEAN_MOBILE":      f"{C}{B}[LEGACY-CARRIER?]{RST}",
        "BOTNET_RELAY":     f"{R}{B}[BOTNET-C2]{RST}",
        "SDK_MONETIZED":    f"{Y}{B}[SDK-EXIT]{RST}",
        "DC_METADATA_CONFLICT": f"{Y}{B}[DC-META?]{RST}",
        "SPOOFED_DC":       f"{Y}{B}[LEGACY-DC?]{RST}",
        "PERFORMANCE_FLAGGED": f"{Y}{B}[PERF?]{RST}",
        "IOC_STRING_MATCH": f"{Y}{B}[IOC-TEXT?]{RST}",
        "OVERSUBSCRIBED":   f"{Y}{B}[LEGACY-PERF?]{RST}",
        "DATACENTER":       f"{DIM}[DATACNTR]{RST}",
        "UNKNOWN_COMMUNITY":f"{DIM}[COMMUNITY]{RST}",
    }
    return badges.get(tag, f"{DIM}[{tag[:9]}]{RST}")
