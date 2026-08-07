#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NCA ECC 2-5: Network Security Management dashboard for Tenable SC."""
from sc_dashboard_lib import *

C = []
def add(name, desc, kind, col, order, defn):
    C.append({"name": name, "desc": desc, "kind": kind, "column": col,
              "order": order, "definition": defn})

# 2-5-3-1 : Exposed services / open ports ----------------------------------
add("NCA ECC 2-5-3-1 | Exposed Network Services",
    "2-5-3-1: Logical/physical segregation and control of network segments. "
    "Detected network services and the hosts exposing them — the attack surface "
    "that segmentation must contain.",
    "matrix", 1, 1,
    # "Service" splits into two distinct meanings:
    #  - Service Enumeration: active + Info -- informational service-detection
    #    plugins (SMB Service Enumeration, LLMNR Detection, ...). This is
    #    inventory/attack-surface, not a finding.
    #  - Service Compliance Findings: compliance + severity 4,3,2,1 (exclude Info,
    #    i.e. FAILED CIS service checks like "Ensure rsync service is not enabled").
    matrix("Detected Network Services",
           ["Service Enumeration (Active)", "Service Compliance Findings",
            "Web Services", "SSL/TLS Services"],
           ["Detections", "Hosts"],
           [("sumid", [flt("pluginName", "Service"), flt("pluginType", "active"), flt("severity", INFO)], C_BLUE),
            ("sumip", [flt("pluginName", "Service"), flt("pluginType", "active"), flt("severity", INFO)], C_BLUE, "cumulative", "ipCount"),
            ("sumid", [flt("pluginName", "Service"), flt("pluginType", "compliance"), flt("severity", "4,3,2,1")], C_AMBER),
            ("sumip", [flt("pluginName", "Service"), flt("pluginType", "compliance"), flt("severity", "4,3,2,1")], C_AMBER, "cumulative", "ipCount"),
            # "Web Application Sitemap" (plugin 98009) cleanly enumerates web apps.
            # The bare "Web" keyword was too noisy (Cisco WebEx, AWS metadata,
            # Web Application Scanner, ...).
            ("sumid", [flt("pluginName", "Web Application Sitemap")], C_PURPLE),
            ("sumip", [flt("pluginName", "Web Application Sitemap")], C_PURPLE, "cumulative", "ipCount"),
            ("sumid", [flt("pluginName", "SSL")], C_NEUTRAL),
            ("sumip", [flt("pluginName", "SSL")], C_NEUTRAL, "cumulative", "ipCount")]))

# 2-5-3-2 : Externally accessible exposure ---------------------------------
# Two rows, both Info-severity host attributes (no severity filter):
#  - broad "external" keyword match (active plugins)
#  - the specific "Accepts external connections" plugin (ID 14)
add("NCA ECC 2-5-3-2 | Externally Accessible Exposure",
    "2-5-3-2: Protection and restriction of external network connections. The "
    "internet-facing footprint that must be minimized and tightly controlled: "
    "externally accessible detections (broad) and assets that accept external "
    "connections (Plugin ID 14).",
    "matrix", 2, 1,
    matrix("Externally Accessible Exposure",
           ["Externally Accessible (Active)", "Accepts External Connections (Plugin 14)"],
           ["Findings", "Hosts"],
           [("sumid", [flt("pluginName", "external"), flt("pluginType", "active")], C_AMBER),
            ("sumip", [flt("pluginName", "external"), flt("pluginType", "active")], C_AMBER, "cumulative", "ipCount"),
            ("sumid", [flt("pluginID", "14")], C_AMBER),
            ("sumip", [flt("pluginID", "14")], C_AMBER, "cumulative", "ipCount")]))

# 2-5-3-3 : Insecure protocols / encryption in transit ---------------------
add("NCA ECC 2-5-3-3 | Insecure Protocols & Weak Encryption",
    "2-5-3-3: Secure network management and encrypted communications. Weak SSL/TLS "
    "and insecure-protocol findings that undermine confidentiality in transit.",
    "matrix", 1, 2,
    matrix("Insecure Transport",
           ["SSL/TLS Weaknesses (High+)", "SSL/TLS Weaknesses (Medium)", "SSL/TLS Weaknesses (Low)"],
           ["Findings", "Hosts"],
           [("sumid", [flt("pluginName", "SSL"), flt("severity", "4,3")], C_RED),
            ("sumip", [flt("pluginName", "SSL"), flt("severity", "4,3")], C_RED, "cumulative", "ipCount"),
            ("sumid", [flt("pluginName", "SSL"), flt("severity", MED)], C_AMBER),
            ("sumip", [flt("pluginName", "SSL"), flt("severity", MED)], C_AMBER, "cumulative", "ipCount"),
            ("sumid", [flt("pluginName", "SSL"), flt("severity", LOW)], C_NEUTRAL),
            ("sumip", [flt("pluginName", "SSL"), flt("severity", LOW)], C_NEUTRAL, "cumulative", "ipCount")]))

# 2-5-3-4 : Perimeter / network device security ----------------------------
add("NCA ECC 2-5-3-4 | Network Device & Perimeter Security",
    "2-5-3-4: Security of network devices (firewalls, routers, switches). "
    "Inventory of detected network devices by type, identified via the Device "
    "Type plugin (ID 54615) whose output reports 'Remote device type : <type>'.",
    "matrix", 2, 2,
    # Plugin 54615 "Device Type" reports the class in its output text. One row per
    # device type, all severities combined (no severity filter). This is a neutral
    # INVENTORY, not a risk view -- use a single neutral color for every row so the
    # coloring can't be misread as severity (a firewall isn't "worse" than a switch).
    matrix("Network Devices by Type",
           ["Firewall", "Router", "Switch", "VPN", "Load Balancer"],
           ["Detections", "Hosts"],
           [("sumid", [flt("pluginID", "54615"), flt("pluginText", "Remote device type : firewall")], C_NEUTRAL),
            ("sumip", [flt("pluginID", "54615"), flt("pluginText", "Remote device type : firewall")], C_NEUTRAL, "cumulative", "ipCount"),
            ("sumid", [flt("pluginID", "54615"), flt("pluginText", "Remote device type : router")], C_NEUTRAL),
            ("sumip", [flt("pluginID", "54615"), flt("pluginText", "Remote device type : router")], C_NEUTRAL, "cumulative", "ipCount"),
            ("sumid", [flt("pluginID", "54615"), flt("pluginText", "Remote device type : switch")], C_NEUTRAL),
            ("sumip", [flt("pluginID", "54615"), flt("pluginText", "Remote device type : switch")], C_NEUTRAL, "cumulative", "ipCount"),
            ("sumid", [flt("pluginID", "54615"), flt("pluginText", "Remote device type : vpn")], C_NEUTRAL),
            ("sumip", [flt("pluginID", "54615"), flt("pluginText", "Remote device type : vpn")], C_NEUTRAL, "cumulative", "ipCount"),
            ("sumid", [flt("pluginID", "54615"), flt("pluginText", "Remote device type : load.balancer")], C_NEUTRAL),
            ("sumip", [flt("pluginID", "54615"), flt("pluginText", "Remote device type : load.balancer")], C_NEUTRAL, "cumulative", "ipCount")]))

# 2-5-3-5 : Top externally exposed hosts -----------------------------------
add("NCA ECC 2-5-3-5 | Top Externally Exposed Hosts",
    "2-5-3-5: Prioritized control of network exposure. Hosts with the most "
    "externally accessible findings — the perimeter remediation priority list.",
    "table", 1, 3,
    table(["ip", "dnsName", "total", "vulnBar"], "sumip",
          [flt("pluginName", "external"), flt("pluginType", "active")], data_points=10))

write_dashboard("NCA ECC 2-5 Network Security.xml",
                "NCA ECC 2-5: Network Security Management",
                "NCA ECC 2-5 — network security: exposed services, external "
                "accessibility, insecure protocols/encryption, network-device "
                "security, and top perimeter-exposed hosts.", C)
print("2-5 done: %d components" % len(C))
