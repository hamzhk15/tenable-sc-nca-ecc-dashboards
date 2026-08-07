#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NCA ECC 2-3: Information System & Processing Facilities Protection."""
from sc_dashboard_lib import *

C = []
def add(name, desc, kind, col, order, defn):
    C.append({"name": name, "desc": desc, "kind": kind, "column": col,
              "order": order, "definition": defn})

# 2-3-3-1 : Anti-malware protection posture / hygiene ----------------------
# NOTE: Tenable's credentialed plugins report anti-malware *posture and hygiene*
# (e.g. stale AV signatures, missing MSRT updates) -- NOT confirmed live
# infections. Labeling these as "detections" would overstate the risk, so the
# rows describe what the data actually represents.
add("NCA ECC 2-3-3-1 | Anti-Malware Protection & Hygiene",
    "2-3-3-1: Advanced, up-to-date protection against malware and viruses on "
    "servers and workstations. Measures the health of anti-malware controls -- "
    "out-of-date antivirus signatures/configuration and missing malicious-software "
    "tool updates. These indicate protection GAPS, not confirmed infections.",
    "matrix", 1, 1,
    matrix("Anti-Malware Protection Posture",
           ["Antivirus Hygiene (signatures / config)", "Malicious-Software Tool Related"],
           ["Findings", "Hosts Affected"],
           # Severity 4,3,2,1 excludes Info-only plugins (e.g. "Antivirus Software
           # Check", "WMI Antivirus Enumeration"). pluginType=active excludes
           # compliance-audit checks whose names contain "virus"/"malicious".
           [("sumid", [flt("pluginName", "Virus"), flt("severity", "4,3,2,1"), flt("pluginType", "active")], C_AMBER),
            ("sumip", [flt("pluginName", "Virus"), flt("severity", "4,3,2,1"), flt("pluginType", "active")], C_AMBER, "cumulative", "ipCount"),
            ("sumid", [flt("pluginName", "Malicious"), flt("severity", "4,3,2,1"), flt("pluginType", "active")], C_AMBER),
            ("sumip", [flt("pluginName", "Malicious"), flt("severity", "4,3,2,1"), flt("pluginType", "active")], C_AMBER, "cumulative", "ipCount")]))

# 2-3-3-2 : Patch / security update management -----------------------------
add("NCA ECC 2-3-3-2 | Security Patch Posture",
    "2-3-3-2: Secure management and protection through timely patching. "
    "Outstanding patch-related findings by severity across the environment.",
    "matrix", 2, 1,
    matrix("Missing Patches by Severity",
           ["Critical", "High", "Medium"],
           ["Findings", "Hosts Affected"],
           [("sumid", [flt("severity", CRIT)], C_RED),
            ("sumip", [flt("severity", CRIT)], C_RED, "cumulative", "ipCount"),
            ("sumid", [flt("severity", HIGH)], C_AMBER),
            ("sumip", [flt("severity", HIGH)], C_AMBER, "cumulative", "ipCount"),
            ("sumid", [flt("severity", MED)], C_NEUTRAL),
            ("sumip", [flt("severity", MED)], C_NEUTRAL, "cumulative", "ipCount")]))

# 2-3-3-3 : Secure configuration / hardening -------------------------------
add("NCA ECC 2-3-3-3 | Secure Configuration & Hardening",
    "2-3-3-3: Secure configuration and hardening per leading practice (e.g. CIS). "
    "Compliance-audit results (populates once CIS/DISA audit policies are run). "
    "Result status maps to severity: Failed/Not Compliant = High, Manual Check "
    "Required = Medium, Passed = Info.",
    "matrix", 1, 2,
    matrix("Configuration Compliance (audit results)",
           # Compliance severity encodes result status:
           #   High = Failed/Not Compliant, Medium = Manual review, Info = Passed.
           ["Failed (Not Compliant)", "Manual Check Required", "Passed"],
           ["Checks"],
           # Compliance/config-audit data lives in a normal 'vuln' query filtered by
           # pluginType=compliance (the technique used in the ISO 27001 dashboard).
           [("sumid", [flt("pluginType", "compliance"), flt("severity", HIGH)], C_RED),
            ("sumid", [flt("pluginType", "compliance"), flt("severity", MED)],  C_AMBER),
            ("sumid", [flt("pluginType", "compliance"), flt("severity", INFO)], C_GREEN)]))

# 2-3-3-4 : Default / weak credentials -------------------------------------
add("NCA ECC 2-3-3-4 | Default & Weak Credentials",
    "2-3-3-4: Change default configurations/credentials. Detections of default or "
    "weak credentials that expose systems to trivial compromise.",
    "matrix", 2, 2,
    # The bare "Default" keyword is too broad -- it matches SCA/compliance checks
    # like "SCA: security update for ...-default". Match the specific phrases the
    # real credential plugins use instead: "Default Credentials" and "Default
    # Password". pluginName is a substring "contains" match with NO OR operator,
    # so each phrase gets its own row rather than one combined filter.
    # severity=4,3,2,1 excludes Info -- for compliance plugins Info means PASSED
    # (e.g. "CIS Control 4 (4.2) Change Default Passwords" is Info/passed and
    # must not be counted as a finding). Real credential detections are Low+.
    matrix("Default / Weak Credential Findings",
           ["Default Credentials", "Default Password"],
           ["Detections", "Hosts Affected"],
           [("sumid", [flt("pluginName", "Default Credentials"), flt("severity", "4,3,2,1")], C_RED),
            ("sumip", [flt("pluginName", "Default Credentials"), flt("severity", "4,3,2,1")], C_RED, "cumulative", "ipCount"),
            ("sumid", [flt("pluginName", "Default Password"), flt("severity", "4,3,2,1")], C_RED),
            ("sumip", [flt("pluginName", "Default Password"), flt("severity", "4,3,2,1")], C_RED, "cumulative", "ipCount")]))

# 2-3-3-5 : Top affected hosts (remediation target) ------------------------
add("NCA ECC 2-3-3-5 | Top Hosts Requiring Protection",
    "2-3-3-5: Prioritized protection of facilities/systems. Hosts carrying the "
    "highest weighted finding load — the priority queue for hardening effort.",
    "table", 1, 3,
    table(["ip", "dnsName", "total", "vulnBar"], "sumip",
          [flt("severity", "4,3,2")], data_points=10))

write_dashboard("NCA ECC 2-3 Systems Protection.xml",
                "NCA ECC 2-3: Information System & Facilities Protection",
                "NCA ECC 2-3 — protection of information systems and processing "
                "facilities: malware defense, patch posture, secure configuration/"
                "hardening, default-credential exposure, and hardening priorities.", C)
print("2-3 done: %d components" % len(C))
