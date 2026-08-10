#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NCA ECC 2-1: Asset Management dashboard for Tenable SC."""
from sc_dashboard_lib import *

C = []
def add(name, desc, kind, col, order, defn):
    C.append({"name": name, "desc": desc, "kind": kind, "column": col,
              "order": order, "definition": defn})

# 2-1-3-1 : Asset inventory & scan coverage --------------------------------
add("NCA ECC 2-1-3-1 | Asset Inventory & Scan Coverage",
    "2-1-3-1: Maintain an accurate, detailed and up-to-date inventory of "
    "information and technology assets. Counts of scanned hosts and detection "
    "coverage across the estate.",
    "matrix", 1, 1,
    matrix("Asset Inventory & Coverage",
           ["All Detected Hosts", "Actively Scanned (30d)", "Not Recently Scanned"],
           ["Hosts"],
           [("sumip", [], C_BLUE, "cumulative", "ipCount"),
            ("sumip", [flt("lastSeen", "0:30")], C_GREEN, "cumulative", "ipCount"),
            ("sumip", [flt("lastSeen", "30:all")], C_AMBER, "cumulative", "ipCount")]))

# 2-1-3-2 : Asset classification by OS -------------------------------------
add("NCA ECC 2-1-3-2 | Asset Classification by Operating System",
    "2-1-3-2: Classify assets and identify their owners. Distribution of hosts "
    "by operating-system family supports ownership and classification.",
    "matrix", 2, 1,
    # Use plugin 11936 (OS Identification) — the same plugin that populates the
    # OS CPE field. Filter by pluginText to match the OS family string found in
    # the plugin output. Actual lab output format is:
    #   "Remote operating system : Microsoft Windows Server 2019 ..."
    #   "Remote operating system : Linux Kernel 4.18.0-... on Oracle Linux ..."
    # So the reliable family substrings are "Microsoft Windows" and "Linux Kernel".
    matrix("Hosts by Operating System",
           ["Microsoft Windows", "Linux / UNIX", "macOS", "Network / Other"],
           ["Hosts"],
           [("sumip", [flt("pluginID", "11936"), flt("pluginText", "Microsoft Windows")],
             C_BLUE, "cumulative", "ipCount"),
            ("sumip", [flt("pluginID", "11936"), flt("pluginText", "Linux Kernel")],
             C_PURPLE, "cumulative", "ipCount"),
            ("sumip", [flt("pluginID", "11936"), flt("pluginText", "Mac OS")],
             C_NEUTRAL, "cumulative", "ipCount"),
            ("sumip", [flt("pluginID", "11936"),
                      flt("pluginText", "Microsoft Windows", "!="),
                      flt("pluginText", "Linux Kernel", "!="),
                      flt("pluginText", "Mac OS", "!=")],
             C_AMBER, "cumulative", "ipCount")]))

# 2-1-3-3 : Detailed asset inventory table ---------------------------------
add("NCA ECC 2-1-3-3 | Detailed Asset Inventory",
    "2-1-3-3: Up-to-date asset register. Hosts with DNS name and detected finding "
    "count, forming a living inventory of the environment.",
    "table", 1, 2,
    table(["ip", "dnsName", "total"], "sumip", [], data_points=100,
          sort_col="total", sort_dir="desc"))

# 2-1-3-4 : Unsupported / end-of-life assets -------------------------------
add("NCA ECC 2-1-3-4 | Unsupported & End-of-Life Assets",
    "2-1-3-4: Governance over the asset lifecycle. Unsupported / end-of-life "
    "products (via 'Unsupported' plugin family) represent lifecycle risk that "
    "must be tracked and retired.",
    "matrix", 2, 2,
    matrix("Unsupported / EOL Products",
           ["Unsupported Software/OS"],
           ["Detections", "Hosts Affected"],
           [("sumid", [flt("pluginName", "Unsupported")], C_RED),
            ("sumip", [flt("pluginName", "Unsupported")], C_RED, "cumulative", "ipCount")]))

# 2-1-3-5 : Installed software / applications ------------------------------
add("NCA ECC 2-1-3-5 | Installed Software Inventory",
    "2-1-3-5: Inventory of software assets. Presence of common application classes "
    "detected across the estate to support software asset management.",
    "matrix", 1, 3,
    matrix("Detected Software Classes",
           ["Web Servers/Apps", "Database (SQL)", "Java Runtime", "SSL/TLS Services"],
           ["Detections", "Hosts"],
           [("sumid", [flt("pluginName", "Web")], C_BLUE),
            ("sumip", [flt("pluginName", "Web")], C_BLUE, "cumulative", "ipCount"),
            ("sumid", [flt("pluginName", "SQL")], C_PURPLE),
            ("sumip", [flt("pluginName", "SQL")], C_PURPLE, "cumulative", "ipCount"),
            ("sumid", [flt("pluginName", "Java")], C_AMBER),
            ("sumip", [flt("pluginName", "Java")], C_AMBER, "cumulative", "ipCount"),
            ("sumid", [flt("pluginName", "SSL")], C_NEUTRAL),
            ("sumip", [flt("pluginName", "SSL")], C_NEUTRAL, "cumulative", "ipCount")]))

write_dashboard("NCA ECC 2-1 Asset Management.xml",
                "NCA ECC 2-1: Asset Management",
                "NCA ECC 2-1 — Cybersecurity Asset Management. Inventory, scan "
                "coverage, OS/software classification, and unsupported-asset "
                "lifecycle risk, mapped to each 2-1 sub-control.", C)
print("2-1 done: %d components" % len(C))
