#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generator for a Tenable Security Center dashboard XML mapped to
Saudi NCA ECC control 2-10 (Vulnerability Management).

Rebuilt for a VM operations audience with:
  * Explicit 1:1 mapping to each ECC 2-10 sub-control (+ 2-10-4 review)
  * VPR + CVSS severity models side-by-side
  * Standard remediation SLAs: Critical 7d / High 30d / Medium 60d / Low 90d

Definitions are emitted as base64(PHP-serialized) exactly as SC expects.
"""
import base64
from xml.sax.saxutils import escape

# ---------------------------------------------------------------------------
# PHP serialization (matches Tenable SC's format; byte-length prefixed)
# ---------------------------------------------------------------------------
def ser(obj):
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return 's:%d:"%s";' % (len(b), obj)
    if isinstance(obj, dict):
        out = "a:%d:{" % len(obj)
        for k, v in obj.items():
            out += ser(k) + ser(v)
        return out + "}"
    if isinstance(obj, list):
        out = "a:%d:{" % len(obj)
        for i, v in enumerate(obj):
            out += "i:%d;" % i + ser(v)
        return out + "}"
    raise TypeError(type(obj))

def b64(obj):
    return base64.b64encode(ser(obj).encode("utf-8")).decode("ascii")

# ---------------------------------------------------------------------------
# Query / cell builders
# ---------------------------------------------------------------------------
_qc = [0]
def qname():
    _qc[0] += 1
    return "_1750000000.%04d_%d_1_1" % (_qc[0], _qc[0])

def flt(name, value, op="="):
    return {"filterName": name, "operator": op, "value": value}

def datasource(tool, filters, source="cumulative", result="single",
               sort_col="", sort_dir="", qname_val=None):
    # SC names queries per-component: matrix cells "_<ts>_<cellSeq>_1_1",
    # tables "_<ts>_table_1_1". Match that so widgets don't hang on first load.
    return {
        "querySourceType": source, "querySourceID": "", "querySourceView": "all",
        "sortColumn": sort_col, "sortDirection": sort_dir, "iteratorID": "-1",
        "context": "dashboard", "resultStyle": result,
        "query": {
            "name": qname_val if qname_val is not None else qname(),
            "description": "", "tool": tool, "type": "vuln",
            "tags": "", "context": "dashboard", "browseColumns": "",
            "browseSortColumn": "", "browseSortDirection": "ASC",
            "ownerGID": "0", "targetGID": "-1",
            "filters": filters, "groups": [],
        },
    }

def cell(seq, tool, filters, colors, source="cumulative", out_text="vulnCount"):
    return {
        "sequence": str(seq),
        "dataSource": datasource(tool, filters, source=source,
                                 qname_val="_1750000000.%04d_%d_1_1" % (seq, seq)),
        "baseDataSource": [],
        "conditionals": [{
            "conditionalName": "default", "conditionalOperator": "=",
            "conditionalValue": "", "outputType": "textCount",
            "outputColors": colors, "outputText": out_text,
        }],
    }

# color scheme -- format is foreground:background (hex, no '#').
# Values taken from the original SC dashboard's proven-rendering palette so
# text always contrasts with its cell background.
C_NEUTRAL = "000000:ffffff"   # black text on white (SC default)
C_GREEN   = "ffffff:79ab3d"   # white text on green
C_RED     = "ffffff:dd4b50"   # white text on red
C_AMBER   = "000000:f8c851"   # black text on amber
C_ORANGE  = "000000:f18c43"   # black text on orange (escalation tier)
C_BLUE    = "ffffff:2c87d6"   # white text on blue

def matrix(title, row_labels, col_labels, cell_specs):
    """cell_specs: list (row-major) of (tool, filters, colors, source, out_text)."""
    rows, cols = len(row_labels), len(col_labels)
    cells = []
    seq = 1
    for spec in cell_specs:
        tool, filters, colors = spec[0], spec[1], spec[2]
        source = spec[3] if len(spec) > 3 else "cumulative"
        out_text = spec[4] if len(spec) > 4 else "vulnCount"
        cells.append(cell(seq, tool, filters, colors, source, out_text))
        seq += 1
    clusters = [{"id": str(2000 + i), "strips": str(i + 1),
                 "schedule": "FREQ=DAILY;INTERVAL=1"} for i in range(rows)]
    return {
        "styleID": "-1", "cells": cells, "rows": str(rows), "columns": str(cols),
        "title": title, "stripType": "column",
        "rowLabels":    [{"sequence": str(i + 1), "text": t} for i, t in enumerate(row_labels)],
        "columnLabels": [{"sequence": str(i + 1), "text": t} for i, t in enumerate(col_labels)],
        "clusters": clusters,
    }

def table(columns, tool, filters, data_points=10, sort_col="score", sort_dir="desc"):
    return {
        "styleID": "-1",
        "columns": [{"name": c} for c in columns],
        "dataPoints": str(data_points),
        "displayDataPoints": str(data_points),
        "dataSource": datasource(tool, filters, result="list",
                                 sort_col=sort_col, sort_dir=sort_dir,
                                 qname_val="_1750000000.0001_table_1_1"),
    }

# severity codes
CRIT, HIGH, MED, LOW = "4", "3", "2", "1"
# VPR ranges
VPR = {"crit": "9-10", "high": "7-8.9", "med": "4-6.9", "low": "0.1-3.9"}

# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------
components = []  # (name, description, kind, column, order, definition_obj)

def add(name, desc, kind, column, order, definition):
    components.append((name, desc, kind, column, order, definition))

# --- 2-10-1 & 2-10-2 : SLA Compliance -------------------------------------
sla = [("Critical", CRIT, "7"), ("High", HIGH, "30"),
       ("Medium", MED, "60"), ("Low", LOW, "90")]
specs = []
for _, sev, days in sla:
    specs.append(("sumid", [flt("severity", sev)], C_NEUTRAL))                       # total unmitigated
    specs.append(("sumid", [flt("severity", sev), flt("firstSeen", "0:%s" % days)], C_GREEN))   # within SLA
    specs.append(("sumid", [flt("severity", sev), flt("firstSeen", "%s:all" % days)], C_RED))   # overdue
add("NCA ECC 2-10-1 & 2-10-2 | Remediation SLA Compliance",
    "2-10-1: VM cybersecurity requirements defined, documented and approved. "
    "2-10-2: those requirements implemented. Unmitigated vulnerabilities measured "
    "against remediation SLAs (Critical 7d / High 30d / Medium 60d / Low 90d).",
    "matrix", 1, 1,
    matrix("Remediation SLA Compliance (by CVSS severity)",
           ["Critical (7 Days)", "High (30 Days)", "Medium (60 Days)", "Low (90 Days)"],
           ["Total Unmitigated", "Within SLA", "Overdue"], specs))

# --- 2-10-3-1 : Periodic assessment cadence -------------------------------
specs = []
for window in ["0:7", "0:30", "0:90"]:
    specs.append(("sumid", [flt("firstSeen", window), flt("vprScore", VPR["crit"])], C_RED))
    specs.append(("sumid", [flt("firstSeen", window), flt("vprScore", VPR["high"])], C_AMBER))
    specs.append(("sumip", [flt("firstSeen", window)], C_BLUE, "cumulative", "ipCount"))
add("NCA ECC 2-10-3-1 | Periodic Vulnerability Assessment Cadence",
    "2-10-3-1: Periodic vulnerability assessments. Newly discovered findings by "
    "detection window demonstrate ongoing assessment coverage and cadence.",
    "matrix", 2, 1,
    matrix("Newly Discovered Findings (assessment cadence)",
           ["Discovered ≤ 7 Days", "Discovered ≤ 30 Days", "Discovered ≤ 90 Days"],
           ["Critical (VPR)", "High (VPR)", "Hosts Affected"], specs))

# --- 2-10-3-1 : Scan coverage (assets scanned by window) ------------------
# Plugin 19506 "Nessus Scan Information" is present on every successfully
# scanned host, so counting hosts (ipCount) with it by lastSeen window shows
# how many assets were actually scanned in each period -- i.e. coverage.
specs = []
for window in ["0:7", "0:30", "0:90"]:
    specs.append(("sumip", [flt("pluginID", "19506"), flt("lastSeen", window)], C_GREEN, "cumulative", "ipCount"))
add("NCA ECC 2-10-3-1 | Scan Coverage (Assets Scanned) — Higher is Better",
    "2-10-3-1: Periodic vulnerability assessments. Number of assets actually "
    "scanned within each window (via Plugin ID 19506, present on every scanned "
    "host) -- evidences assessment coverage and cadence across the estate. NOTE: "
    "unlike the risk widgets on this dashboard, a HIGHER number here is BETTER "
    "(more assets covered). Green shading reflects this.",
    "matrix", 2, 3,
    matrix("Assets Scanned by Window (↑ higher is better)",
           ["Scanned ≤ 7 Days", "Scanned ≤ 30 Days", "Scanned ≤ 90 Days"],
           ["Hosts Scanned (↑ better)"], specs))

# --- 2-10-3-2 : Classification CVSS vs VPR --------------------------------
rows = [("Critical", CRIT, VPR["crit"]), ("High", HIGH, VPR["high"]),
        ("Medium", MED, VPR["med"]), ("Low", LOW, VPR["low"])]
specs = []
for _, sev, vpr in rows:
    specs.append(("sumid", [flt("severity", sev)], C_BLUE))
    specs.append(("sumid", [flt("vprScore", vpr)], C_AMBER))
add("NCA ECC 2-10-3-2 | Vulnerability Classification (CVSS vs VPR)",
    "2-10-3-2: Classification of vulnerabilities by criticality. Static CVSS "
    "severity (compliance language) shown alongside Tenable VPR (threat-aware "
    "prioritization) so operations can triage on real-world risk.",
    "matrix", 1, 2,
    matrix("Classification by Criticality",
           ["Critical", "High", "Medium", "Low"],
           ["By CVSS Severity", "By VPR Score"], specs))

# --- 2-10-3-2 : Exploitable / actively targeted ---------------------------
# FUNNEL: each row is a subset of the one above, narrowing to what matters most.
#   Row 1: exploit available
#   Row 2: + Critical/High severity
#   Row 3: + VPR 9-10 (top priority)
# Host cells use ipCount so "Hosts Affected" counts hosts, not vulnerabilities.
EXPL = [flt("exploitAvailable", "true")]
EXPL_CH = EXPL + [flt("severity", "4,3")]
EXPL_CH_VPR = EXPL_CH + [flt("vprScore", VPR["crit"])]
# Color escalates DOWN the funnel: amber -> orange -> red, so the deepest,
# most-critical row (exploitable + Crit/High + VPR 9-10) is the most alarming.
specs = [
    ("sumid", EXPL, C_AMBER),
    ("sumip", EXPL, C_AMBER, "cumulative", "ipCount"),
    ("sumid", EXPL_CH, C_ORANGE),
    ("sumip", EXPL_CH, C_ORANGE, "cumulative", "ipCount"),
    ("sumid", EXPL_CH_VPR, C_RED),
    ("sumip", EXPL_CH_VPR, C_RED, "cumulative", "ipCount"),
]
add("NCA ECC 2-10-3-2 | Exploitable & Actively Targeted",
    "2-10-3-2: Highest-criticality classification. A narrowing funnel: findings "
    "with a known exploit, then those that are also Critical/High, then those "
    "also VPR 9-10 — each row a subset of the one above, focusing on what matters "
    "most. Hosts Affected counts unique hosts.",
    "matrix", 2, 2,
    matrix("Exploitable & High-Priority Exposure (narrowing funnel)",
           ["Exploit Available", "+ Critical/High", "+ VPR 9-10 (Top Priority)"],
           ["Vulnerabilities", "Hosts Affected"], specs))

# --- 2-10-3-3 : Remediation progress (mitigated) --------------------------
specs = []
for _, sev, _ in sla[:3]:
    specs.append(("sumid", [flt("severity", sev), flt("daysMitigated", "0:30")], C_GREEN, "patched"))
    specs.append(("sumid", [flt("severity", sev), flt("daysMitigated", "0:90")], C_GREEN, "patched"))
add("NCA ECC 2-10-3-3 | Remediation Progress (Mitigated)",
    "2-10-3-3: Remediation of vulnerabilities per classification/risk. Volume of "
    "findings mitigated in the last 30 and 90 days evidences remediation throughput.",
    "matrix", 1, 3,
    matrix("Mitigated Findings",
           ["Critical", "High", "Medium"],
           ["Last 30 Days", "Last 90 Days"], specs))

# --- 2-10-3-3 : Top 10 vulnerable hosts (action queue) --------------------
add("NCA ECC 2-10-3-3 | Top 10 Most Vulnerable Hosts (Action Queue)",
    "2-10-3-3: Prioritized remediation. Hosts ranked by weighted severity so the "
    "operations team can drive fixes where exposure is highest.",
    "table", 2, 4,
    table(["ip", "dnsName", "total", "vulnBar"], "sumip",
          [flt("severity", "4,3,2")], data_points=10))

# --- 2-10-3-4 : Patch management SLA violations ---------------------------
specs = []
for _, sev, days in sla[:3]:
    specs.append(("sumid", [flt("severity", sev), flt("firstSeen", "%s:all" % days)], C_RED))
    specs.append(("sumip", [flt("severity", sev), flt("firstSeen", "%s:all" % days)], C_RED, "cumulative", "ipCount"))
add("NCA ECC 2-10-3-4 | Patch Management SLA Violations",
    "2-10-3-4: Security patch and update management. Unmitigated findings that have "
    "breached their remediation SLA — the outstanding patch backlog and the hosts it affects.",
    "matrix", 1, 4,
    matrix("Overdue Patches (past SLA)",
           ["Critical (>7 Days)", "High (>30 Days)", "Medium (>60 Days)"],
           ["Overdue Vulns", "Hosts Affected"], specs))

# --- 2-10-3-5 : Trusted-source remediation guidance -----------------------
add("NCA ECC 2-10-3-5 | Trusted-Source Remediation Guidance",
    "2-10-3-5: Subscription to authorized/trusted sources. Tenable-curated solutions "
    "ranked by risk reduction — the fixes that remove the most exposure first.",
    "table", 2, 5,
    table(["solution", "scorePctg", "hostTotal"], "sumremediation",
          [], data_points=100, sort_col="scorePctg", sort_dir="desc"))

# --- 2-10-4 : Periodic review / aging backlog -----------------------------
specs = []
for window in ["30:60", "60:90", "90:all"]:
    specs.append(("sumid", [flt("firstSeen", window), flt("severity", CRIT)], C_RED))
    specs.append(("sumid", [flt("firstSeen", window), flt("severity", HIGH)], C_AMBER))
    specs.append(("sumid", [flt("firstSeen", window), flt("severity", MED)], C_NEUTRAL))
add("NCA ECC 2-10-4 | Vulnerability Aging & Backlog Review",
    "2-10-4: Periodic review of vulnerability management. Aging of the unmitigated "
    "backlog highlights findings that are stagnating and require escalation.",
    "matrix", 1, 5,
    matrix("Unmitigated Backlog Aging",
           ["30–60 Days", "60–90 Days", ">90 Days"],
           ["Critical", "High", "Medium"], specs))

# ---------------------------------------------------------------------------
# Emit XML
# ---------------------------------------------------------------------------
DASH_NAME = "NCA ECC 2-10: Vulnerability Management (Operations)"
DASH_DESC = ("NCA ECC 2-10 — Vulnerability Management. Operations-focused dashboard "
             "mapping each ECC sub-control (2-10-1 through 2-10-4) to actionable metrics: "
             "SLA compliance, CVSS/VPR classification, exploitability, remediation progress, "
             "patch backlog, trusted-source guidance, and aging review.")

parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<dashboardTab>",
         "\t<scVersion>6.2.0</scVersion>",
         "\t<name>%s</name>" % escape(DASH_NAME),
         "\t<description>%s</description>" % escape(DASH_DESC),
         "\t<numColumns>2</numColumns>",
         "\t<columnWidths>", "\t\t<column>50</column>", "\t\t<column>50</column>",
         "\t</columnWidths>", "\t<dashboardComponents>"]

for name, desc, kind, col, order, definition in components:
    parts += [
        "\t\t<component>",
        "\t\t\t<name>%s</name>" % escape(name),
        "\t\t\t<description>%s</description>" % escape(desc),
        "\t\t\t<componentType>%s</componentType>" % kind,
        "\t\t\t<type>%s</type>" % kind,
        "\t\t\t<column>%d</column>" % col,
        "\t\t\t<order>%d</order>" % order,
    ]
    # Table components carry a top-level refresh schedule (matrices embed it
    # inside their clusters instead). SC's importer requires it for tables.
    if kind == "table":
        parts.append("\t\t\t<schedule>FREQ=DAILY;INTERVAL=1</schedule>")
    parts += [
        "\t\t\t<definition>%s</definition>" % b64(definition),
        "\t\t</component>",
    ]

parts += ["\t</dashboardComponents>", "</dashboardTab>", ""]

with open("NCA ECC 2-10 Vulnerability Management (Operations).xml", "w", encoding="utf-8") as f:
    f.write("\n".join(parts))

print("Wrote dashboard with %d components." % len(components))
