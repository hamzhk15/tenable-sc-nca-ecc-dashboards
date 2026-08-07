#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interactive generator for a CUSTOMIZED NCA ECC 2-10 (Vulnerability Management)
dashboard for Tenable Security Center.

Asks the user three things and builds the dashboard XML accordingly:
  1. Data freshness  -> lastSeen filter (last N days, or 'all' to skip)
  2. Repository      -> repositoryIDs filter (ID list, or 'all' to skip)
  3. Per-severity SLA days (Critical / High / Medium / Low)

The freshness + repository filters are applied GLOBALLY to every widget
(except that freshness is skipped on widgets that already key off lastSeen,
to avoid a conflicting duplicate filter). SLA days drive the firstSeen
thresholds in the SLA-compliance and patch-violation widgets.

Run:  python3 build_ecc_2_10_custom.py
Definitions are emitted as base64(PHP-serialized) via sc_dashboard_lib.
"""
import sys
from sc_dashboard_lib import (ser, b64, flt, matrix, table, write_dashboard,
                              C_NEUTRAL, C_GREEN, C_RED, C_AMBER, C_ORANGE, C_BLUE,
                              CRIT, HIGH, MED, LOW, INFO)

# VPR ranges (fixed; classification is by score band, not SLA)
VPR = {"crit": "9-10", "high": "7-8.9", "med": "4-6.9", "low": "0.1-3.9"}

# ---------------------------------------------------------------------------
# Interactive prompts
# ---------------------------------------------------------------------------
def ask(prompt, default=None):
    suffix = " [%s]" % default if default is not None else ""
    try:
        val = input("%s%s: " % (prompt, suffix)).strip()
    except EOFError:
        val = ""
    return val if val else (default if default is not None else "")

def ask_int(prompt, default):
    while True:
        v = ask(prompt, str(default))
        try:
            return int(v)
        except ValueError:
            print("  Please enter a whole number of days.")

def prompt_config():
    print("=" * 64)
    print(" NCA ECC 2-10 — Customized Dashboard Generator")
    print("=" * 64)

    # 1. Data freshness (lastSeen)
    print("\n[1/3] DATA FRESHNESS (Last Observed)")
    print("      Limits data to assets/findings seen recently.")
    fresh = ask("      Last N days, or 'all' for no limit", "30")
    if fresh.lower() == "all":
        last_seen = None
        fresh_label = "All time"
    else:
        try:
            days = int(fresh)
        except ValueError:
            print("      Not a number — defaulting to 30 days.")
            days = 30
        last_seen = "0:%d" % days
        fresh_label = "Last %d days" % days

    # 2. Repository (repositoryIDs)
    print("\n[2/3] REPOSITORY")
    print("      Limits which repository/repositories to read from.")
    repo = ask("      Repository ID(s) comma-separated, or 'all'", "all")
    if repo.lower() == "all" or repo == "":
        repo_ids = None
        repo_label = "All repositories"
    else:
        # normalize "1, 3" -> "1,3"
        repo_ids = ",".join(p.strip() for p in repo.split(",") if p.strip())
        repo_label = "Repository IDs: %s" % repo_ids

    # 3. SLA per severity
    print("\n[3/3] REMEDIATION SLA (days) — blank keeps the default")
    sla_crit = ask_int("      Critical SLA days", 7)
    sla_high = ask_int("      High SLA days", 30)
    sla_med  = ask_int("      Medium SLA days", 60)
    sla_low  = ask_int("      Low SLA days", 90)

    print("\n" + "-" * 64)
    print(" Summary:")
    print("   Freshness : %s" % fresh_label)
    print("   Scope     : %s" % repo_label)
    print("   SLA (days): Critical %d / High %d / Medium %d / Low %d"
          % (sla_crit, sla_high, sla_med, sla_low))
    print("-" * 64)

    return {
        "last_seen": last_seen, "fresh_label": fresh_label,
        "repo_ids": repo_ids, "repo_label": repo_label,
        "sla": {"Critical": (CRIT, sla_crit), "High": (HIGH, sla_high),
                "Medium": (MED, sla_med), "Low": (LOW, sla_low)},
    }

# ---------------------------------------------------------------------------
# Global-filter injection
# ---------------------------------------------------------------------------
def make_gf(cfg):
    """Return a function that appends global filters (lastSeen + repositoryIDs)
    to a per-cell filter list. Skips lastSeen when the cell already uses it."""
    def gf(base_filters):
        out = list(base_filters)
        has_last_seen = any(f["filterName"] == "lastSeen" for f in out)
        if cfg["repo_ids"] is not None:
            out.append(flt("repositoryIDs", cfg["repo_ids"]))
        if cfg["last_seen"] is not None and not has_last_seen:
            out.append(flt("lastSeen", cfg["last_seen"]))
        return out
    return gf

# ---------------------------------------------------------------------------
# Build components
# ---------------------------------------------------------------------------
def build(cfg):
    gf = make_gf(cfg)
    sla = cfg["sla"]
    C = []
    def add(name, desc, kind, col, order, defn):
        C.append({"name": name, "desc": desc, "kind": kind, "column": col,
                  "order": order, "definition": defn})

    # --- 2-10-1 & 2-10-2 : SLA Compliance ---------------------------------
    specs = []
    for label in ["Critical", "High", "Medium", "Low"]:
        sev, days = sla[label]
        specs.append(("sumid", gf([flt("severity", sev)]), C_NEUTRAL))
        specs.append(("sumid", gf([flt("severity", sev), flt("firstSeen", "0:%d" % days)]), C_GREEN))
        specs.append(("sumid", gf([flt("severity", sev), flt("firstSeen", "%d:all" % days)]), C_RED))
    add("NCA ECC 2-10-1 & 2-10-2 | Remediation SLA Compliance",
        "2-10-1/2-10-2: VM cybersecurity requirements defined and implemented. "
        "Unmitigated vulnerabilities vs remediation SLAs (Critical %d / High %d / "
        "Medium %d / Low %d days). Scope: %s; %s."
        % (sla["Critical"][1], sla["High"][1], sla["Medium"][1], sla["Low"][1],
           cfg["repo_label"], cfg["fresh_label"]),
        "matrix", 1, 1,
        matrix("Remediation SLA Compliance (by CVSS severity)",
               ["Critical (%d Days)" % sla["Critical"][1], "High (%d Days)" % sla["High"][1],
                "Medium (%d Days)" % sla["Medium"][1], "Low (%d Days)" % sla["Low"][1]],
               ["Total Unmitigated", "Within SLA", "Overdue"], specs))

    # --- 2-10-3-1 : Assessment cadence ------------------------------------
    specs = []
    for window in ["0:7", "0:30", "0:90"]:
        specs.append(("sumid", gf([flt("firstSeen", window), flt("vprScore", VPR["crit"])]), C_RED))
        specs.append(("sumid", gf([flt("firstSeen", window), flt("vprScore", VPR["high"])]), C_AMBER))
        specs.append(("sumip", gf([flt("firstSeen", window)]), C_BLUE, "cumulative", "ipCount"))
    add("NCA ECC 2-10-3-1 | Periodic Vulnerability Assessment Cadence",
        "2-10-3-1: Periodic vulnerability assessments. Newly discovered findings "
        "by detection window. Scope: %s; %s." % (cfg["repo_label"], cfg["fresh_label"]),
        "matrix", 2, 1,
        matrix("Newly Discovered Findings (assessment cadence)",
               ["Discovered ≤ 7 Days", "Discovered ≤ 30 Days", "Discovered ≤ 90 Days"],
               ["Critical (VPR)", "High (VPR)", "Hosts Affected"], specs))

    # --- 2-10-3-1 : Scan coverage (higher is better) ----------------------
    # NOTE: this widget keys off lastSeen itself -> gf() skips the global lastSeen.
    specs = []
    for window in ["0:7", "0:30", "0:90"]:
        specs.append(("sumip", gf([flt("pluginID", "19506"), flt("lastSeen", window)]), C_GREEN, "cumulative", "ipCount"))
    add("NCA ECC 2-10-3-1 | Scan Coverage (Assets Scanned) — Higher is Better",
        "2-10-3-1: Assets actually scanned within each window (Plugin ID 19506). "
        "NOTE: a HIGHER number here is BETTER (more coverage). Scope: %s."
        % cfg["repo_label"],
        "matrix", 2, 3,
        matrix("Assets Scanned by Window (↑ higher is better)",
               ["Scanned ≤ 7 Days", "Scanned ≤ 30 Days", "Scanned ≤ 90 Days"],
               ["Hosts Scanned (↑ better)"], specs))

    # --- 2-10-3-2 : Classification CVSS vs VPR ----------------------------
    rows = [("Critical", CRIT, VPR["crit"]), ("High", HIGH, VPR["high"]),
            ("Medium", MED, VPR["med"]), ("Low", LOW, VPR["low"])]
    specs = []
    for _, sev, vpr in rows:
        specs.append(("sumid", gf([flt("severity", sev)]), C_BLUE))
        specs.append(("sumid", gf([flt("vprScore", vpr)]), C_AMBER))
    add("NCA ECC 2-10-3-2 | Vulnerability Classification (CVSS vs VPR)",
        "2-10-3-2: Classification by criticality. CVSS severity alongside VPR. "
        "Scope: %s; %s." % (cfg["repo_label"], cfg["fresh_label"]),
        "matrix", 1, 2,
        matrix("Classification by Criticality",
               ["Critical", "High", "Medium", "Low"],
               ["By CVSS Severity", "By VPR Score"], specs))

    # --- 2-10-3-2 : Exploitable / actively targeted -----------------------
    # FUNNEL: each row is a subset of the one above (exploit -> +Crit/High ->
    # +VPR 9-10). Host cells use ipCount so "Hosts Affected" counts hosts.
    expl = [flt("exploitAvailable", "true")]
    expl_ch = expl + [flt("severity", "4,3")]
    expl_ch_vpr = expl_ch + [flt("vprScore", VPR["crit"])]
    # Color escalates DOWN the funnel: amber -> orange -> red (deepest = worst).
    specs = [
        ("sumid", gf(expl), C_AMBER),
        ("sumip", gf(expl), C_AMBER, "cumulative", "ipCount"),
        ("sumid", gf(expl_ch), C_ORANGE),
        ("sumip", gf(expl_ch), C_ORANGE, "cumulative", "ipCount"),
        ("sumid", gf(expl_ch_vpr), C_RED),
        ("sumip", gf(expl_ch_vpr), C_RED, "cumulative", "ipCount"),
    ]
    add("NCA ECC 2-10-3-2 | Exploitable & Actively Targeted",
        "2-10-3-2: Highest-criticality classification. A narrowing funnel: "
        "exploit available, then also Critical/High, then also VPR 9-10 — each "
        "row a subset of the one above. Hosts Affected counts unique hosts. "
        "Scope: %s; %s." % (cfg["repo_label"], cfg["fresh_label"]),
        "matrix", 2, 2,
        matrix("Exploitable & High-Priority Exposure (narrowing funnel)",
               ["Exploit Available", "+ Critical/High", "+ VPR 9-10 (Top Priority)"],
               ["Vulnerabilities", "Hosts Affected"], specs))

    # --- 2-10-3-3 : Remediation progress (mitigated) ----------------------
    specs = []
    for label in ["Critical", "High", "Medium"]:
        sev, _ = sla[label]
        specs.append(("sumid", gf([flt("severity", sev), flt("daysMitigated", "0:30")]), C_GREEN, "patched"))
        specs.append(("sumid", gf([flt("severity", sev), flt("daysMitigated", "0:90")]), C_GREEN, "patched"))
    add("NCA ECC 2-10-3-3 | Remediation Progress (Mitigated)",
        "2-10-3-3: Remediation per classification. Findings mitigated in the last "
        "30 and 90 days. Scope: %s." % cfg["repo_label"],
        "matrix", 1, 3,
        matrix("Mitigated Findings",
               ["Critical", "High", "Medium"],
               ["Last 30 Days", "Last 90 Days"], specs))

    # --- 2-10-3-3 : Top 10 vulnerable hosts -------------------------------
    add("NCA ECC 2-10-3-3 | Top 10 Most Vulnerable Hosts (Action Queue)",
        "2-10-3-3: Prioritized remediation. Hosts ranked by weighted severity. "
        "Scope: %s; %s." % (cfg["repo_label"], cfg["fresh_label"]),
        "table", 2, 4,
        table(["ip", "dnsName", "total", "vulnBar"], "sumip",
              gf([flt("severity", "4,3,2")]), data_points=10))

    # --- 2-10-3-4 : Patch management SLA violations -----------------------
    specs = []
    for label in ["Critical", "High", "Medium"]:
        sev, days = sla[label]
        specs.append(("sumid", gf([flt("severity", sev), flt("firstSeen", "%d:all" % days)]), C_RED))
        specs.append(("sumip", gf([flt("severity", sev), flt("firstSeen", "%d:all" % days)]), C_RED, "cumulative", "ipCount"))
    add("NCA ECC 2-10-3-4 | Patch Management SLA Violations",
        "2-10-3-4: Patch/update management. Unmitigated findings that have breached "
        "their SLA (Critical >%d / High >%d / Medium >%d days). Scope: %s."
        % (sla["Critical"][1], sla["High"][1], sla["Medium"][1], cfg["repo_label"]),
        "matrix", 1, 4,
        matrix("Overdue Patches (past SLA)",
               ["Critical (>%d Days)" % sla["Critical"][1], "High (>%d Days)" % sla["High"][1],
                "Medium (>%d Days)" % sla["Medium"][1]],
               ["Overdue Vulns", "Hosts Affected"], specs))

    # --- 2-10-3-5 : Trusted-source remediation guidance -------------------
    # sumremediation supports repositoryIDs; keep global filters applied.
    add("NCA ECC 2-10-3-5 | Trusted-Source Remediation Guidance",
        "2-10-3-5: Authorized/trusted sources. Tenable-curated solutions ranked by "
        "risk reduction. Scope: %s." % cfg["repo_label"],
        "table", 2, 5,
        table(["solution", "scorePctg", "hostTotal"], "sumremediation",
              gf([]), data_points=100, sort_col="scorePctg", sort_dir="desc"))

    # --- 2-10-4 : Aging / backlog review ----------------------------------
    specs = []
    for window in ["30:60", "60:90", "90:all"]:
        specs.append(("sumid", gf([flt("firstSeen", window), flt("severity", CRIT)]), C_RED))
        specs.append(("sumid", gf([flt("firstSeen", window), flt("severity", HIGH)]), C_AMBER))
        specs.append(("sumid", gf([flt("firstSeen", window), flt("severity", MED)]), C_NEUTRAL))
    add("NCA ECC 2-10-4 | Vulnerability Aging & Backlog Review",
        "2-10-4: Periodic review. Aging of the unmitigated backlog. Scope: %s; %s."
        % (cfg["repo_label"], cfg["fresh_label"]),
        "matrix", 1, 5,
        matrix("Unmitigated Backlog Aging",
               ["30–60 Days", "60–90 Days", ">90 Days"],
               ["Critical", "High", "Medium"], specs))

    return C

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    cfg = prompt_config()
    components = build(cfg)

    # Build a filename that reflects the customization.
    repo_part = "AllRepos" if cfg["repo_ids"] is None else "Repo-%s" % cfg["repo_ids"].replace(",", "-")
    fresh_part = "AllTime" if cfg["last_seen"] is None else cfg["last_seen"].replace(":", "-") + "d"
    fname = "NCA ECC 2-10 Custom (%s, %s).xml" % (repo_part, fresh_part)

    desc = ("NCA ECC 2-10 — Vulnerability Management (customized). "
            "Scope: %s. Freshness: %s. SLA (days): Critical %d / High %d / "
            "Medium %d / Low %d."
            % (cfg["repo_label"], cfg["fresh_label"],
               cfg["sla"]["Critical"][1], cfg["sla"]["High"][1],
               cfg["sla"]["Medium"][1], cfg["sla"]["Low"][1]))

    write_dashboard(fname, "NCA ECC 2-10: Vulnerability Management (Custom)", desc, components)
    print("\n✓ Wrote %d components to:\n  %s" % (len(components), fname))
    print("  Import via SC: Dashboard → Options → Add Dashboard → Import.")

if __name__ == "__main__":
    main()
