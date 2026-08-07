# NCA ECC Dashboards for Tenable Security Center

Ready-to-import dashboard templates for **Saudi NCA Essential Cybersecurity Controls (ECC 2024)** on Tenable Security Center (SC). Each dashboard maps directly to an ECC control domain and uses only proven SC query constructs (plugins, filters, tools) — no fake metrics, no keyword-based noise.

## Dashboards included

| Control | Dashboard | Focus |
|---------|-----------|-------|
| **ECC 2-1** | Asset Management | Asset inventory, OS distribution, network device types |
| **ECC 2-3** | Systems Protection | Anti-malware hygiene, default credentials, compliance posture |
| **ECC 2-5** | Network Security | Service enumeration, external exposure, device classification |
| **ECC 2-10** | Vulnerability Management (Operations) | Severity breakdown, SLA tracking, exploitable exposure, scan coverage, remediation progress |
| **ECC 2-10** | Vulnerability Management (Custom) | Interactive generator — prompts for repository, data freshness, and per-severity SLA days |

## Quick start — import a ready XML

1. In Tenable SC: **Dashboard > Options > Add Dashboard > Import Dashboard**
2. Upload any `.xml` file from the `xml/` folder
3. The dashboard tab appears immediately

No configuration needed for the standard dashboards. They work with any repository and show cumulative data.

## Generate a customized ECC 2-10 dashboard

The interactive generator lets you scope the dashboard to specific repositories, freshness windows, and SLA targets:

```bash
cd dashboards
python3 build_ecc_2_10_custom.py
```

It prompts for:
- **Data freshness** — restrict to hosts seen in the last N days (or `all`)
- **Repository IDs** — limit to specific SC repositories
- **SLA days** — per-severity remediation targets (Critical/High/Medium/Low)

The generated `.xml` is ready to import.

## Regenerate all standard dashboards

```bash
cd dashboards
python3 build_dashboard.py       # ECC 2-10 Operations
python3 build_ecc_2_1.py         # ECC 2-1
python3 build_ecc_2_3.py         # ECC 2-3
python3 build_ecc_2_5.py         # ECC 2-5
```

Each writes a `.xml` in the current directory.

## Requirements

- **Python 3.6+** — standard library only, no pip packages needed
- **Tenable Security Center 6.2+** — any version that supports dashboard XML import

## Claude Code skill (optional)

This repo includes a Claude Code skill (`tenable-sc-reporting-assistant`) in `.claude/skills/`. If you use [Claude Code](https://claude.com/claude-code), it enables conversational dashboard and report generation:

- Ask Claude to build a custom SC dashboard from a plain-English description
- Upload generated dashboards directly to SC via API
- Generate PDF and CSV reports

To install: copy the `.claude/` folder into your project or `~/.claude/`.

## File structure

```
dashboards/
  sc_dashboard_lib.py       # Shared library (PHP serialize, filters, matrix/table builders)
  build_dashboard.py        # ECC 2-10 Operations (10 components)
  build_ecc_2_1.py          # ECC 2-1 Asset Management
  build_ecc_2_3.py          # ECC 2-3 Systems Protection
  build_ecc_2_5.py          # ECC 2-5 Network Security
  build_ecc_2_10_custom.py  # Interactive ECC 2-10 generator

xml/
  NCA ECC 2-10 Vulnerability Management (Operations).xml
  NCA ECC 2-1 Asset Management.xml
  NCA ECC 2-3 Systems Protection.xml
  NCA ECC 2-5 Network Security.xml

.claude/skills/tenable-sc-reporting-assistant/   # Claude Code skill
```

## Design principles

- **Data accuracy first** — structured filters (pluginID, severity, pluginType) over keyword matching; every widget guardrailed against known false-positive patterns
- **Host vs finding counts** — coverage widgets use `sumip` + `ipCount` (hosts); risk widgets use `sumid` (findings). Never conflated.
- **Proven palette** — colors pass foreground:background contrast checks and match SC's native rendering
- **Per-component query naming** — prevents the "loading" hang that global counters cause on import
- **Byte-accurate PHP serialization** — every `s:N:"..."` prefix counts UTF-8 bytes correctly

## ECC control mapping

The dashboards map to the following NCA ECC 2024 control domains:

- **2-1 (Asset Management):** Establish and maintain an inventory of technology assets
- **2-3 (Systems Protection):** Protect systems from malicious software, unauthorized changes, and configuration drift
- **2-5 (Network Security):** Implement network security controls, segmentation, and monitoring
- **2-10 (Vulnerability Management):** Identify, prioritize, and remediate vulnerabilities within defined SLAs

## License

MIT License — see [LICENSE](LICENSE).
