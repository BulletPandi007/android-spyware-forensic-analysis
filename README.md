# Hybrid Static-Dynamic Forensic Analysis of Android Spyware

> **Academic Research Project — National Forensic Sciences University (NFSU)**
> February – April 2026 | 12-Week Study

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![Semgrep](https://img.shields.io/badge/Semgrep-Custom%20Rules-orange.svg)](https://semgrep.dev)
[![Ghidra](https://img.shields.io/badge/Ghidra-12.0.2-red.svg)](https://ghidra-sre.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Samples](https://img.shields.io/badge/Samples-7%20APKs-purple.svg)]()
[![YARA Rules](https://img.shields.io/badge/YARA-6%20Rules-yellow.svg)](rules/)

---

## Overview

This repository contains all scripts, detection rules, data artifacts, and documentation produced during a 12-week hybrid forensic analysis of seven Android spyware and stalkerware samples. The study combined static analysis, advanced code pattern matching (Semgrep), native binary reverse engineering (Ghidra), and controlled sandbox dynamic analysis (ANY.RUN) to produce a comprehensive behavioral characterization of each sample.

### Samples Analyzed

| Sample | Family | Category | Stealth Score | Key Finding |
|--------|--------|----------|--------------|-------------|
| antidot.apk | Antidot | Banking Trojan | 10/10 | 8 OEM-specific overlay functions + VM code protection |
| brata.apk | BraTA | Banking Trojan | 5/10 | Embedded PHP phishing kit targeting Mellat Bank (Iran) |
| clayrat.apk | ClayRAT | RAT | 7/10 | Live C2 confirmed — losthed.clay.rest (Python Werkzeug) |
| selfspy.apk | Custom | Stalkerware | 7/10 | 6 dex files — largest codebase, GPS tracking |
| spymax.apk | SpyMax | RAT | 5/10 | 13 dangerous permissions, C2-dependent dormancy |
| spynote.apk | SpyNote | RAT | 7/10 | Zero permissions + Unicode evasion + Accessibility abuse |
| truthspy.apk | TruthSpy | Stalkerware | 8/10 | LAME MP3 encoder weaponized for audio exfiltration |

---

## Critical Finding — BraTA Embedded Phishing Kit

> The most significant discovery of this project.

The BraTA APK was found to contain `Mellat.zip` — a **complete PHP web phishing kit** targeting Mellat Bank (Iran), including:

- 12 PHP server-side files (payment processing, OTP interception, C2 exfiltration)
- A **live Telegram bot token** for real-time victim notification
- A **server error log** revealing live infrastructure details (June 2021)
- Farsi-language banking UI targeting Iranian users

**Confirmed IOCs from the kit:**

```
Telegram Bot:  5339581065:AAEI3MvGuNmc2io57pk8vIQjIVN4PPIUiao
C2 Relay:      codex-team.tk/api/card2card.php
Server Path:   /home/icmmhitg/public_html/text1/Mellat/
Target API:    ipb.parsian-bank.ir/mobileBank/1.0/getCardOwnerWithoutLogin
Campaign Date: June 27, 2021
```

> ⚠️ These credentials are documented for threat intelligence purposes only. Do not interact with any identified infrastructure.

---

## Repository Structure

```
android-spyware-forensic-analysis/
│
├── scripts/                        # All Python analysis scripts
│   ├── Static_Script.py            # Phase 1: manifest, permissions, IOC scanning
│   ├── Semgrep_results_parser.py   # Parse Semgrep JSON → CSV
│   ├── Stealth_score_calculation.py# 8-indicator stealth scoring (0-10)
│   ├── APK_Structure_Analysis.py   # Dex, .so, signing, ZIP anomalies
│   ├── Brata_IOC_Report.py         # Phishing kit extraction + IOC documentation
│   ├── Ghidra_Analysis.py          # Ghidra headless findings → CSV
│   ├── Visualizations.py           # 5 publication-quality charts
│   ├── Static_Dynamic_Correlation.py # Cross-analysis correlation engine
│   └── Detection_Rules.py          # YARA + Semgrep rule generator
│
├── rules/                          # Detection artifacts
│   ├── spyware_rules.yaml          # 15 Semgrep behavioral rules (source)
│   ├── android_spyware_rules.yar   # 6 YARA detection rules
│   ├── android_spyware_semgrep.yaml# 10 exportable Semgrep signatures
│   └── ioc_master_list.txt         # Comprehensive IOC reference
│
├── ghidra_scripts/
│   └── ExtractNativeStrings.java   # Ghidra headless post-script
│
├── data/
│   ├── forensic_analysis_correlated.csv  # Master dataset (all findings)
│   └── IOCs/
│       └── brata_ioc_report.json         # Structured BraTA IOC report
│
├── visualizations/
│   ├── 01_stealth_scores.png
│   ├── 02_permissions_heatmap.png
│   ├── 03_semgrep_heatmap.png
│   ├── 04_radar_chart.png
│   └── 05_obfuscation_scatter.png
│
├── sandbox_reports/
│   ├── antidot_anyrun_report.pdf
│   ├── spynote_anyrun_report.pdf
│   └── sandbox_results_summary.md
│
└── docs/
    └── Android_Spyware_Forensic_Report.docx  # Full 35-page technical report
```

---

## Setup and Usage

### Prerequisites

```bash
# Python dependencies
pip install pandas matplotlib numpy

# Semgrep (via WSL on Windows)
pipx install semgrep
pipx ensurepath

# JADX for APK decompilation
# Download from: https://github.com/skylot/jadx/releases

# Ghidra 12.x with Java 21 LTS
# Download from: https://ghidra-sre.org/
```

### Running the Analysis Pipeline

The analysis is designed to be run sequentially. Configure your APK paths in each script before running.

**Step 1 — Basic Static Extraction**
```bash
python scripts/Static_Script.py
# Output: initial_forensic_analysis_readable.csv
```

**Step 2 — Semgrep Code Analysis**
```bash
# Run in WSL:
semgrep --config rules/spyware_rules.yaml /path/to/decompiled/java/ \
        --json --output semgrep_results.json

# Parse results:
python scripts/Semgrep_results_parser.py
# Output: forensic_analysis_with_semgrep.csv
```

**Step 3 — Stealth Scoring**
```bash
python scripts/Stealth_score_calculation.py
# Output: forensic_analysis_final.csv
```

**Step 4 — APK Structure Analysis**
```bash
python scripts/APK_Structure_Analysis.py
# Output: Updated forensic_analysis_final.csv
```

**Step 5 — Ghidra Native Analysis** *(samples with .so libraries only)*
```bash
# Run in Ghidra installation directory:
support\analyzeHeadless.bat /path/to/project ProjectName ^
  -import /path/to/sample.apk ^
  -postScript ExtractNativeStrings.java ^
  -scriptPath /path/to/ghidra_scripts/ ^
  -recursive -overwrite
# Output: ghidra_output/<sample>/<lib>_analysis.txt

python scripts/Ghidra_Analysis.py
# Output: Updated forensic_analysis_final.csv
```

**Step 6 — Static-Dynamic Correlation**
```bash
python scripts/Static_Dynamic_Correlation.py
# Output: forensic_analysis_correlated.csv
```

**Step 7 — Visualizations**
```bash
python scripts/Visualizations.py
# Output: visualizations/01_*.png through 05_*.png
```

**Step 8 — Detection Rules**
```bash
python scripts/Detection_Rules.py
# Output: rules/android_spyware_rules.yar
#         rules/android_spyware_semgrep.yaml
#         rules/ioc_master_list.txt
```

---

## Key Findings

### Stealth Score Summary

| Sample | Score | Primary Indicators |
|--------|-------|--------------------|
| antidot | 10/10 | 489 obfuscated res files · 8 OEM overlays · VM protection · confirmed C2 |
| truthspy | 8/10 | Audio exfil via LAME · 10 dangerous perms · 4 CPU archs |
| spynote | 7/10 | Zero permissions · Unicode filenames · Accessibility abuse · sandbox evasion |
| selfspy | 7/10 | GPS tracking · 10 dangerous perms · emulator detection |
| clayrat | 7/10 | Live C2 confirmed · 90 HTTP requests in 60s · app hiding |
| brata | 5/10 | Embedded phishing kit · v1-only signing · Firebase blending |
| spymax | 5/10 | 13 dangerous perms · C2-dependent dormancy · low obfuscation |

### Confirmed IOCs

**Malicious Domains**
```
ping.ynrkone.top              # Antidot C2
pip.uiimoss.top               # Antidot secondary C2
log-service-*.aliyuncs.com    # Antidot C2 logging (Alibaba Cloud)
losthed.clay.rest             # ClayRAT live C2
codex-team.tk                 # BraTA card relay
```

**Malicious IPs**
```
147.139.146.211               # Antidot C2 (Alibaba Cloud, CN)
147.139.146.209               # Antidot C2 (Alibaba Cloud, CN)
147.139.146.144               # Antidot C2 (Alibaba Cloud, CN)
64.188.83.172                 # ClayRAT C2
```

**Package Names**
```
com.wetpacd1d.psyd1d          # Antidot (disguised as random app)
com.appd.mercantil            # SpyNote (disguised as merchant app)
sh.abc.shabd                  # BraTA
```

### Semgrep Hit Matrix

| Sample | Camera | Call Log | GPS | HTTP POST | Socket | Audio | Emulator | Total |
|--------|--------|----------|-----|-----------|--------|-------|----------|-------|
| antidot | 21 | 1 | 1 | 6 | 0 | 0 | 1 | **35** |
| brata | 5 | 1 | 0 | 3 | 0 | 0 | 2 | **12** |
| clayrat | 11 | 0 | 0 | 2 | 0 | 0 | 0 | **14** |
| selfspy | 5 | 1 | 7 | 2 | 2 | 0 | 2 | **20** |
| spymax | 2 | 0 | 3 | 0 | 0 | 0 | 0 | **5** |
| spynote | 2 | **50** | 0 | 0 | 1 | 0 | 0 | **54** |
| truthspy | 7 | 4 | 1 | 0 | 1 | **5** | 0 | **19** |

---

## Detection Rules

### YARA Rules (`rules/android_spyware_rules.yar`)

| Rule | Target | Confidence | Key Indicators |
|------|--------|-----------|----------------|
| Antidot_Banking_Trojan | Antidot | HIGH | Package name, C2 domains, OEM overlay functions |
| BraTA_Banking_Trojan_PhishingKit | BraTA | HIGH | Mellat.zip, Telegram token, PHP kit filenames |
| ClayRAT_RAT | ClayRAT | HIGH | losthed.clay.rest, Werkzeug fingerprint |
| SpyNote_RAT | SpyNote | MEDIUM | Package name, Unicode sequences, Accessibility patterns |
| TruthSpy_Stalkerware | TruthSpy | HIGH | LAME JNI bridge functions |
| Generic_Android_Spyware | All | MEDIUM | Boot + SMS + overlay, Telegram API |

### Using YARA Rules

```bash
# Install yara-python
pip install yara-python

# Scan a single APK
yara rules/android_spyware_rules.yar /path/to/sample.apk

# Scan a directory
yara -r rules/android_spyware_rules.yar /path/to/apks/
```

### Using Semgrep Rules

```bash
# Scan decompiled Java source
semgrep --config rules/android_spyware_semgrep.yaml /path/to/decompiled/
```

---

## Native Library Analysis Highlights

### Antidot — libx2.so (OEM Overlay Engine)
Ghidra analysis revealed manufacturer-specific overlay bypass functions for **8 Android OEMs**:
- `setupSamsungWindowLayout`, `setupHuaWeiWindowLayout`, `setupOPPOWindowLayout`
- `setupVivoWindowLayout`, `setupXiaomiWindowLayout`, `setupRedMiWindowLayout`
- `setupMotoRolaWindowLayout`, `setupRealmeWindowLayout`
- `hideEnable()` — native stealth toggle at address 0x141000

### Antidot — libnmmp.so (VM Code Protection)
Identified as the **nmmedit protect SDK** — encrypts Java bytecode into a custom VM interpreter, making core malicious logic invisible to static analysis.
- Key functions: `vmInterpret`, `cacheInitial`, `getCacheClass`
- Package: `com/nmmedit/protect/NativeUtil`

### TruthSpy — libandroidlame.so (Audio Exfiltration)
Weaponized version of the open-source [AndroidLame](https://github.com/naman14/AndroidLame) library:
- `Java_com_naman14_androidlame_AndroidLame_lameEncode` — PCM → MP3 encoding
- `Java_com_naman14_androidlame_AndroidLame_lameFlush` — buffer flush
- `Java_com_naman14_androidlame_AndroidLame_lameClose` — encoder teardown
- MP3 compression reduces exfil traffic volume ~10x vs raw PCM

---

## Visualizations

All charts are generated in a dark cyber theme by `scripts/Visualizations.py`.

| File | Description |
|------|-------------|
| `01_stealth_scores.png` | Horizontal bar chart — stealth scores color-coded by severity |
| `02_permissions_heatmap.png` | Grid heatmap — dangerous permission declarations across all samples |
| `03_semgrep_heatmap.png` | Heatmap — Semgrep rule hit counts by behavior category |
| `04_radar_chart.png` | Radar chart — multi-dimensional threat profile per sample |
| `05_obfuscation_scatter.png` | Scatter plot — obfuscation level vs stealth score (bubble = Semgrep hits) |

---

## Ethical Statement

This research was conducted in strict compliance with ethical guidelines for malware analysis:

- **No live infrastructure interaction** — Discovered credentials (Telegram tokens, C2 endpoints) were documented for intelligence purposes only. No requests were made to active C2 servers.
- **No victim contact** — No attempt was made to identify or contact victims of any analyzed malware family.
- **Controlled environment** — All dynamic analysis was performed in isolated sandbox environments.
- **Responsible disclosure** — Findings are reported in an academic context. IOCs are provided to enable detection and victim identification by forensic investigators.
- **Stalkerware ethics** — TruthSpy and Selfspy are documented to enable detection. Their existence represents a serious threat to personal safety, particularly for victims of domestic abuse and intimate partner violence.

> ⚠️ **Important**: The samples analyzed in this repository are dangerous malware. Do not execute them outside of isolated analysis environments. The authors accept no responsibility for any misuse of the information or tools contained in this repository.

---

## Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| APKTool | v2.x | APK decompilation to Smali |
| JADX | v1.5.0 | APK decompilation to Java |
| Semgrep | Latest | Code pattern matching |
| Ghidra | v12.0.2 | Native library reverse engineering |
| Python | v3.14 | Automation and analysis |
| pandas | Latest | Data processing |
| matplotlib | Latest | Visualization |
| ANY.RUN | Cloud | Dynamic sandbox analysis |
| WSL | Ubuntu 24 | Linux environment on Windows |

---

## Citation

If you use any artifacts from this repository in your research, please cite:

```bibtex
@misc{spyware_forensic_2026,
  title   = {Hybrid Static-Dynamic Forensic Analysis of Android Spyware},
  author  = {Yaswanth},
  year    = {2026},
  school  = {National Forensic Sciences University (NFSU)},
  url     = {https://github.com/[your-username]/android-spyware-forensic-analysis}
}
```

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

Detection rules (YARA and Semgrep) are released for defensive security research purposes only.

---

*National Forensic Sciences University (NFSU) | April 2026*
