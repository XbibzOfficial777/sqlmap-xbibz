# SQLMAP REVAMP!

[![sqlmap-xbibz](https://imgbs.com/uploads/sqlmapbibz-57b957d5.jpg)](https://tiktok.com/@xbibzofficial)

[![Version](https://img.shields.io/badge/version-3.0-red.svg)](https://github.com/XbibzOfficial777/sqlmap-xbibz) [![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE) [![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Termux-blue.svg)](https://github.com/XbibzOfficial777/sqlmap-xbibz) [![Recoded](https://img.shields.io/badge/recoded%20by-Xbibz%20Official-orange.svg)](https://tiktok.com/@xbibzofficial)

> **Recoded By Xbibz Official v3.0** - Enhanced sqlmap with ParamSpider-style parameter discovery, DalFox-style WAF intelligence, and fully automated mode.

![visitors](https://visitor-badge.laobi.icu/badge?page_id=XbibzOfficial777.sqlmap-xbibz)

---

## What's New in v3.0

| Feature | Description |
|---------|-------------|
| **`--auto`** | Fully automated mode - auto-detect WAF, auto-apply tamper scripts, auto-level/risk, zero interaction |
| **`--spider`** | ParamSpider-style parameter discovery via Wayback Machine CDX API + DOM mining |
| **DalFox WAF Engine** | Multi-layer WAF fingerprinting (passive header + body + provocation probe) with 28+ WAF bypass strategies |
| **Progressive Escalation** | 6-stage tamper escalation when current bypass chain fails |
| **Smart Retry** | Adaptive connection error handling with exponential backoff for rate limits |
| **Priority Sorting** | Discovered URLs sorted by SQLi priority (high/medium/low parameter classification) |
| **Termux Support** | Full non-root Android/Termux support with auto-dependency installation |
| **One-line Install** | Install via curl with automatic .bashrc/.zshrc setup |

---

## Quick Install

### One-line Install (Linux/macOS)
```bash
curl -sL https://raw.githubusercontent.com/XbibzOfficial777/sqlmap-xbibz/main/install.sh | bash
```

### One-line Install (Termux)
```bash
curl -sL https://raw.githubusercontent.com/XbibzOfficial777/sqlmap-xbibz/main/install.sh | bash
```

### Manual Install
```bash
git clone https://github.com/XbibzOfficial777/sqlmap-xbibz.git
cd sqlmap-xbibz
chmod +x install.sh
./install.sh
```

### Uninstall
```bash
~/.sqlmap-xbibz/uninstall.sh
```

---

## Usage

### Basic Usage (same as original sqlmap)
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch
```

### **NEW: Fully Automated Mode (--auto)**
```bash
sqlmap -u "http://target.com/page.php?id=1" --auto
```
What `--auto` does automatically:
- Sets batch mode (no interactive prompts)
- Enables random User-Agent for stealth
- Sets detection level=3, risk=2
- Auto-detects WAF and applies appropriate tamper scripts
- Progressive 6-stage escalation when bypass fails
- Adaptive connection error handling
- Tests casted parameters that would normally be skipped

### **NEW: Parameter Discovery (--spider)**
```bash
sqlmap -u "http://target.com" --spider
```
What `--spider` does (ParamSpider-style):
- Queries Wayback Machine CDX API for historical URLs with parameters
- DOM mining from the target page for hidden parameters
- Filters out static resources (images, CSS, JS, etc.)
- Replaces parameter values with FUZZ placeholder
- Sorts URLs by SQLi priority (id, uid, cat = HIGH priority)
- Automatically adds all discovered URLs to scan queue

### **Combined: Full Auto + Spider**
```bash
sqlmap -u "http://target.com" --auto --spider
```
Maximum automation: discovers all parameters, then auto-scans each one with WAF bypass intelligence.

### Other Examples
```bash
# Auto mode with specific target
sqlmap -u "http://target.com/page?id=1" --auto --dbs

# Spider mode with forms discovery
sqlmap -u "http://target.com" --spider --forms --batch

# Auto mode with proxy
sqlmap -u "http://target.com/page?id=1" --auto --proxy="http://127.0.0.1:8080"

# Dump database with auto mode
sqlmap -u "http://target.com/page?id=1" --auto --dump
```

---

## WAF Detection & Bypass

The `--auto` flag includes DalFox-inspired WAF intelligence that detects and bypasses:

| WAF | Tamper Strategy | Delay |
|-----|----------------|-------|
| Cloudflare | charencode, randomcase, space2comment, between | 100ms |
| AWS WAF | space2comment, randomcase, charencode | 0ms |
| Akamai | charencode, randomcase, space2plus, percentage | 50ms |
| Imperva/Incapsula | charencode, randomcase, space2comment, between, equaltolike | 100ms |
| ModSecurity | modsecurityversioned, modsecurityzeroversioned, charencode, randomcase | 0ms |
| ModSecurity CRS | modsecurityversioned, modsecurityzeroversioned + OWASP-specific mutations | 0ms |
| Wordfence | charencode, randomcase, space2comment, between | 0ms |
| F5 BIG-IP ASM | charencode, randomcase, space2comment, between, modsecurityversioned | 50ms |
| Barracuda | charencode, randomcase, space2comment, percentage | 50ms |
| Safedog | charencode, randomcase, space2comment, percentage | 50ms |
| Alibaba Cloud | charencode, randomcase, space2comment, percentage | 50ms |
| Azure WAF | charencode, randomcase, space2comment, percentage | 50ms |
| ... | 28+ WAFs mapped | ... |

### WAF Detection Layers (DalFox-style)
1. **Passive Header Fingerprinting** - Zero extra requests, matches response headers
2. **Passive Body Fingerprinting** - Zero extra requests, matches body patterns
3. **Status Code Boost** - 403/406/429/503 responses boost detection confidence
4. **Provocation Probe** - One extra request with malicious payload to trigger WAF

### Progressive Escalation Stages
When WAF is detected but current tamper chain fails:
1. `charencode` (subtle)
2. `charencode + randomcase` (case randomization)
3. `charencode + randomcase + space2comment` (space replacement)
4. `+ between + equaltolike` (keyword substitution)
5. `+ chardoubleencode + percentage` (double encoding)
6. `+ equaltolike + randomcomments` (maximum bypass)

---

## Feature Comparison

| Feature | Original sqlmap | sqlmap-xbibz v3.0 |
|---------|----------------|-------------------|
| `--auto` mode | No | Yes (full automation) |
| `--spider` param discovery | No | Yes (Wayback + DOM) |
| WAF auto-detection | Basic (identYwaf) | Enhanced (DalFox-style 3-layer) |
| WAF auto-bypass | No | Yes (28+ WAF strategies) |
| Progressive escalation | No | Yes (6 stages) |
| Smart retry/backoff | No | Yes (exponential) |
| Param priority sorting | No | Yes (high/medium/low) |
| Termux non-root | Partial | Full support |
| curl one-line install | No | Yes |
| Auto .bashrc/.zshrc | No | Yes |

---

## Project Structure

```
sqlmap-xbibz/
  sqlmap.py                    # Main entry point (--auto/--spider hooks)
  sqlmapapi.py                 # API entry point
  install.sh                   # One-line curl installer
  uninstall.sh                 # Clean uninstaller
  lib/
    controller/
      auto.py                  # NEW: AutoEngine v3.0 (ParamSpider + DalFox logic)
      controller.py            # Modified: WAF handler hook
      checks.py                # WAF detection integration
    core/
      settings.py              # Modified: Xbibz Official branding + version
      optiondict.py            # Modified: --auto, --spider, autoMode options
    parse/
      cmdline.py               # Modified: --auto and --spider arguments
    request/
      basic.py                 # identYwaf integration (existing)
  thirdparty/
    identywaf/                 # WAF identification library (existing)
```

---

## Original sqlmap Features

sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester, and a broad range of switches including database fingerprinting, over data fetching from the database, accessing the underlying file system, and executing commands on the operating system via out-of-band connections.

To get a list of basic options and switches use:

    python sqlmap.py -h

To get a list of all options and switches use:

    python sqlmap.py -hh

You can find the [user's manual](https://github.com/sqlmapproject/sqlmap/wiki/Usage) for the original sqlmap features.

---

## Links

* Homepage: https://sqlmap.org
* Original Repository: https://github.com/sqlmapproject/sqlmap
* This Fork: https://github.com/XbibzOfficial777/sqlmap-xbibz
* User's manual: https://github.com/sqlmapproject/sqlmap/wiki
* TikTok: https://tiktok.com/@xbibzofficial

---

## Legal Disclaimer

Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
