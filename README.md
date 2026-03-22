# 🔍 Sherlock - Linux Cryptominer Detection Toolkit

A forensic toolkit for detecting cryptominer infections on Linux systems. Supports both **live box analysis** (running system) and **dead box analysis** (mounted forensic image or chroot). All detection signatures are managed through an external YAML file — no code changes needed to add new miners.

---

## 📋 Table of Contents

- [Features](#-features)
- [File Structure](#-file-structure)
- [Requirements](#-requirements)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
  - [Live Analysis](#live-analysis)
  - [Dead Box Analysis](#dead-box-analysis)
  - [JSON Report Output](#json-report-output)
- [Managing IOCs](#-managing-iocs)
  - [Adding New Miners](#adding-new-miners)
  - [Removing Entries](#removing-entries)
  - [Listing Entries](#listing-entries)
  - [Validating the IOC File](#validating-the-ioc-file)
  - [Editing iocs.yaml Directly](#editing-iocsyaml-directly)
- [Detection Coverage](#-detection-coverage)
- [Severity Levels](#-severity-levels)
- [JSON Report Schema](#-json-report-schema)
- [Tuning & Configuration](#-tuning--configuration)
- [Limitations](#-limitations)
- [License](#-license)

---

## ✨ Features

- **Live analysis** — inspects running processes, active network connections, `/proc`, and CPU usage in real time
- **Dead box analysis** — point at any mounted filesystem root; no agent required on the target
- **External IOC management** — all miner names, strings, pool domains, and filename patterns live in `iocs.yaml`; update signatures without touching Python
- **`update_iocs.py` CLI** — add, remove, list, and validate IOC entries from the command line with automatic version tracking
- **Zero third-party dependencies** — pure Python 3.8+ stdlib (PyYAML is used automatically if installed, but not required)
- **JSON reports** — machine-readable output embeds the IOC version used, suitable for SIEM ingestion or ticketing workflows
- **Entropy analysis** — flags executables with suspiciously high Shannon entropy that may be packed or obfuscated miners
- **Persistence detection** — checks crontabs, systemd units, shell startup files, and `/etc/ld.so.preload` (rootkit indicator)

---

## 📁 File Structure

```
.
├── cryptominer_detect.py   # Main detection script
├── iocs.yaml               # IOC definitions — edit this to add/update signatures
├── update_iocs.py          # CLI helper to manage iocs.yaml
└── README.md
```

All three files must live in the same directory.

---

## ⚙️ Requirements

| Requirement | Details |
|---|---|
| Python | 3.8 or later |
| OS | Linux (any distribution) |
| Privileges | Root recommended for live analysis; not required for dead box |
| Dependencies | None (PyYAML optional but auto-used if present) |

Install PyYAML for more robust YAML parsing (optional):

```bash
pip install pyyaml
```

---

## 🚀 Quick Start

```bash
# Clone or download the toolkit
git clone https://github.com/your-org/cryptominer-detect.git
cd cryptominer-detect

# Run a live analysis (root recommended)
sudo python3 cryptominer_detect.py

# Save findings to a JSON report
sudo python3 cryptominer_detect.py --json report.json
```

---

## 📖 Usage

### Live Analysis

Runs directly on the target system. Inspects running processes, network connections, `/proc`, and CPU usage in addition to filesystem and persistence checks.

```bash
sudo python3 cryptominer_detect.py
```

> **Note:** Running without root may miss process details, `/proc/*/maps` entries, and certain system files. A warning is printed if not root.

### Dead Box Analysis

Point the script at the root of a mounted forensic image or chroot. All live checks (process list, network, `/proc`, CPU) are automatically skipped.

```bash
# Mount the image first
sudo mount -o ro /path/to/disk.img /mnt/evidence

# Run dead box analysis
sudo python3 cryptominer_detect.py --root /mnt/evidence
```

### Custom IOC File

```bash
sudo python3 cryptominer_detect.py --iocs /path/to/custom_iocs.yaml
```

### JSON Report Output

```bash
sudo python3 cryptominer_detect.py --json findings.json
```

The IOC file version is embedded in every report, so you always know which signature set produced a given result.

### Disable Colour Output

Useful when piping to a log file or running in CI.

```bash
sudo python3 cryptominer_detect.py --no-color | tee scan.log
```

### Full Options Reference

```
usage: cryptominer_detect.py [-h] [--root DIR] [--iocs FILE] [--json FILE] [--no-color]

  --root DIR    Filesystem root for dead-box analysis (default: /, live mode)
  --iocs FILE   Path to IOC YAML file (default: iocs.yaml next to this script)
  --json FILE   Write findings to a JSON report file
  --no-color    Disable ANSI colour output
```

---

## 🛠 Managing IOCs

All detection signatures are stored in `iocs.yaml`. Use `update_iocs.py` to manage them — it preserves comments and formatting and automatically bumps the version on every change.

### Adding New Miners

```bash
# Add a process/binary name
python3 update_iocs.py add --section process_names --entry "newminer"

# Add multiple entries at once
python3 update_iocs.py add --section pool_indicators \
    --entry "evilpool.io" "stratum.evilpool.io" ":9998"

# Add a string to search for inside files and cmdlines
python3 update_iocs.py add --section miner_strings --entry "newalgo"

# Add a filename regex pattern
python3 update_iocs.py add --section filename_patterns --entry "newminer.*bin"

# Preview changes without saving
python3 update_iocs.py --dry-run add --section process_names --entry "testminer"
```

### Removing Entries

```bash
python3 update_iocs.py remove --section pool_indicators --entry "evilpool.io"
```

### Listing Entries

```bash
# Show all sections
python3 update_iocs.py list

# Show one section
python3 update_iocs.py list --section pool_indicators
```

### Validating the IOC File

Checks for YAML parse errors, invalid regex patterns, duplicate entries, and empty sections.

```bash
python3 update_iocs.py validate
```

### Bumping the Version Manually

`add` and `remove` bump the patch version automatically. To bump manually (e.g. after hand-editing):

```bash
python3 update_iocs.py bump
```

### Full `update_iocs.py` Reference

```
Commands:
  list      Show all IOC entries (--section to filter)
  add       Add one or more entries (--section, --entry)
  remove    Remove an entry (--section, --entry)
  validate  Check iocs.yaml for syntax and regex errors
  bump      Increment version and set last_updated to today

Global flags:
  --iocs FILE    Path to iocs.yaml (default: next to this script)
  --dry-run      Preview changes without writing to disk
  --no-bump      Skip automatic version increment on add/remove
```

### Editing `iocs.yaml` Directly

You can also hand-edit `iocs.yaml` — it is plain, commented YAML. Run `validate` afterwards to catch any mistakes.

**Sections in `iocs.yaml`:**

| Section | Description |
|---|---|
| `metadata` | Version and last_updated tracking |
| `thresholds` | Entropy cutoff, CPU alert percentages |
| `scan_dirs` | Directories walked during filesystem scan |
| `persistence_paths` | Files/dirs checked for persistence |
| `process_names` | Known miner binary/process names |
| `miner_strings` | Strings matched in file contents and cmdlines |
| `filename_patterns` | Regex patterns matched against filenames |
| `pool_indicators` | Pool domains, IPs, port strings, URL fragments |

---

## 🔬 Detection Coverage

| Check | Live | Dead Box | What It Looks For |
|---|:---:|:---:|---|
| Running processes | ✅ | ❌ | Name match, IOC strings in cmdline, fake kworker/kthread |
| Network connections | ✅ | ❌ | Active connections to known pool domains/ports |
| Filesystem scan | ✅ | ✅ | Filename patterns, IOC strings inside files, high-entropy executables |
| Persistence — crontabs | ✅ | ✅ | IOC strings in all crontab files |
| Persistence — systemd | ✅ | ✅ | Suspicious unit names and contents |
| Persistence — shell startup | ✅ | ✅ | `.bashrc`, `.profile`, `/etc/profile.d/*`, etc. |
| LD_PRELOAD rootkit | ✅ | ✅ | Non-empty `/etc/ld.so.preload` |
| /proc — deleted executables | ✅ | ❌ | Running processes whose binary has been deleted |
| /proc — memory maps | ✅ | ❌ | IOC strings in `/proc/*/maps` |
| CPU abuse | ✅ | ❌ | Processes consuming ≥ configured CPU threshold |

---

## 🚦 Severity Levels

| Level | Meaning | Recommended Action |
|---|---|---|
| `HIGH` | Direct name, string, or pool match | Treat as confirmed; isolate and investigate immediately |
| `MEDIUM` | High entropy binary, high CPU, suspicious cmdline | Investigate — likely malicious but needs confirmation |
| `LOW` | Deleted executable, borderline indicator | Review manually; may be benign |
| `INFO` | Informational only | No action required |

---

## 📄 JSON Report Schema

```jsonc
{
  "scan_mode":   "live" | "deadbox",
  "root":        "/",
  "ioc_version": "1.0.0",          // version from iocs.yaml at scan time
  "ioc_file":    "/path/to/iocs.yaml",
  "timestamp":   "2026-03-22T10:00:00Z",
  "total":       3,
  "findings": [
    {
      "severity":    "HIGH",
      "category":    "Process",
      "description": "Known miner binary running",
      "details": {
        "pid":     "1337",
        "name":    "xmrig",
        "cpu_pct": "98.2",
        "cmdline": "xmrig --config /tmp/.cfg"
      },
      "timestamp": "2026-03-22T10:00:01Z"
    }
  ]
}
```

---

## ⚖️ Tuning & Configuration

Edit the `thresholds` block in `iocs.yaml` to adjust sensitivity:

```yaml
thresholds:
  entropy:    7.0   # Raise to reduce false positives on packed binaries
  cpu_medium: 80.0  # % CPU to trigger MEDIUM alert
  cpu_high:   95.0  # % CPU to trigger HIGH alert
```

To extend the scan to additional directories, add them to `scan_dirs`:

```yaml
scan_dirs:
  - /data/custom_apps
  - /mnt/nfs_share
```

---

## ⚠️ Limitations

- **No kernel-level visibility** — rootkits that hide processes from `ps` or files from the VFS will not be detected without a kernel module or memory image.
- **Signature-based** — novel miners with no overlapping IOCs will not be flagged; entropy analysis provides partial coverage for packed/obfuscated samples.
- **Dead box CPU/network checks are skipped** — those checks require a live system.
- **Regex filename patterns** are matched against the basename only, not the full path.
- **No automatic IOC feed** — signatures must be updated manually using `update_iocs.py` or by hand-editing `iocs.yaml`. Consider integrating with a threat intel feed for automated updates.

---

## 📜 License

This project is released under the [MIT License](LICENSE).

---

> **Disclaimer:** This tool is intended for authorised security investigations and incident response only. Always obtain proper written authorisation before running forensic tools on any system you do not own.
