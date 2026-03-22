#!/usr/bin/env python3
"""
cryptominer_detect.py
=====================
Detects cryptominer presence on Linux systems.
Supports both:
  - Live box analysis  (run directly on the target system, root recommended)
  - Dead box analysis  (point at a mounted filesystem image / chroot)

All IOC definitions (miner names, strings, pool indicators, filename
patterns, scan directories, etc.) live in iocs.yaml — edit that file
to add new miners without touching this script.

Usage:
  Live:    sudo python3 cryptominer_detect.py
  Deadbox: sudo python3 cryptominer_detect.py --root /mnt/evidence
  JSON:    sudo python3 cryptominer_detect.py --json report.json
  Custom:  sudo python3 cryptominer_detect.py --iocs /path/to/custom_iocs.yaml
"""

import argparse
import hashlib
import json
import math
import os
import re
import stat
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# YAML LOADER  (stdlib only — no PyYAML required)
# ─────────────────────────────────────────────────────────────────────────────

def _load_yaml(path: str) -> dict:
    """
    Minimal YAML loader for the subset used in iocs.yaml:
      - Nested mappings (key: value)
      - Block sequences (  - item)
      - Quoted strings, inline comments
    Falls back to PyYAML automatically if it is installed.
    """
    try:
        import yaml                        # type: ignore
        with open(path, "r") as f:
            return yaml.safe_load(f)
    except ImportError:
        pass                               # use built-in parser below

    with open(path, "r", encoding="utf-8") as f:
        raw_lines = f.readlines()

    def _strip_comment(s: str) -> str:
        in_sq = in_dq = False
        for i, ch in enumerate(s):
            if ch == "'" and not in_dq:
                in_sq = not in_sq
            elif ch == '"' and not in_sq:
                in_dq = not in_dq
            elif ch == "#" and not in_sq and not in_dq:
                return s[:i]
        return s

    def _unquote(s: str) -> str:
        s = s.strip()
        if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
            return s[1:-1]
        return s

    root: dict = {}
    # Stack entries: (indent_level, container)
    stack: list[tuple[int, Any]] = [(-1, root)]

    for idx, raw_line in enumerate(raw_lines):
        stripped = _strip_comment(raw_line.rstrip("\n")).rstrip()
        if not stripped.strip():
            continue

        indent  = len(stripped) - len(stripped.lstrip())
        content = stripped.lstrip()

        # Pop stack back to current indent
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()

        parent = stack[-1][1]

        if content.startswith("- "):
            value = _unquote(content[2:].strip())
            if isinstance(parent, list):
                parent.append(value)
        elif ":" in content:
            key, _, val_raw = content.partition(":")
            key     = key.strip()
            val_str = _unquote(val_raw.strip())
            if val_str == "":
                # Determine whether child is a list or dict by peeking ahead
                new_container: Any = {}
                for future_line in raw_lines[idx + 1:]:
                    fc = _strip_comment(future_line).rstrip().lstrip()
                    if fc:
                        new_container = [] if fc.startswith("- ") else {}
                        break
                if isinstance(parent, dict):
                    parent[key] = new_container
                stack.append((indent, new_container))
            else:
                # Attempt numeric conversion
                try:
                    typed_val: Any = int(val_str)
                except ValueError:
                    try:
                        typed_val = float(val_str)
                    except ValueError:
                        typed_val = val_str
                if isinstance(parent, dict):
                    parent[key] = typed_val

    return root


# ─────────────────────────────────────────────────────────────────────────────
# IOC CONFIG
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_IOC_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "iocs.yaml")


class IOCConfig:
    """
    Loads all detection signatures from iocs.yaml and exposes them as
    typed attributes.  The detector never references raw IOC strings
    directly — everything comes through this class.
    """

    def __init__(self, path: str = DEFAULT_IOC_FILE) -> None:
        self.path = path
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"IOC file not found: {path}\n"
                "Place iocs.yaml next to this script, or pass --iocs <path>.")
        self._raw = _load_yaml(path)
        self._compile()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _lst(self, key: str) -> list[str]:
        val = self._raw.get(key, [])
        return [str(v) for v in val if v is not None] if isinstance(val, list) else []

    def _flt(self, *keys: str, default: float) -> float:
        node: Any = self._raw
        for k in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(k)
            if node is None:
                return default
        try:
            return float(node)
        except (TypeError, ValueError):
            return default

    # ── compilation ───────────────────────────────────────────────────────────

    def _compile(self) -> None:
        self.process_names:     set[str]         = {s.lower() for s in self._lst("process_names")}
        self.miner_strings:     list[str]        = self._lst("miner_strings")
        self.pool_indicators:   list[str]        = self._lst("pool_indicators")
        self.scan_dirs:         list[str]        = self._lst("scan_dirs")
        self.persistence_paths: list[str]        = self._lst("persistence_paths")
        self.entropy_threshold: float            = self._flt("thresholds", "entropy",    default=7.0)
        self.cpu_medium:        float            = self._flt("thresholds", "cpu_medium", default=80.0)
        self.cpu_high:          float            = self._flt("thresholds", "cpu_high",   default=95.0)

        self.filename_patterns: list[re.Pattern] = []
        for p in self._lst("filename_patterns"):
            try:
                self.filename_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error as exc:
                print(f"  [!] Bad regex in iocs.yaml: {p!r} — {exc}")

    # ── metadata ──────────────────────────────────────────────────────────────

    @property
    def version(self) -> str:
        meta = self._raw.get("metadata", {})
        return str(meta.get("version", "unknown")) if isinstance(meta, dict) else "unknown"

    @property
    def last_updated(self) -> str:
        meta = self._raw.get("metadata", {})
        return str(meta.get("last_updated", "unknown")) if isinstance(meta, dict) else "unknown"

    def summary(self) -> str:
        return (
            f"IOC file       : {self.path}\n"
            f"Version        : {self.version}  (updated: {self.last_updated})\n"
            f"Process names  : {len(self.process_names)}\n"
            f"Miner strings  : {len(self.miner_strings)}\n"
            f"Pool indicators: {len(self.pool_indicators)}\n"
            f"Filename regex : {len(self.filename_patterns)}\n"
            f"Scan dirs      : {len(self.scan_dirs)}\n"
            f"Entropy thresh : {self.entropy_threshold}"
        )

    def all_content_iocs(self) -> list[str]:
        """Combined IOC list used for content scanning."""
        return self.miner_strings + self.pool_indicators


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"


def cprint(color: str, msg: str) -> None:
    print(f"{color}{msg}{RESET}")


def banner(ioc: IOCConfig) -> None:
    cprint(CYAN, r"""
  ___                  _        __  __ _                 ____       _            _
 / __| _ _  _  _ _ __ | |_ ___ |  \/  (_)_ _  ___ _ _  |  _ \  ___| |_ ___  ___| |_
| (__ | '_|| || | '_ \|  _/ _ \| |\/| | | ' \/ -_) '_| | | | |/ _ \ __/ _ \/ __| __|
 \___||_|   \_, | .__/ \__\___/|_|  |_|_|_||_\___|_|   |_| |_|\___/\__\___/\___|\__|
            |__/|_|
    Linux Cryptominer Detection Tool  |  Live & Dead-Box Analysis
""")
    cprint(GREEN, ioc.summary())


def sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return "unreadable"
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def file_entropy(path: str) -> float:
    try:
        with open(path, "rb") as f:
            sample = f.read(1024 * 256)
        return shannon_entropy(sample)
    except OSError:
        return 0.0


def grep_strings(path: str, patterns: list[str]) -> list[str]:
    """Return IOC strings found inside a file (binary-safe, case-insensitive)."""
    hits: list[str] = []
    try:
        with open(path, "rb") as f:
            content = f.read(1024 * 512).lower()
        for pat in patterns:
            if pat.lower().encode() in content:
                hits.append(pat)
    except OSError:
        pass
    return hits


def resolve(root: str, rel: str) -> str:
    rel = rel.lstrip("/")
    return os.path.join(root, rel) if root != "/" else "/" + rel


# ─────────────────────────────────────────────────────────────────────────────
# FINDING
# ─────────────────────────────────────────────────────────────────────────────

class Finding:
    def __init__(self, severity: str, category: str, description: str,
                 details: dict[str, Any] | None = None) -> None:
        self.severity    = severity
        self.category    = category
        self.description = description
        self.details     = details or {}
        self.timestamp   = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict:
        return {
            "severity":    self.severity,
            "category":    self.category,
            "description": self.description,
            "details":     self.details,
            "timestamp":   self.timestamp,
        }

    def print(self) -> None:
        colour = RED if self.severity == "HIGH" else (
                 YELLOW if self.severity == "MEDIUM" else CYAN)
        cprint(colour, f"  [{self.severity}] {self.category}: {self.description}")
        for k, v in self.details.items():
            print(f"         {k}: {v}")


# ─────────────────────────────────────────────────────────────────────────────
# DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

class CryptominerDetector:

    def __init__(self, ioc: IOCConfig, root: str = "/", live: bool = True) -> None:
        self.ioc      = ioc
        self.root     = root.rstrip("/") or "/"
        self.live     = live
        self.findings: list[Finding] = []

    def _add(self, severity: str, category: str, description: str, **details) -> None:
        f = Finding(severity, category, description, dict(details))
        self.findings.append(f)
        f.print()

    def _rpath(self, rel: str) -> str:
        return resolve(self.root, rel)

    # ── 1. Running processes (live only) ─────────────────────────────────────

    def check_processes(self) -> None:
        if not self.live:
            return
        cprint(BOLD, "\n[*] Checking running processes …")
        try:
            result = subprocess.run(["ps", "auxww"],
                                    capture_output=True, text=True, timeout=10)
        except Exception as e:
            cprint(YELLOW, f"  [!] Could not run ps: {e}")
            return

        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 11:
                continue
            pid  = parts[1]
            cpu  = parts[2]
            cmd  = " ".join(parts[10:]).lower()
            name = parts[10].split("/")[-1].lower()

            if name in self.ioc.process_names:
                self._add("HIGH", "Process", "Known miner binary running",
                          pid=pid, name=name, cpu_pct=cpu, cmdline=cmd[:120])
                continue

            for s in self.ioc.miner_strings:
                if s.lower() in cmd:
                    self._add("HIGH", "Process",
                              f"Miner string '{s}' in cmdline",
                              pid=pid, name=name, cmdline=cmd[:120])
                    break

            for p in self.ioc.pool_indicators:
                if p.lower() in cmd:
                    self._add("HIGH", "Process",
                              f"Pool indicator '{p}' in cmdline",
                              pid=pid, name=name, cmdline=cmd[:120])
                    break

            if (name.startswith("kworker") or name.startswith("kthread")) \
                    and "/" in parts[10]:
                self._add("MEDIUM", "Process",
                          "Process disguised as kernel thread with real path",
                          pid=pid, name=name, path=parts[10])

    # ── 2. Network connections (live only) ───────────────────────────────────

    def check_network(self) -> None:
        if not self.live:
            return
        cprint(BOLD, "\n[*] Checking network connections …")
        output = ""
        for cmd in (["ss", "-tunp"], ["netstat", "-tunp"]):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    output = r.stdout
                    break
            except (FileNotFoundError, Exception):
                continue
        if not output:
            cprint(YELLOW, "  [!] Neither ss nor netstat available")
            return

        for line in output.splitlines():
            ll = line.lower()
            for p in self.ioc.pool_indicators:
                if p.lower() in ll:
                    self._add("HIGH", "Network",
                              f"Connection matching pool indicator '{p}'",
                              line=line.strip()[:160])
                    break

    # ── 3. Filesystem scan ────────────────────────────────────────────────────

    def check_filesystem(self) -> None:
        cprint(BOLD, "\n[*] Scanning filesystem for miner artefacts …")
        scanned = 0
        for rel_dir in self.ioc.scan_dirs:
            scan_path = self._rpath(rel_dir)
            if not os.path.isdir(scan_path):
                continue
            for dirpath, dirnames, filenames in os.walk(scan_path, followlinks=False):
                if dirpath[len(scan_path):].count(os.sep) > 6:
                    dirnames.clear()
                    continue
                for fname in filenames:
                    scanned += 1
                    self._inspect_file(os.path.join(dirpath, fname))

        cprint(GREEN, f"  [+] Scanned {scanned} files across monitored directories")

    def _inspect_file(self, fpath: str) -> None:
        fname_l = os.path.basename(fpath).lower()

        for pat in self.ioc.filename_patterns:
            if pat.search(fname_l):
                self._add("HIGH", "File",
                          f"Filename matches miner pattern '{pat.pattern}'",
                          path=fpath, sha256=sha256(fpath))
                return

        try:
            st = os.lstat(fpath)
        except OSError:
            return
        if not stat.S_ISREG(st.st_mode):
            return

        hits = grep_strings(fpath, self.ioc.all_content_iocs())
        if hits:
            self._add("HIGH" if len(hits) >= 3 else "MEDIUM", "File",
                      "Miner IOC strings found inside file",
                      path=fpath, matches=", ".join(hits[:8]),
                      sha256=sha256(fpath))
            return

        if os.access(fpath, os.X_OK):
            ent = file_entropy(fpath)
            if ent >= self.ioc.entropy_threshold:
                self._add("MEDIUM", "File",
                          "Executable with suspiciously high entropy (packed?)",
                          path=fpath, entropy=f"{ent:.2f}", sha256=sha256(fpath))

    # ── 4. Persistence ────────────────────────────────────────────────────────

    def check_persistence(self) -> None:
        cprint(BOLD, "\n[*] Checking persistence locations …")
        for rel in self.ioc.persistence_paths:
            full = self._rpath(rel)
            if not os.path.exists(full):
                continue
            if os.path.isfile(full):
                self._scan_text_file(full)
            elif os.path.isdir(full):
                for fn in os.listdir(full):
                    fp = os.path.join(full, fn)
                    if os.path.isfile(fp):
                        self._scan_text_file(fp)

        # LD_PRELOAD is always an immediate red flag if non-empty
        preload = self._rpath("/etc/ld.so.preload")
        if os.path.isfile(preload):
            try:
                content = Path(preload).read_text(errors="replace").strip()
                if content:
                    self._add("HIGH", "Persistence",
                              "/etc/ld.so.preload is non-empty (rootkit indicator)",
                              content=content[:200])
            except OSError:
                pass

    def _scan_text_file(self, fpath: str) -> None:
        try:
            content = Path(fpath).read_text(errors="replace").lower()
        except OSError:
            return
        all_iocs = (self.ioc.miner_strings
                    + self.ioc.pool_indicators
                    + [p.pattern for p in self.ioc.filename_patterns])
        hits = [ioc for ioc in all_iocs if ioc.lower() in content]
        if hits:
            self._add("HIGH", "Persistence", "Miner IOC in persistence file",
                      path=fpath, matches=", ".join(hits[:8]))

    # ── 5. Systemd units ──────────────────────────────────────────────────────

    def check_systemd(self) -> None:
        cprint(BOLD, "\n[*] Checking systemd service units …")
        for rel_dir in ["/etc/systemd/system", "/usr/lib/systemd/system",
                         "/lib/systemd/system", "/run/systemd/system"]:
            d = self._rpath(rel_dir)
            if not os.path.isdir(d):
                continue
            for fname in os.listdir(d):
                if not fname.endswith((".service", ".timer", ".path")):
                    continue
                fp = os.path.join(d, fname)
                if os.path.isfile(fp):
                    self._scan_text_file(fp)
                for pat in self.ioc.filename_patterns:
                    if pat.search(fname.lower()):
                        self._add("HIGH", "Systemd",
                                  "Suspicious systemd unit name",
                                  unit=fname, path=fp)

    # ── 6. Crontabs ───────────────────────────────────────────────────────────

    def check_cron(self) -> None:
        cprint(BOLD, "\n[*] Checking crontab entries …")
        for rel in ["/etc/crontab", "/var/spool/cron",
                     "/var/spool/cron/crontabs", "/etc/cron.d"]:
            full = self._rpath(rel)
            if not os.path.exists(full):
                continue
            if os.path.isfile(full):
                self._scan_text_file(full)
            elif os.path.isdir(full):
                for fn in os.listdir(full):
                    fp = os.path.join(full, fn)
                    if os.path.isfile(fp):
                        self._scan_text_file(fp)

    # ── 7. Shell startup files ────────────────────────────────────────────────

    def check_shell_startup(self) -> None:
        cprint(BOLD, "\n[*] Checking shell startup / environment files …")
        files = ["/etc/profile", "/etc/bash.bashrc", "/etc/environment",
                 "/root/.bashrc", "/root/.bash_profile", "/root/.profile",
                 "/root/.zshrc"]
        passwd = self._rpath("/etc/passwd")
        if os.path.isfile(passwd):
            try:
                for line in Path(passwd).read_text(errors="replace").splitlines():
                    parts = line.split(":")
                    if len(parts) >= 6:
                        home = parts[5]
                        for rc in (".bashrc", ".bash_profile", ".profile",
                                   ".zshrc", ".config/autostart"):
                            files.append(os.path.join(home, rc))
            except OSError:
                pass
        for rel in files:
            full = self._rpath(rel) if rel.startswith("/") else rel
            if os.path.isfile(full):
                self._scan_text_file(full)

    # ── 8. /proc (live only) ─────────────────────────────────────────────────

    def check_proc(self) -> None:
        if not self.live:
            return
        cprint(BOLD, "\n[*] Inspecting /proc for hidden/deleted miners …")
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return

        for pid in pids:
            try:
                target = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                continue
            if "(deleted)" in target:
                try:
                    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes() \
                                  .replace(b"\x00", b" ").decode(errors="replace")
                except OSError:
                    cmdline = ""
                for s in self.ioc.miner_strings:
                    if s.lower() in target.lower() or s.lower() in cmdline.lower():
                        self._add("HIGH", "Process",
                                  "Running process with deleted exe (miner IOC)",
                                  pid=pid, exe=target, cmdline=cmdline[:120])
                        break
                else:
                    self._add("LOW", "Process",
                              "Running process with deleted executable (investigate)",
                              pid=pid, exe=target, cmdline=cmdline[:80])
            try:
                maps = Path(f"/proc/{pid}/maps").read_text(errors="replace").lower()
                for s in self.ioc.miner_strings:
                    if s.lower() in maps:
                        self._add("MEDIUM", "Process",
                                  f"Miner string '{s}' in /proc/{pid}/maps",
                                  pid=pid)
                        break
            except OSError:
                pass

    # ── 9. CPU abuse (live only) ──────────────────────────────────────────────

    def check_cpu_abuse(self) -> None:
        if not self.live:
            return
        cprint(BOLD, "\n[*] Checking for CPU-intensive processes …")
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid,ppid,user,%cpu,ni,stat,comm"],
                capture_output=True, text=True, timeout=10)
        except Exception:
            return

        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 7:
                continue
            pid, _, user, cpu, nice, _, comm = parts[:7]
            try:
                cpu_f = float(cpu)
            except ValueError:
                continue
            if cpu_f >= self.ioc.cpu_high:
                self._add("HIGH", "CPU",
                          f"Process consuming ≥{self.ioc.cpu_high:.0f}% CPU",
                          pid=pid, user=user, cpu_pct=cpu, comm=comm)
            elif cpu_f >= self.ioc.cpu_medium:
                self._add("MEDIUM", "CPU",
                          f"Process consuming ≥{self.ioc.cpu_medium:.0f}% CPU (possible miner)",
                          pid=pid, user=user, cpu_pct=cpu, nice=nice, comm=comm)

    # ── orchestration ─────────────────────────────────────────────────────────

    def run_all(self) -> None:
        mode = "LIVE" if self.live else f"DEAD-BOX (root={self.root})"
        cprint(BOLD, f"\nAnalysis mode : {mode}")
        cprint(BOLD, f"Started       : {datetime.utcnow().isoformat()}Z\n")

        self.check_processes()
        self.check_network()
        self.check_filesystem()
        self.check_persistence()
        self.check_systemd()
        self.check_cron()
        self.check_shell_startup()
        self.check_proc()
        self.check_cpu_abuse()

        self.print_summary()

    def print_summary(self) -> None:
        counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        cprint(BOLD, "\n" + "=" * 60)
        cprint(BOLD, "  SUMMARY")
        cprint(BOLD, "=" * 60)
        cprint(RED,    f"  HIGH   : {counts['HIGH']}")
        cprint(YELLOW, f"  MEDIUM : {counts['MEDIUM']}")
        cprint(CYAN,   f"  LOW    : {counts['LOW']}")
        cprint(GREEN,  f"  INFO   : {counts['INFO']}")
        cprint(BOLD,   f"  TOTAL  : {len(self.findings)}")
        cprint(BOLD, "=" * 60)

        if counts["HIGH"] > 0:
            cprint(RED, "\n  ⚠  HIGH-severity findings detected."
                        " Cryptominer activity is likely.")
        elif counts["MEDIUM"] > 0:
            cprint(YELLOW, "\n  ⚠  MEDIUM-severity findings detected."
                           " Further investigation recommended.")
        else:
            cprint(GREEN, "\n  ✓  No high-confidence miner indicators found.")

    def to_json(self) -> dict:
        return {
            "scan_mode":    "live" if self.live else "deadbox",
            "root":         self.root,
            "ioc_version":  self.ioc.version,
            "ioc_file":     self.ioc.path,
            "timestamp":    datetime.utcnow().isoformat() + "Z",
            "total":        len(self.findings),
            "findings":     [f.to_dict() for f in self.findings],
        }


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect cryptominers on Linux — live or dead-box")
    parser.add_argument(
        "--root", default="/",
        help="Filesystem root for dead-box analysis (e.g. /mnt/image). "
             "Default: / (live analysis)")
    parser.add_argument(
        "--iocs", default=DEFAULT_IOC_FILE, metavar="FILE",
        help=f"Path to IOC YAML file (default: iocs.yaml next to this script)")
    parser.add_argument(
        "--json", metavar="FILE",
        help="Write findings to a JSON report file")
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour output")
    args = parser.parse_args()

    if args.no_color:
        global RED, YELLOW, CYAN, GREEN, BOLD, RESET
        RED = YELLOW = CYAN = GREEN = BOLD = RESET = ""

    try:
        ioc = IOCConfig(path=args.iocs)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        raise SystemExit(1)

    banner(ioc)

    live = (args.root == "/")
    if live and os.geteuid() != 0:
        cprint(YELLOW, "[!] Warning: not running as root. "
                       "Some checks may be incomplete.\n")

    detector = CryptominerDetector(ioc=ioc, root=args.root, live=live)
    detector.run_all()

    if args.json:
        report = detector.to_json()
        with open(args.json, "w") as jf:
            json.dump(report, jf, indent=2)
        cprint(GREEN, f"\n  [+] JSON report written to: {args.json}")


if __name__ == "__main__":
    main()
