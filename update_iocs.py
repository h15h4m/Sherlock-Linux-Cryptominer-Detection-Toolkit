#!/usr/bin/env python3
"""
update_iocs.py
==============
CLI helper for managing iocs.yaml — add, remove, or list IOC entries
without hand-editing the YAML file.

Commands:
  list      Show all current IOC entries (optionally filtered by section)
  add       Add one or more entries to a section
  remove    Remove an entry from a section
  validate  Check iocs.yaml for syntax / regex errors
  bump      Increment the version number and update last_updated

Sections:
  process_names      Known miner binary / process names
  miner_strings      Strings matched inside files and cmdlines
  pool_indicators    Mining pool domains, IPs, port strings
  filename_patterns  Regex patterns matched against filenames
  scan_dirs          Directories to scan
  persistence_paths  Persistence locations to inspect

Examples:
  python3 update_iocs.py list
  python3 update_iocs.py list --section pool_indicators
  python3 update_iocs.py add --section process_names --entry "newminer"
  python3 update_iocs.py add --section pool_indicators --entry "evilpool.io" ":9999"
  python3 update_iocs.py remove --section miner_strings --entry "coinminer"
  python3 update_iocs.py validate
  python3 update_iocs.py bump
"""

import argparse
import os
import re
import sys
from datetime import date
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_IOC_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "iocs.yaml")

VALID_LIST_SECTIONS = {
    "process_names",
    "miner_strings",
    "pool_indicators",
    "filename_patterns",
    "scan_dirs",
    "persistence_paths",
}

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"


def cprint(color: str, msg: str) -> None:
    print(f"{color}{msg}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# Low-level YAML helpers
# (operate directly on the raw text to preserve comments & formatting)
# ─────────────────────────────────────────────────────────────────────────────

def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _write(path: str, content: str) -> None:
    Path(path).write_text(content, encoding="utf-8")


def _find_section_block(text: str, section: str) -> tuple[int, int]:
    """
    Return (start, end) line indices (0-based, end exclusive) of the
    block-sequence body under `section:`.
    Raises ValueError if the section is not found or has no list body.
    """
    lines = text.splitlines(keepends=True)
    section_re = re.compile(r"^" + re.escape(section) + r"\s*:", re.IGNORECASE)
    start_idx = None
    for i, line in enumerate(lines):
        if section_re.match(line.lstrip()):
            # Make sure it's actually a top-level key (no leading spaces beyond
            # what exists uniformly — just check it's not heavily indented)
            indent = len(line) - len(line.lstrip())
            if indent <= 2:
                start_idx = i
                break
    if start_idx is None:
        raise ValueError(f"Section '{section}' not found in IOC file.")

    # Collect subsequent lines that are list items or blank/comment
    block_start = start_idx + 1
    block_end   = block_start
    item_indent: int | None = None
    for j in range(block_start, len(lines)):
        stripped = lines[j].lstrip()
        current_indent = len(lines[j]) - len(lines[j].lstrip())
        if not stripped or stripped.startswith("#"):
            block_end = j + 1
            continue
        if stripped.startswith("- "):
            if item_indent is None:
                item_indent = current_indent
            if current_indent == item_indent:
                block_end = j + 1
                continue
        # Reached a new top-level key or un-indented content
        break

    return (block_start, block_end)


def _get_entries(text: str, section: str) -> list[str]:
    """Return the list of values under a block-sequence section."""
    lines = text.splitlines(keepends=True)
    start, end = _find_section_block(text, section)
    entries: list[str] = []
    for line in lines[start:end]:
        stripped = line.strip()
        if stripped.startswith("- "):
            val = stripped[2:].strip()
            # Strip inline comment
            val = re.sub(r"\s+#.*$", "", val)
            # Unquote
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            if val:
                entries.append(val)
    return entries


def _entry_exists(text: str, section: str, entry: str) -> bool:
    return entry.lower() in [e.lower() for e in _get_entries(text, section)]


def _add_entry(text: str, section: str, entry: str) -> str:
    """Insert entry as the last item in the section block."""
    lines = text.splitlines(keepends=True)
    _, end = _find_section_block(text, section)

    # Detect indent used by existing items; default to 2 spaces
    item_indent = "  "
    start, _ = _find_section_block(text, section)
    for line in lines[start:end]:
        if line.lstrip().startswith("- "):
            item_indent = " " * (len(line) - len(line.lstrip()))
            break

    # Quote the entry if it contains special YAML characters
    needs_quoting = any(c in entry for c in ('#', ':', '"', "'", '{', '}', '[', ']'))
    formatted = f'"{entry}"' if needs_quoting else entry

    new_line = f"{item_indent}- {formatted}\n"

    # Insert before the blank line / next section that ends the block
    insert_at = end
    # Walk back past trailing blank lines so the new entry sits just after
    # the last real item
    while insert_at > start and lines[insert_at - 1].strip() == "":
        insert_at -= 1

    lines.insert(insert_at, new_line)
    return "".join(lines)


def _remove_entry(text: str, section: str, entry: str) -> tuple[str, bool]:
    """Remove entry from section. Returns (new_text, found)."""
    lines = text.splitlines(keepends=True)
    start, end = _find_section_block(text, section)
    removed = False
    new_lines: list[str] = []
    for i, line in enumerate(lines):
        if start <= i < end and line.lstrip().startswith("- "):
            val = line.lstrip()[2:].strip()
            val = re.sub(r"\s+#.*$", "", val)
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            if val.lower() == entry.lower():
                removed = True
                continue   # skip this line
        new_lines.append(line)
    return "".join(new_lines), removed


def _bump_version(text: str) -> str:
    """Increment patch version and set last_updated to today."""
    today = date.today().isoformat()

    def _inc_patch(m: re.Match) -> str:
        ver = m.group(1)
        parts = ver.split(".")
        try:
            parts[-1] = str(int(parts[-1]) + 1)
        except (ValueError, IndexError):
            parts.append("1")
        return f'version: "{".".join(parts)}"'

    text = re.sub(r'version:\s*["\']?([\d.]+)["\']?', _inc_patch, text)
    text = re.sub(r'last_updated:\s*["\']?[\d\-]+["\']?',
                  f'last_updated: "{today}"', text)
    return text


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_list(args: argparse.Namespace) -> None:
    text = _read(args.iocs)
    sections = [args.section] if args.section else sorted(VALID_LIST_SECTIONS)

    for section in sections:
        try:
            entries = _get_entries(text, section)
        except ValueError as e:
            cprint(YELLOW, f"  [!] {e}")
            continue
        cprint(BOLD, f"\n── {section} ({len(entries)} entries) ──")
        for e in sorted(entries):
            print(f"    {e}")

    print()


def cmd_add(args: argparse.Namespace) -> None:
    if args.section not in VALID_LIST_SECTIONS:
        cprint(RED, f"Unknown section '{args.section}'. "
                    f"Valid: {', '.join(sorted(VALID_LIST_SECTIONS))}")
        sys.exit(1)

    if args.section == "filename_patterns":
        for entry in args.entries:
            try:
                re.compile(entry, re.IGNORECASE)
            except re.error as exc:
                cprint(RED, f"Invalid regex '{entry}': {exc}")
                sys.exit(1)

    text = _read(args.iocs)
    added = []
    skipped = []

    for entry in args.entries:
        if _entry_exists(text, args.section, entry):
            skipped.append(entry)
        else:
            text = _add_entry(text, args.section, entry)
            added.append(entry)

    if not args.dry_run:
        if added:
            if not args.no_bump:
                text = _bump_version(text)
            _write(args.iocs, text)

    for e in added:
        mark = "[DRY-RUN] " if args.dry_run else ""
        cprint(GREEN, f"  {mark}+ Added   [{args.section}] {e}")
    for e in skipped:
        cprint(YELLOW, f"  ~ Skipped [{args.section}] {e}  (already exists)")

    if added and not args.dry_run:
        cprint(BOLD, f"\n  Saved → {args.iocs}")


def cmd_remove(args: argparse.Namespace) -> None:
    if args.section not in VALID_LIST_SECTIONS:
        cprint(RED, f"Unknown section '{args.section}'.")
        sys.exit(1)

    text = _read(args.iocs)
    text, found = _remove_entry(text, args.section, args.entry)

    if not found:
        cprint(YELLOW, f"  Entry '{args.entry}' not found in [{args.section}].")
        sys.exit(1)

    if not args.dry_run:
        if not args.no_bump:
            text = _bump_version(text)
        _write(args.iocs, text)
        cprint(GREEN, f"  - Removed [{args.section}] {args.entry}")
        cprint(BOLD, f"\n  Saved → {args.iocs}")
    else:
        cprint(GREEN, f"  [DRY-RUN] Would remove [{args.section}] {args.entry}")


def cmd_validate(args: argparse.Namespace) -> None:
    cprint(BOLD, f"\nValidating {args.iocs} …\n")
    errors = 0
    warnings = 0

    # 1. Parse
    try:
        from cryptominer_detect import IOCConfig  # type: ignore
        ioc = IOCConfig(path=args.iocs)
    except ImportError:
        # Fallback: parse inline
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            from cryptominer_detect import IOCConfig
            ioc = IOCConfig(path=args.iocs)
        except Exception as e:
            cprint(RED, f"  [ERROR] Cannot import IOCConfig: {e}")
            errors += 1
            ioc = None

    if ioc is None:
        cprint(RED, "\nValidation FAILED — could not load IOC config.")
        sys.exit(1)

    # 2. Regex patterns
    text = _read(args.iocs)
    raw_patterns = _get_entries(text, "filename_patterns")
    for p in raw_patterns:
        try:
            re.compile(p, re.IGNORECASE)
            cprint(GREEN, f"  [OK]  regex: {p}")
        except re.error as exc:
            cprint(RED, f"  [ERR] regex: {p}  → {exc}")
            errors += 1

    # 3. Duplicate detection
    for section in VALID_LIST_SECTIONS:
        try:
            entries = _get_entries(text, section)
        except ValueError:
            continue
        seen: set[str] = set()
        for e in entries:
            el = e.lower()
            if el in seen:
                cprint(YELLOW, f"  [WARN] Duplicate in [{section}]: {e}")
                warnings += 1
            seen.add(el)

    # 4. Empty sections
    for section in VALID_LIST_SECTIONS:
        try:
            entries = _get_entries(text, section)
            if not entries:
                cprint(YELLOW, f"  [WARN] Section '{section}' is empty")
                warnings += 1
            else:
                cprint(GREEN, f"  [OK]  [{section}] — {len(entries)} entries")
        except ValueError as exc:
            cprint(RED, f"  [ERR] {exc}")
            errors += 1

    print()
    if errors:
        cprint(RED, f"Validation FAILED  ({errors} error(s), {warnings} warning(s))")
        sys.exit(1)
    elif warnings:
        cprint(YELLOW, f"Validation PASSED with {warnings} warning(s)")
    else:
        cprint(GREEN, "Validation PASSED — no issues found.")


def cmd_bump(args: argparse.Namespace) -> None:
    text = _read(args.iocs)
    text = _bump_version(text)
    if not args.dry_run:
        _write(args.iocs, text)
        cprint(GREEN, f"  Version bumped and last_updated set to today → {args.iocs}")
    else:
        cprint(GREEN, "  [DRY-RUN] Would bump version and update last_updated")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manage iocs.yaml — add, remove, list, or validate IOC entries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    parser.add_argument(
        "--iocs", default=DEFAULT_IOC_FILE, metavar="FILE",
        help="Path to iocs.yaml (default: iocs.yaml next to this script)")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview changes without writing to disk")
    parser.add_argument(
        "--no-bump", action="store_true",
        help="Skip automatic version increment on add/remove")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # list
    p_list = sub.add_parser("list", help="List IOC entries")
    p_list.add_argument(
        "--section", choices=sorted(VALID_LIST_SECTIONS), default=None,
        help="Only show this section (default: show all)")

    # add
    p_add = sub.add_parser("add", help="Add entries to a section")
    p_add.add_argument(
        "--section", required=True, choices=sorted(VALID_LIST_SECTIONS),
        help="Target section")
    p_add.add_argument(
        "--entry", dest="entries", nargs="+", required=True, metavar="ENTRY",
        help="One or more values to add")

    # remove
    p_rem = sub.add_parser("remove", help="Remove an entry from a section")
    p_rem.add_argument(
        "--section", required=True, choices=sorted(VALID_LIST_SECTIONS),
        help="Target section")
    p_rem.add_argument(
        "--entry", required=True, metavar="ENTRY",
        help="Value to remove (case-insensitive)")

    # validate
    sub.add_parser("validate", help="Check iocs.yaml for errors")

    # bump
    sub.add_parser("bump", help="Bump version and set last_updated to today")

    args = parser.parse_args()

    dispatch = {
        "list":     cmd_list,
        "add":      cmd_add,
        "remove":   cmd_remove,
        "validate": cmd_validate,
        "bump":     cmd_bump,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
