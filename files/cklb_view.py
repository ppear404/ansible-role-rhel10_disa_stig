#!/usr/bin/env python3
"""Display selected CKLB rule fields as a wrapped terminal table."""

import argparse
import json
from pathlib import Path
import shutil
import sys
import textwrap


# field: (display heading, preferred width). Add column presets here.
COLUMNS = {
    "group_id": ("V-ID", 10),
    "rule_title": ("Rule Name", 38),
    "status": ("Status", 16),
    "fix_text": ("Fix Text", 65),
    "severity": ("Severity", 10),
    "rule_version": ("Rule Version", 20),
    "finding_details": ("Finding Details", 60),
    "comments": ("Comments", 40),
}
DEFAULT_COLUMNS = "group_id,rule_title,status,fix_text"
STATUSES = {"open", "not_reviewed", "not_a_finding", "not_applicable"}


def normalize_status(value):
    return "_".join(value.strip().lower().replace("_", " ").replace("-", " ").split())


def parse_status(value):
    status = normalize_status(value)
    if status not in STATUSES:
        raise argparse.ArgumentTypeError(
            "status must be Open, Not Reviewed, Not a Finding, or Not Applicable"
        )
    return status


def load_rules(path):
    """Read every STIG in a checklist, rejecting malformed rule containers."""
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("stigs"), list):
        raise ValueError("expected an object containing a 'stigs' list")
    rules = []
    for stig in data["stigs"]:
        if not isinstance(stig, dict) or not isinstance(stig.get("rules"), list):
            raise ValueError("each STIG must contain a 'rules' list")
        if not all(isinstance(rule, dict) for rule in stig["rules"]):
            raise ValueError("each rule must be an object")
        rules.extend(stig["rules"])
    return rules


def cell_text(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def wrapped_lines(value, width):
    # Preserve explicit newlines, blank lines, and indentation in fix commands.
    lines = []
    for line in cell_text(value).expandtabs(4).split("\n"):
        lines.extend(textwrap.wrap(line, width, replace_whitespace=False) or [""])
    return lines


def print_table(rules, columns, total_width):
    headings, widths = zip(*(COLUMNS.get(key, (key, 30)) for key in columns))
    widths = list(widths)
    available = max(len(columns) * 8, total_width - (3 * len(columns) + 1))
    while sum(widths) > available:
        widest = max(range(len(widths)), key=widths.__getitem__)
        widths[widest] -= 1
    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def print_row(values):
        cells = [wrapped_lines(value, width) for value, width in zip(values, widths)]
        for index in range(max(map(len, cells))):
            print("| " + " | ".join(
                (cell[index] if index < len(cell) else "").ljust(width)
                for cell, width in zip(cells, widths)
            ) + " |")

    print(border)
    print_row(headings)
    print(border)
    for rule in rules:
        print_row([rule.get(key, "") for key in columns])
        print(border)


def main():
    column_help = "\n".join(
        f"  {field:<18} {heading}" for field, (heading, _) in COLUMNS.items()
    )
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""Available statuses:
  Open, Not Reviewed, Not a Finding, Not Applicable
  Matching ignores case and accepts spaces, underscores, or hyphens.
  Repeat --status to match any selected status; omit it to show all rules.

Column presets:
{column_help}
  Any other field present in the checklist's rules can also be selected.

Examples:
  %(prog)s files/checklist.cklb
  %(prog)s files/*.cklb --status Open
  %(prog)s files/*.cklb --status Open --status "Not Reviewed"
  %(prog)s files/*.cklb --columns group_id,rule_title,status,severity
  %(prog)s files/*.cklb --width 160 | less -S
""",
    )
    parser.add_argument("files", nargs="+", type=Path, help="one or more .cklb files")
    parser.add_argument(
        "--status", action="append", type=parse_status, metavar="STATUS",
        help="show only this status; repeat to match any selected status "
             '(e.g. --status Open --status "Not Reviewed")',
    )
    parser.add_argument(
        "--columns", default=DEFAULT_COLUMNS,
        help="comma-separated rule field keys; any CKLB rule field is supported "
             "(default: %(default)s)",
    )
    parser.add_argument(
        "--width", type=int, default=shutil.get_terminal_size((140, 24)).columns,
        help="table width in characters (default: terminal width, or 140 when unavailable)",
    )
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    args = parser.parse_args()
    columns = [key.strip() for key in args.columns.split(",") if key.strip()]
    if not columns:
        parser.error("--columns must contain at least one field")
    if args.width < 20:
        parser.error("--width must be at least 20")
    failed = False
    for path in args.files:
        try:
            rules = load_rules(path)
            known_fields = set(COLUMNS).union(*(rule.keys() for rule in rules))
            unknown = set(columns) - known_fields
            if unknown:
                raise ValueError("unknown columns: " + ", ".join(sorted(unknown)))
        except (OSError, ValueError) as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            failed = True
            continue
        total = len(rules)
        if args.status:
            rules = [rule for rule in rules
                     if normalize_status(str(rule.get("status", ""))) in args.status]
        count = f"{len(rules)} of {total} rules" if args.status else f"{total} rules"
        print(f"\n{path} ({count})")
        print_table(rules, columns, args.width)
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Permit piping a large checklist into tools such as head.
        sys.stdout = open('/dev/null', 'w')
        sys.exit(0)
