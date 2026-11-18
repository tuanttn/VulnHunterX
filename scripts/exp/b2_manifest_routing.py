# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""B2 check: every alert of a B3a manifest resolves to exactly one family policy.

Reads a manifest (JSONL, outside git), turns each row into the metadata the
benchmark harness hands to ``entry_to_finding`` and asks the policy registry
which family owns it. A row that resolves to no family (legacy path), to two
families (overlap) or that carries an excluded rule is a failure.

Labels are not read: the entry label is a placeholder, and only the manifest
fields a model may see (message, CWE ids and tags, data flow, rule, file, line)
are used. The result is deterministic and makes no model call.

    python -m scripts.exp.b2_manifest_routing <manifest.jsonl>
    python -m scripts.exp.b2_manifest_routing <manifest.jsonl> \\
        --expect sql_injection_java=479 --expect command_injection_java=131

Exit code 0 when every row resolves to one family (and every ``--expect`` count
matches); 1 otherwise; 2 on unreadable input.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from benchmarks.adapters.ground_truth import LABEL_TP, GroundTruthEntry
from benchmarks.approaches.base import entry_to_finding
from vuln_hunter_x.verification.policy.loader import PolicyOverlapError, load_policy_registry

EXCLUDED_RULES = frozenset({"java/exec-tainted-environment", "java/relative-path-command"})
LEGACY = "legacy"
OVERLAP = "OVERLAP"
EXCLUDED = "EXCLUDED_RULE"


def manifest_row_to_entry(row: dict) -> GroundTruthEntry:
    """The entry the harness would build from a manifest row, label-free.

    Only fields a model may see are copied. ``label``, ``source_case``,
    ``family`` and the other bookkeeping fields of the manifest are left out.
    """
    return GroundTruthEntry(
        id=str(row["alert_id"]),
        source_dataset="manifest",
        cwe_id="",
        rule_id=str(row["rule_id"]),
        file_path=str(row["file"]),
        function_name="",
        start_line=int(row["line"]),
        lang="java",
        label=LABEL_TP,  # placeholder: the manifest label is never read here
        code_snippet="",
        metadata={
            "message": row.get("message", ""),
            "cwe_ids": row.get("cwe_ids", []),
            "cwe_tags_raw": row.get("cwe_tags_raw", []),
            "dataflow_path": row.get("data_flow", []),
        },
        sink_line=int(row["line"]),
    )


def route_counts(rows: Sequence[dict]) -> collections.Counter[str]:
    """Count rows per owning family (``legacy``, ``OVERLAP`` and ``EXCLUDED_RULE`` included)."""
    registry = load_policy_registry()
    counts: collections.Counter[str] = collections.Counter()
    for row in rows:
        if row.get("rule_id") in EXCLUDED_RULES:
            counts[EXCLUDED] += 1
            continue
        finding = entry_to_finding(manifest_row_to_entry(row))
        try:
            policy = registry.resolve_family(
                cwe_ids=finding.cwe_ids, rule_id=finding.rule_id, lang=finding.lang
            )
        except PolicyOverlapError:
            counts[OVERLAP] += 1
            continue
        counts[policy.family if policy else LEGACY] += 1
    return counts


def read_manifest(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: not JSON ({exc.msg})") from exc
    return rows


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--expect",
        action="append",
        default=[],
        metavar="FAMILY=N",
        help="require exactly N rows for FAMILY (repeatable)",
    )
    args = parser.parse_args(argv)
    try:
        rows = read_manifest(args.manifest)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    counts = route_counts(rows)
    print(f"entries {len(rows)}")
    for name, count in sorted(counts.items()):
        print(f"{name} {count}")

    failed = False
    for bad in (LEGACY, OVERLAP, EXCLUDED):
        if counts.get(bad):
            print(f"FAIL: {counts[bad]} row(s) resolve to {bad}", file=sys.stderr)
            failed = True
    for item in args.expect:
        family, _, number = item.partition("=")
        if not number.isdigit() or counts.get(family, 0) != int(number):
            print(f"FAIL: expected {family}={number}, got {counts.get(family, 0)}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
