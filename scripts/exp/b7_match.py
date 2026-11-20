# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""B7 matching: CodeQL alerts against RealVuln ground-truth locations (plan v3.3 §3.2).

RealVuln labels vulnerability *locations*, not scanner alerts. An alert that lies
in a ground-truth location (same file, line inside the range, same family) is
genuine. Every other alert of the three families has no label yet; a human labels
it later. Pure functions, no I/O except ``load_ground_truth``; no model is
involved and no label is read from anything but the ground-truth file.

Family of an alert: the scanner's CWE tags decide (``count_dev_alerts.ALERT_FAMILY_CWE``,
the same rule as the day-2 counts). Family of a ground-truth entry: RealVuln's own
``config/cwe-families.json`` (command injection includes CWE-77); the source CWE is
kept next to it and never overwritten.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from scripts.exp.count_dev_alerts import alert_families, in_scope

# group of our three families -> key in RealVuln's cwe-families.json
REALVULN_FAMILY_KEY = {
    "sqli": "sql_injection",
    "cmdi": "command_injection",
    "pathtraver": "path_traversal",
}


def load_ground_truth(path: Path, families_json: Path) -> list[dict[str, Any]]:
    """Vulnerable entries of one repo that fall in the three families.

    Each entry: ``id``, ``family``, ``source_cwe``, ``file``, ``ranges`` (list of
    ``(file, start, end)``: the primary location, then any ``acceptable_locations``).
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    families = json.loads(families_json.read_text(encoding="utf-8"))["families"]
    cwe_family: dict[str, str] = {}
    for family, key in REALVULN_FAMILY_KEY.items():
        for cwe in families[key]["cwes"]:
            cwe_family[cwe] = family
    out: list[dict[str, Any]] = []
    for finding in data.get("findings", []):
        if not finding.get("is_vulnerable"):
            continue
        family = cwe_family.get(finding.get("primary_cwe", ""))
        if family is None:
            continue
        file = str(finding["file"]).replace("\\", "/")
        loc = finding["location"]
        ranges = [(file, int(loc["start_line"]), int(loc["end_line"]))]
        for extra in finding.get("acceptable_locations") or []:
            ranges.append(
                (
                    str(extra["file"]).replace("\\", "/"),
                    int(extra["start_line"]),
                    int(extra["end_line"]),
                )
            )
        out.append(
            {
                "id": finding["id"],
                "family": family,
                "source_cwe": finding["primary_cwe"],
                "file": file,
                "ranges": ranges,
            }
        )
    return out


def alert_family(alert: dict[str, Any]) -> str | None:
    """The one family of an alert, or None when it has none or several."""
    families = alert_families(alert)
    return next(iter(families)) if len(families) == 1 else None


def scope_alerts(alerts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], Counter]:
    """Keep alerts of one of the three families; count what is dropped and why."""
    kept, stats = in_scope(alerts)
    single: list[dict[str, Any]] = []
    for alert in kept:
        if alert_family(alert) is None:
            stats["ambiguous_family"] += 1
        else:
            single.append(alert)
    return single, stats


def one_alert_per_location(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One alert per (file, line, family); prefer a rule with a data-flow path.

    The chosen alert gets ``candidates`` (how many alerts shared the location)
    and ``family``. Output is sorted by (file, line, rule) so it is deterministic.
    """
    groups: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
    for alert in alerts:
        family = alert_family(alert)
        assert family is not None  # scope_alerts ran first
        groups.setdefault((alert["file"], alert["line"], family), []).append(alert)
    chosen: list[dict[str, Any]] = []
    for (_file, _line, family), group in groups.items():
        best = min(group, key=lambda a: (not a["data_flow"], a["rule_id"], a["message"]))
        chosen.append({**best, "family": family, "candidates": len(group)})
    chosen.sort(key=lambda a: (a["file"], a["line"], a["rule_id"]))
    return chosen


def matching_entries(
    alert: dict[str, Any], ground_truth: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Ground-truth entries that contain the alert's line, in the same file and family."""
    hits = []
    for entry in ground_truth:
        if entry["family"] != alert["family"]:
            continue
        if any(f == alert["file"] and s <= alert["line"] <= e for f, s, e in entry["ranges"]):
            hits.append(entry)
    return hits


def match_alerts(
    alerts: list[dict[str, Any]], ground_truth: list[dict[str, Any]]
) -> dict[str, Any]:
    """Split deduplicated, in-scope alerts into matched and unmatched.

    Returns ``matched`` (alert dicts with ``gt`` = list of entry ids and
    ``source_cwe`` / ``source_id`` of the first entry in id order), ``unmatched``,
    ``gt_flagged`` (ids hit by at least one alert) and ``gt_unflagged`` (entries no
    alert reached: CodeQL did not flag them; kept for the mismatch list).
    """
    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    flagged: set[str] = set()
    for alert in alerts:
        hits = matching_entries(alert, ground_truth)
        if hits:
            hits.sort(key=lambda g: g["id"])
            flagged.update(g["id"] for g in hits)
            matched.append(
                {
                    **alert,
                    "gt": [g["id"] for g in hits],
                    "source_id": hits[0]["id"],
                    "source_cwe": hits[0]["source_cwe"],
                }
            )
        else:
            unmatched.append(alert)
    unflagged = [g for g in ground_truth if g["id"] not in flagged]
    return {
        "matched": matched,
        "unmatched": unmatched,
        "gt_flagged": flagged,
        "gt_unflagged": unflagged,
    }
