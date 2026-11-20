# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""B7 matching: CodeQL alerts against RealVuln ground-truth locations (plan v3.3 §3.2).

RealVuln labels vulnerability *locations*, not scanner alerts. An alert whose lines
overlap a ground-truth location (same file, same family; v3.3 §3.2 "overlapping lines")
is genuine. An alert's lines are its region, ``startLine`` to ``endLine``; a region
without an end line is its start line. Every other alert of the three families has no label yet; a human labels
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

from scripts.exp.b3a_scan_manifest import parse_alerts
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


def parse_alerts_with_regions(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    """``parse_alerts`` plus ``end_line`` (the last line of the alert's region).

    ``parse_alerts`` skips results without a location; the same filter is applied here,
    so the two lists line up one to one.
    """
    alerts = parse_alerts(sarif)
    ends: list[int] = []
    for result in sarif["runs"][0].get("results", []):
        locations = result.get("locations") or []
        if not locations:
            continue
        region = locations[0].get("physicalLocation", {}).get("region", {})
        start = int(region.get("startLine", 0))
        ends.append(int(region.get("endLine", start) or start))
    if len(ends) != len(alerts):  # cannot happen while the two filters agree
        raise ValueError("SARIF results and parsed alerts do not line up")
    for alert, end in zip(alerts, ends, strict=True):
        alert["end_line"] = max(end, alert["line"])
    return alerts


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
    """Ground-truth entries whose lines overlap the alert's region (same file and family)."""
    first = alert["line"]
    last = alert.get("end_line", first)
    hits = []
    for entry in ground_truth:
        if entry["family"] != alert["family"]:
            continue
        if any(f == alert["file"] and first <= e and last >= s for f, s, e in entry["ranges"]):
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
