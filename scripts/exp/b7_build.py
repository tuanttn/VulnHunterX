# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""B7 / dev manifest builders: rows, OpenVuln alerts and the student labelling sheet.

Every manifest row has the schema of the OWASP manifest (``scripts/exp/b3a_scan_manifest``)
plus ``track``, ``source``, ``source_cwe`` and ``source_id``. The source CWE, the
scanner's CWE tags and the group's family sit side by side; a source label is never
overwritten. ``benchmarks/adapters/manifest_adapter.py`` reads these rows.

The labelling sheet is for two students who label alerts independently from the code,
without model output (plan v3.3 §3.2). It holds no label, no source and no repository
name; the key that maps a sheet row back to its alert is a separate file.
"""

from __future__ import annotations

import csv
import hashlib
import random
from collections import Counter
from pathlib import Path
from typing import Any

from benchmarks.adapters.manifest_adapter import numbered_window
from benchmarks.adapters.openvuln_adapter import _rule_id_from_filename, _rule_matches
from scripts.exp._java_ast import method_spans
from scripts.exp.b3a_scan_manifest import flow_leaves_method, parse_alerts
from scripts.exp.b7_match import alert_family

LABEL_GENUINE = "genuine"
LABEL_FALSE_ALARM = "false_alarm"
LABEL_PENDING = "pending"  # no source label: goes to the sheet, never into a test manifest


def alert_id(copy_name: str, alert: dict[str, Any]) -> str:
    """Stable ID that stays unique across copies (the OWASP ID omits the copy)."""
    key = f"{copy_name}|{alert['rule_id']}|{alert['file']}|{alert['line']}|{alert['message']}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def make_row(
    alert: dict[str, Any],
    *,
    copy_name: str,
    label: str,
    track: str,
    source: str,
    source_cwe: str = "",
    source_id: str = "",
    source_case: str = "",
    flow_leaves: bool | None = None,
) -> dict[str, Any]:
    """One manifest row. ``alert`` needs ``family`` plus the ``parse_alerts`` fields."""
    return {
        "alert_id": alert_id(copy_name, alert),
        "candidates_for_case": int(alert.get("candidates", 1)),
        "copy_name": copy_name,
        "cwe_ids": list(alert["cwe_ids"]),
        "cwe_tags_raw": list(alert["cwe_tags_raw"]),
        "data_flow": [dict(step) for step in alert["data_flow"]],
        "family": alert["family"],
        "file": alert["file"],
        "flow_leaves_method": flow_leaves,
        "label": label,
        "line": alert["line"],
        "message": alert["message"],
        "rule_id": alert["rule_id"],
        "source": source,
        "source_case": source_case,
        "source_cwe": source_cwe,
        "source_id": source_id,
        "track": track,
    }


def flow_leaves_for(alert: dict[str, Any], copy_dir: Path, cache: dict[str, list]) -> bool | None:
    """``flow_leaves_method`` using the copy's source; None when it cannot be decided."""
    if not alert["data_flow"]:
        return None
    try:
        for file in {alert["file"], *(s["file"] for s in alert["data_flow"])}:
            if file not in cache:
                cache[file] = method_spans((copy_dir / file).read_bytes())
        return flow_leaves_method(alert, cache)
    except (OSError, KeyError):
        return None


def count_by(rows: list[dict[str, Any]], *keys: str) -> dict[str, int]:
    """``{"a:b:c": n}`` over the given row keys, for reports."""
    counts = Counter(":".join(str(r[k]) for k in keys) for r in rows)
    return dict(sorted(counts.items()))


# ── OpenVuln ─────────────────────────────────────────────────────────────────


def openvuln_alerts(sarif: dict[str, Any]) -> list[dict[str, Any] | None]:
    """Alerts of an OpenVuln SARIF indexed like the dataset's ``alert_number`` (1-based).

    Index ``i`` of the returned list is alert number ``i + 1``; a result that
    ``parse_alerts`` cannot read (no location) is ``None`` so numbering never shifts.
    """
    run = sarif["runs"][0]
    out: list[dict[str, Any] | None] = []
    for result in run.get("results", []):
        parsed = parse_alerts({"runs": [{**run, "results": [result]}]})
        out.append(parsed[0] if parsed else None)
    return out


def openvuln_rows(
    slug: str,
    sarif: dict[str, Any],
    labels: list[dict[str, str]],
    checkout: Path,
    copy_name: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Rows for the labelled alerts of one OpenVuln project, plus the exclusions.

    ``labels``: the project's ``ground_truth.csv`` rows (``alert_number``,
    ``filename``, ``is_vulnerable``). The dataset's own alerts and labels are used
    as shipped. An alert is excluded, with its reason, when its number is out of
    range, its rule does not agree with the label file name, it is outside the three
    families, or its file or line is not in the checkout.
    """
    alerts = openvuln_alerts(sarif)
    rows: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    cache: dict[str, list] = {}

    def exclude(label: dict[str, str], reason: str) -> None:
        excluded.append({"project": slug, "alert_number": label["alert_number"], "reason": reason})

    for label in labels:
        number = int(label["alert_number"])
        alert = alerts[number - 1] if 1 <= number <= len(alerts) else None
        if alert is None:
            exclude(label, "alert_number_not_in_sarif")
            continue
        rule_id, _ = _rule_id_from_filename(label["filename"])
        if not _rule_matches({"ruleId": alert["rule_id"]}, rule_id):
            exclude(label, "sarif_rule_mismatch")
            continue
        family = alert_family(alert)
        if family is None:
            exclude(label, "outside_three_families")
            continue
        source = checkout / alert["file"]
        try:
            lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            exclude(label, "file_not_in_checkout")
            continue
        if not 1 <= alert["line"] <= len(lines):
            exclude(label, "line_not_in_file")
            continue
        alert = {**alert, "family": family}
        genuine = str(label["is_vulnerable"]).strip().lower() == "true"
        rows.append(
            make_row(
                alert,
                copy_name=copy_name,
                label=LABEL_GENUINE if genuine else LABEL_FALSE_ALARM,
                track="realapp",
                source="openvuln",
                source_id=f"{slug}#{number}",
                flow_leaves=flow_leaves_for(alert, checkout, cache),
            )
        )
    return _merge_same_alert(rows, excluded)


def _merge_same_alert(
    rows: list[dict[str, Any]], excluded: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """One row per alert ID.

    A SARIF may report the same sink twice with different data-flow paths; the dataset
    then labels each report. They are one alert here (same rule, file, line and message),
    so the first row stays and the others are recorded as ``same_alert_as``. If the labels
    disagree the alert cannot be labelled and every report of it is excluded.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(row["alert_id"], []).append(row)
    kept: list[dict[str, Any]] = []
    for group in groups.values():
        first = group[0]
        if len({r["label"] for r in group}) > 1:
            for row in group:
                excluded.append(
                    {
                        "project": row["copy_name"],
                        "alert_number": row["source_id"].split("#")[-1],
                        "reason": "same_alert_conflicting_labels",
                    }
                )
            continue
        kept.append({**first, "candidates_for_case": len(group)})
        for row in group[1:]:
            excluded.append(
                {
                    "project": row["copy_name"],
                    "alert_number": row["source_id"].split("#")[-1],
                    "reason": f"same_alert_as:{first['source_id']}",
                }
            )
    kept.sort(key=lambda r: (r["file"], r["line"], r["rule_id"]))
    return kept, excluded


# ── labelling sheet ──────────────────────────────────────────────────────────

SHEET_COLUMNS = (
    "sheet_id",
    "family",
    "rule_id",
    "message",
    "location",
    "dataflow",
    "code",
    "label_s1",
    "rationale_s1",
    "label_s2",
    "rationale_s2",
)
KEY_COLUMNS = ("sheet_id", "alert_id", "source", "copy_name")


def _line_text(copy_dir: Path, file: str, line: int) -> str:
    try:
        lines = (copy_dir / file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return lines[line - 1].strip() if 1 <= line <= len(lines) else ""


def build_sheet(
    pending: list[dict[str, Any]],
    copy_dirs: dict[str, Path],
    *,
    seed: str,
    window: int = 15,
    max_steps: int = 12,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Sheet rows (what students see) and the key (``sheet_id`` -> alert), shuffled.

    The order is a fixed shuffle (``seed``), so rows of one repository are not
    adjacent. No label, source, repository name, model output or ground-truth ID is
    on the sheet; the student columns start empty.
    """
    order = sorted(pending, key=lambda r: r["alert_id"])
    random.Random(f"{seed}:sheet").shuffle(order)
    sheet: list[dict[str, str]] = []
    key: list[dict[str, str]] = []
    for number, row in enumerate(order, 1):
        copy_dir = copy_dirs[row["copy_name"]]
        try:
            text = (copy_dir / row["file"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        steps = row["data_flow"][:max_steps]
        flow = "\n".join(
            f"{s['file']}:{s['line']}  {_line_text(copy_dir, s['file'], s['line'])}" for s in steps
        )
        if len(row["data_flow"]) > max_steps:
            flow += f"\n... ({len(row['data_flow']) - max_steps} more steps)"
        sheet_id = f"S{number:04d}"
        sheet.append(
            {
                "sheet_id": sheet_id,
                "family": row["family"],
                "rule_id": row["rule_id"],
                "message": row["message"],
                "location": f"{row['file']}:{row['line']}",
                "dataflow": flow,
                "code": numbered_window(text, row["line"], window),
                "label_s1": "",
                "rationale_s1": "",
                "label_s2": "",
                "rationale_s2": "",
            }
        )
        key.append(
            {
                "sheet_id": sheet_id,
                "alert_id": row["alert_id"],
                "source": row["source"],
                "copy_name": row["copy_name"],
            }
        )
    return sheet, key


def write_csv(rows: list[dict[str, str]], columns: tuple[str, ...], path: Path) -> str:
    """Write a CSV (UTF-8 with BOM so spreadsheets open it) and its ``.sha256``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(columns))
        writer.writeheader()
        writer.writerows(rows)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return digest
