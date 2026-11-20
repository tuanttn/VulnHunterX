# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B7 matching of CodeQL alerts to RealVuln ground-truth locations (synthetic data)."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.exp import b7_match as m

FAMILIES = {
    "families": {
        "sql_injection": {"cwes": ["CWE-89", "CWE-564", "CWE-943"]},
        "command_injection": {"cwes": ["CWE-78", "CWE-77"]},
        "path_traversal": {"cwes": ["CWE-22", "CWE-23", "CWE-36"]},
    }
}


def _alert(rule="java/sql-injection", file="A.java", line=10, cwes=("CWE-89",), flow=True, msg="m"):
    return {
        "rule_id": rule,
        "message": msg,
        "file": file,
        "line": line,
        "cwe_ids": list(cwes),
        "cwe_tags_raw": [],
        "data_flow": [{"file": file, "line": 1}] if flow else [],
    }


def _gt_file(tmp_path: Path, findings: list[dict]) -> tuple[Path, Path]:
    gt = tmp_path / "ground-truth.json"
    gt.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    fam = tmp_path / "cwe-families.json"
    fam.write_text(json.dumps(FAMILIES), encoding="utf-8")
    return gt, fam


def _finding(fid, cwe, file, start, end, vulnerable=True, acceptable=None):
    return {
        "id": fid,
        "is_vulnerable": vulnerable,
        "primary_cwe": cwe,
        "file": file,
        "location": {"start_line": start, "end_line": end},
        "acceptable_locations": acceptable or [],
    }


# ── ground truth ─────────────────────────────────────────────────────────────


def test_ground_truth_keeps_only_vulnerable_entries_of_the_three_families(tmp_path):
    gt, fam = _gt_file(
        tmp_path,
        [
            _finding("g1", "CWE-89", "src\\A.java", 5, 7),
            _finding("g2", "CWE-77", "B.java", 3, 3),  # command injection per RealVuln
            _finding("g3", "CWE-564", "C.java", 1, 2),
            _finding("g4", "CWE-79", "D.java", 1, 2),  # xss: out of scope
            _finding("g5", "CWE-22", "E.java", 1, 2, vulnerable=False),
        ],
    )
    out = m.load_ground_truth(gt, fam)
    assert [(g["id"], g["family"], g["source_cwe"]) for g in out] == [
        ("g1", "sqli", "CWE-89"),
        ("g2", "cmdi", "CWE-77"),
        ("g3", "sqli", "CWE-564"),
    ]
    assert out[0]["file"] == "src/A.java"  # backslashes normalised


def test_acceptable_locations_become_extra_ranges(tmp_path):
    gt, fam = _gt_file(
        tmp_path,
        [
            _finding(
                "g1",
                "CWE-22",
                "A.java",
                5,
                6,
                acceptable=[{"file": "B.java", "start_line": 40, "end_line": 41}],
            ),
        ],
    )
    (entry,) = m.load_ground_truth(gt, fam)
    assert entry["ranges"] == [("A.java", 5, 6), ("B.java", 40, 41)]


# ── families and scope ───────────────────────────────────────────────────────


def test_alert_family_is_unique_or_none():
    assert m.alert_family(_alert(cwes=("CWE-89", "CWE-564"))) == "sqli"
    assert m.alert_family(_alert(cwes=("CWE-78", "CWE-88"))) == "cmdi"
    assert m.alert_family(_alert(cwes=("CWE-22", "CWE-23", "CWE-36", "CWE-73"))) == "pathtraver"
    assert m.alert_family(_alert(cwes=("CWE-79",))) is None
    assert m.alert_family(_alert(cwes=("CWE-89", "CWE-78"))) is None  # two families


def test_scope_counts_what_it_drops():
    kept, stats = m.scope_alerts(
        [
            _alert(),
            _alert(rule="java/exec-tainted-environment", cwes=("CWE-78",)),
            _alert(rule="java/xss", cwes=("CWE-79",)),
            _alert(cwes=("CWE-89", "CWE-78")),
        ]
    )
    assert len(kept) == 1
    assert stats["excluded_rule:java/exec-tainted-environment"] == 1
    assert stats["outside_three_families"] == 1
    assert stats["ambiguous_family"] == 1


def test_one_alert_per_location_prefers_a_data_flow_rule():
    chosen = m.one_alert_per_location(
        [
            _alert(rule="java/z-rule", flow=False),
            _alert(rule="java/b-rule", flow=True),
            _alert(rule="java/a-rule", flow=False),
            _alert(file="B.java", line=3),
        ]
    )
    assert [(a["file"], a["line"], a["rule_id"], a["candidates"]) for a in chosen] == [
        ("A.java", 10, "java/b-rule", 3),
        ("B.java", 3, "java/sql-injection", 1),
    ]
    assert all(a["family"] == "sqli" for a in chosen)


# ── matching ─────────────────────────────────────────────────────────────────


def _gt(fid="g1", family="sqli", file="A.java", start=8, end=12, cwe="CWE-89", extra=()):
    return {
        "id": fid,
        "family": family,
        "source_cwe": cwe,
        "file": file,
        "ranges": [(file, start, end), *extra],
    }


def _located(**kw):
    return m.one_alert_per_location([_alert(**kw)])[0]


def test_alert_inside_the_range_in_the_same_file_and_family_is_matched():
    result = m.match_alerts([_located(line=10)], [_gt()])
    (alert,) = result["matched"]
    assert alert["source_id"] == "g1" and alert["source_cwe"] == "CWE-89"
    assert result["gt_flagged"] == {"g1"} and result["gt_unflagged"] == []


def test_range_edges_are_inclusive():
    for line in (8, 12):
        assert m.match_alerts([_located(line=line)], [_gt()])["matched"]
    for line in (7, 13):
        assert not m.match_alerts([_located(line=line)], [_gt()])["matched"]


def test_other_file_or_other_family_does_not_match():
    assert not m.match_alerts([_located(file="B.java")], [_gt()])["matched"]
    assert not m.match_alerts(
        [_located(rule="java/command-line-injection", cwes=("CWE-78",))], [_gt()]
    )["matched"]


def test_acceptable_location_matches_too():
    gt = _gt(extra=(("B.java", 40, 41),))
    assert m.match_alerts([_located(file="B.java", line=40)], [gt])["matched"]


def test_unmatched_alerts_and_unflagged_entries_are_kept_for_the_lists():
    result = m.match_alerts(
        [_located(line=10), _located(line=99)], [_gt("g1"), _gt("g2", start=50, end=60)]
    )
    assert [a["line"] for a in result["matched"]] == [10]
    assert [a["line"] for a in result["unmatched"]] == [99]
    assert [g["id"] for g in result["gt_unflagged"]] == ["g2"]


def test_one_alert_can_hit_two_entries_and_reports_both():
    result = m.match_alerts([_located(line=10)], [_gt("g2"), _gt("g1")])
    (alert,) = result["matched"]
    assert alert["gt"] == ["g1", "g2"] and alert["source_id"] == "g1"
    assert result["gt_flagged"] == {"g1", "g2"}
