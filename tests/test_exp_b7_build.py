# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B7 row builders, OpenVuln alerts and the student sheet (synthetic data)."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from benchmarks.adapters.manifest_adapter import row_to_entry
from scripts.exp import b7_build as b
from tests.test_exp_b3a_manifest import _res

RULES = [
    {
        "id": "java/path-injection",
        "properties": {"tags": ["external/cwe/cwe-022", "external/cwe/cwe-073"]},
    },
    {"id": "java/zipslip", "properties": {"tags": ["external/cwe/cwe-022"]}},
    {"id": "java/xss", "properties": {"tags": ["external/cwe/cwe-079"]}},
]
_SECRET = "ZZLEAKZZ"
SOURCE = "\n".join(f"code line {i}" for i in range(1, 41)) + "\n"


def _sarif(results):
    return {
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.20.0", "rules": RULES}},
                "results": results,
            }
        ]
    }


def _alert(**over):
    base = {
        "rule_id": "java/path-injection",
        "message": "msg",
        "file": "src/A.java",
        "line": 12,
        "cwe_ids": ["CWE-22", "CWE-73"],
        "cwe_tags_raw": ["external/cwe/cwe-022"],
        "data_flow": [{"file": "src/A.java", "line": 5}, {"file": "src/A.java", "line": 12}],
        "family": "pathtraver",
        "candidates": 2,
    }
    base.update(over)
    return base


# ── rows ─────────────────────────────────────────────────────────────────────


def test_alert_id_is_stable_and_differs_between_copies():
    a = _alert()
    assert b.alert_id("app-01", a) == b.alert_id("app-01", a)
    assert b.alert_id("app-01", a) != b.alert_id("app-02", a)
    assert len(b.alert_id("app-01", a)) == 16


def test_row_has_the_owasp_schema_plus_track_fields():
    row = b.make_row(
        _alert(),
        copy_name="app-01",
        label="genuine",
        track="realapp",
        source="realvuln_human",
        source_cwe="CWE-22",
        source_id="gt-7",
    )
    assert set(row) == {
        "alert_id",
        "candidates_for_case",
        "copy_name",
        "cwe_ids",
        "cwe_tags_raw",
        "data_flow",
        "family",
        "file",
        "flow_leaves_method",
        "label",
        "line",
        "message",
        "rule_id",
        "source",
        "source_case",
        "source_cwe",
        "source_id",
        "track",
    }
    assert row["candidates_for_case"] == 2 and row["source_cwe"] == "CWE-22"
    # source CWE, scanner tags and family stay side by side
    assert row["cwe_ids"] == ["CWE-22", "CWE-73"] and row["family"] == "pathtraver"


def test_rows_load_through_the_manifest_adapter():
    row = b.make_row(_alert(), copy_name="app-01", label="false_alarm", track="dev", source="x")
    entry = row_to_entry(row)
    assert (
        entry.label == "FP" and entry.cwe_id == "CWE-22" and entry.metadata["repo_name"] == "app-01"
    )
    assert "gt-7" not in json.dumps(entry.metadata)


def test_pending_rows_are_refused_by_the_adapter():
    row = b.make_row(_alert(), copy_name="app-01", label=b.LABEL_PENDING, track="dev", source="x")
    with pytest.raises(ValueError, match="waiting for a student label"):
        row_to_entry(row)


def test_count_by_joins_the_keys():
    rows = [{"a": "x", "b": "1"}, {"a": "x", "b": "1"}, {"a": "y", "b": "2"}]
    assert b.count_by(rows, "a", "b") == {"x:1": 2, "y:2": 1}


def test_flow_leaves_uses_the_copy_source(tmp_path):
    (tmp_path / "A.java").write_text(
        "class A {\n  void f() {\n    int a = 1;\n    sink(a);\n  }\n  void g() {\n    int b = 2;\n  }\n}\n",
        encoding="utf-8",
    )
    inside = {
        "file": "A.java",
        "line": 4,
        "data_flow": [{"file": "A.java", "line": 3}, {"file": "A.java", "line": 4}],
    }
    leaving = {
        **inside,
        "data_flow": [{"file": "A.java", "line": 7}, {"file": "A.java", "line": 4}],
    }
    cache: dict = {}
    assert b.flow_leaves_for(inside, tmp_path, cache) is False
    assert b.flow_leaves_for(leaving, tmp_path, cache) is True
    assert b.flow_leaves_for({**inside, "data_flow": []}, tmp_path, cache) is None
    assert b.flow_leaves_for({**inside, "file": "Missing.java"}, tmp_path, {}) is None


# ── OpenVuln ─────────────────────────────────────────────────────────────────


def _results():
    return [
        _res("java/path-injection", "src/A.java", 12, flow=[("src/A.java", 5), ("src/A.java", 12)]),
        {"ruleId": "java/path-injection", "message": {"text": "no location"}},  # unreadable
        _res("java/zipslip", "src/A.java", 20),
        _res("java/xss", "src/A.java", 7),
        _res("java/path-injection", "src/Gone.java", 3),
        _res("java/path-injection", "src/A.java", 999),
    ]


def _label(n, rule, true):
    return {
        "alert_number": str(n),
        "filename": f"vulnerability_java_{rule}_{n}.txt",
        "is_vulnerable": "True" if true else "False",
    }


@pytest.fixture()
def checkout(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.java").write_text(SOURCE, encoding="utf-8")
    return tmp_path


def test_openvuln_index_matches_alert_numbers_even_after_an_unreadable_result():
    alerts = b.openvuln_alerts(_sarif(_results()))
    assert len(alerts) == 6
    assert alerts[0]["line"] == 12 and alerts[1] is None and alerts[2]["rule_id"] == "java/zipslip"


def test_openvuln_rows_use_the_shipped_labels_and_list_every_exclusion(checkout):
    labels = [
        _label(1, "path-injection", True),
        _label(2, "path-injection", True),  # unreadable result
        _label(3, "zipslip", False),
        _label(4, "xss", True),  # outside the three families
        _label(5, "path-injection", True),  # file missing
        _label(6, "path-injection", False),  # line beyond the file
        _label(7, "path-injection", True),  # number not in the SARIF
        _label(3, "path-injection", True),  # rule disagrees with the label file name
    ]
    rows, excluded = b.openvuln_rows("proj", _sarif(_results()), labels, checkout, "proj")
    assert [(r["source_id"], r["label"]) for r in rows] == [
        ("proj#1", "genuine"),
        ("proj#3", "false_alarm"),
    ]
    assert {(e["alert_number"], e["reason"]) for e in excluded} == {
        ("2", "alert_number_not_in_sarif"),
        ("4", "outside_three_families"),
        ("5", "file_not_in_checkout"),
        ("6", "line_not_in_file"),
        ("7", "alert_number_not_in_sarif"),
        ("3", "sarif_rule_mismatch"),
    }
    assert all(r["track"] == "realapp" and r["source"] == "openvuln" for r in rows)
    assert rows[0]["flow_leaves_method"] in (True, False, None)


# ── labelling sheet ──────────────────────────────────────────────────────────


def _pending(n: int, copy: str) -> dict:
    row = b.make_row(
        _alert(line=10 + n, message=f"message {n}"),
        copy_name=copy,
        label=b.LABEL_PENDING,
        track="realapp",
        source="realvuln_human",
        source_cwe=_SECRET,
        source_id=f"{_SECRET}-gt{n}",
    )
    return row


@pytest.fixture()
def copies(tmp_path):
    out = {}
    for name in ("app-01", "app-02"):
        root = tmp_path / name / "src"
        root.mkdir(parents=True)
        (root / "A.java").write_text(SOURCE, encoding="utf-8")
        out[name] = tmp_path / name
    return out


def test_sheet_has_no_label_source_or_repository_and_empty_student_columns(copies):
    pending = [_pending(n, "app-01" if n % 2 else "app-02") for n in range(1, 9)]
    sheet, key = b.build_sheet(pending, copies, seed="s")
    assert len(sheet) == len(key) == 8
    for row in sheet:
        assert tuple(row) == b.SHEET_COLUMNS
        assert (
            row["label_s1"] == row["rationale_s1"] == row["label_s2"] == row["rationale_s2"] == ""
        )
    blob = json.dumps(sheet)
    for forbidden in (
        _SECRET,
        "realvuln_human",
        "app-01",
        "app-02",
        "genuine",
        "false_alarm",
        "pending",
    ):
        assert forbidden not in blob, forbidden
    # the key, not the sheet, maps back to the alert and its source
    assert {k["alert_id"] for k in key} == {p["alert_id"] for p in pending}
    assert {k["source"] for k in key} == {"realvuln_human"}


def test_sheet_shows_code_and_data_flow_text(copies):
    sheet, _ = b.build_sheet([_pending(1, "app-01")], copies, seed="s", window=2)
    row = sheet[0]
    assert row["location"] == "src/A.java:11"
    assert row["code"].splitlines() == [
        "9: code line 9",
        "10: code line 10",
        "11: code line 11",
        "12: code line 12",
        "13: code line 13",
    ]
    assert "src/A.java:5  code line 5" in row["dataflow"]


def test_sheet_order_is_a_fixed_shuffle(copies):
    pending = [_pending(n, "app-01") for n in range(1, 13)]
    a, ka = b.build_sheet(pending, copies, seed="s")
    again, kb = b.build_sheet(list(reversed(pending)), copies, seed="s")
    other, kc = b.build_sheet(pending, copies, seed="t")
    assert [k["alert_id"] for k in ka] == [k["alert_id"] for k in kb]  # input order does not matter
    assert [k["alert_id"] for k in ka] != [k["alert_id"] for k in kc]  # seed does
    assert [k["alert_id"] for k in ka] != sorted(k["alert_id"] for k in ka)  # actually shuffled
    assert [r["sheet_id"] for r in a] == [f"S{n:04d}" for n in range(1, 13)]
    assert again == a and other != a


def test_long_data_flow_is_cut_and_says_so(copies):
    row = _pending(1, "app-01")
    row["data_flow"] = [{"file": "src/A.java", "line": n} for n in range(1, 21)]
    sheet, _ = b.build_sheet([row], copies, seed="s", max_steps=5)
    assert sheet[0]["dataflow"].endswith("... (15 more steps)")


def test_write_csv_round_trips_and_hashes(tmp_path, copies):
    sheet, key = b.build_sheet([_pending(1, "app-01"), _pending(2, "app-02")], copies, seed="s")
    path = tmp_path / "out" / "sheet.csv"
    digest = b.write_csv(sheet, b.SHEET_COLUMNS, path)
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert path.with_name("sheet.csv.sha256").read_text(encoding="utf-8").startswith(digest)
    with path.open(encoding="utf-8-sig", newline="") as fh:
        assert list(csv.DictReader(fh)) == sheet
    key_path = tmp_path / "out" / "key.csv"
    b.write_csv(key, b.KEY_COLUMNS, key_path)
    assert "alert_id" in Path(key_path).read_text(encoding="utf-8-sig").splitlines()[0]


def test_two_reports_of_the_same_sink_are_one_alert_and_the_extra_is_listed(checkout):
    results = [
        _res("java/path-injection", "src/A.java", 12, flow=[("src/A.java", 5), ("src/A.java", 12)]),
        _res("java/path-injection", "src/A.java", 12, flow=[("src/A.java", 7), ("src/A.java", 12)]),
        _res("java/zipslip", "src/A.java", 20),
    ]
    labels = [
        _label(1, "path-injection", True),
        _label(2, "path-injection", True),
        _label(3, "zipslip", False),
    ]
    rows, excluded = b.openvuln_rows("proj", _sarif(results), labels, checkout, "proj")
    assert [(r["source_id"], r["candidates_for_case"]) for r in rows] == [
        ("proj#1", 2),
        ("proj#3", 1),
    ]
    assert excluded == [{"project": "proj", "alert_number": "2", "reason": "same_alert_as:proj#1"}]
    assert len({r["alert_id"] for r in rows}) == len(rows)


def test_conflicting_labels_for_one_alert_exclude_all_its_reports(checkout):
    results = [
        _res("java/path-injection", "src/A.java", 12),
        _res("java/path-injection", "src/A.java", 12),
    ]
    labels = [_label(1, "path-injection", True), _label(2, "path-injection", False)]
    rows, excluded = b.openvuln_rows("proj", _sarif(results), labels, checkout, "proj")
    assert rows == []
    assert {e["reason"] for e in excluded} == {"same_alert_conflicting_labels"} and len(
        excluded
    ) == 2
