"""Tests for scripts/exp/count_dev_alerts.py (synthetic SARIF, no CodeQL)."""

from __future__ import annotations

from scripts.exp import count_dev_alerts as cd
from tests.test_exp_b3a_manifest import _res, _sarif


def test_count_juliet_labels_by_line_range():
    f = "suite/Dsql/s01/Cx.java"
    sarif = _sarif(
        [
            _res("java/sql-injection", f, 12, flow=[(f, 10), (f, 12)]),  # inside bad range
            _res("java/sql-injection", f, 30),  # inside good range
            _res("java/sql-injection", f, 5),  # outside both
            _res("java/exec-tainted-environment", f, 12),  # excluded rule
            _res("java/xss", f, 12),  # other family
            _res("java/sql-injection", "testcasesupport/IO.java", 3),  # support file
        ]
    )
    name_map = {"dir_family": {"Dsql": "sqli"}, "dir_cwe_original": {"Dsql": "CWE89_SQL_Injection"}}
    label_map = {f: {"file_rule": None, "bad": [[10, 20]], "good": [[25, 35]], "lines": 40}}
    out = cd.count_juliet(sarif, name_map, label_map)
    assert out["by_family_label"] == {
        "sqli:genuine": 1,
        "sqli:false_alarm": 1,
        "sqli:outside_bad_and_good": 1,
    }
    assert out["stats"]["alerts_in_support_or_other_files"] == 1
    assert out["stats"]["outside_three_families"] == 1
    assert out["stats"]["excluded_rule:java/exec-tainted-environment"] == 1


def test_count_app_matches_ground_truth_and_reports_flagged_entries():
    f = "src/main/java/A.java"
    sarif = _sarif(
        [
            _res("java/sql-injection", f, 12, flow=[(f, 9), (f, 12)]),  # in GT range
            _res("java/sql-injection", f, 90),  # no GT there
            _res("java/command-line-injection", f, 12),  # same lines, wrong family
        ]
    )
    gt = [
        {"id": "g1", "family": "sqli", "file": f, "start": 10, "end": 15},
        {"id": "g2", "family": "pathtraver", "file": f, "start": 50, "end": 60},
    ]
    out = cd.count_app(sarif, gt)
    assert out["by_family_label"] == {
        "cmdi:unlabelled": 1,
        "sqli:genuine": 1,
        "sqli:unlabelled": 1,
    }
    assert out["ground_truth_entries"] == {"sqli": 1, "pathtraver": 1}
    assert out["ground_truth_entries_flagged"] == {"sqli": 1}
