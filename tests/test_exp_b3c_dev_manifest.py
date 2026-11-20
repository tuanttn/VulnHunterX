# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B3c development manifest: Juliet sampling, app matching, pooled rule (synthetic data)."""

from __future__ import annotations

from scripts.exp import b3c_dev_manifest as dev
from tests.test_exp_b3a_manifest import _res, _sarif

NAME_MAP = {"dir_family": {"Dsql": "sqli", "Dcmd": "cmdi", "Dpath": "pathtraver"}}


def _label_map(file, bad=((10, 20),), good=((25, 35),)):
    return {
        file: {
            "file_rule": None,
            "bad": [list(r) for r in bad],
            "good": [list(r) for r in good],
            "lines": 50,
            "orig": f"orig/{file}",
        }
    }


# ── Juliet units ─────────────────────────────────────────────────────────────


def test_one_alert_per_file_and_label_with_a_data_flow_rule_first():
    f = "suite/Dsql/s/A.java"
    sarif = _sarif(
        [
            _res("java/concatenated-sql-query", f, 12),  # bad, no flow
            _res("java/sql-injection", f, 14, flow=[(f, 11), (f, 14)]),  # bad, flow
            _res("java/sql-injection", f, 30, flow=[(f, 26), (f, 30)]),  # good
            _res("java/sql-injection", f, 5),  # outside both
            _res("java/sql-injection", "testcasesupport/IO.java", 3),  # support file
            _res("java/exec-tainted-environment", f, 12),  # excluded rule
            _res("java/xss", f, 12),  # other family
        ]
    )
    units, stats = dev.juliet_units(sarif, NAME_MAP, _label_map(f))
    assert [(u["line"], u["rule_id"], u["unit_label"], u["candidates"]) for u in units] == [
        (14, "java/sql-injection", "genuine", 2),
        (30, "java/sql-injection", "false_alarm", 1),
    ]
    assert units[0]["source_case"] == f"orig/{f}#bad" and units[0]["family"] == "sqli"
    assert stats["alerts_outside_bad_and_good"] == 1
    assert stats["alerts_in_support_or_other_files"] == 1
    assert stats["outside_three_families"] == 1
    assert stats["excluded_rule:java/exec-tainted-environment"] == 1


def test_an_alert_of_the_wrong_family_for_its_directory_is_left_out():
    f = "suite/Dcmd/s/A.java"
    sarif = _sarif([_res("java/sql-injection", f, 12)])
    units, stats = dev.juliet_units(sarif, NAME_MAP, _label_map(f))
    assert units == [] and stats["alerts_wrong_family_for_dir"] == 1


# ── sampling ─────────────────────────────────────────────────────────────────


def _units(family, genuine, false):
    def make(label, n):
        return {
            "family": family,
            "unit_label": label,
            "file": f"suite/{family}/{label}{n:04d}.java",
            "line": 10,
            "rule_id": "r",
            "candidates": 1,
        }

    return [make("genuine", n) for n in range(genuine)] + [
        make("false_alarm", n) for n in range(false)
    ]


def _all(**counts):
    out = []
    for family, (genuine, false) in counts.items():
        out += _units(family, genuine, false)
    return out


def test_each_family_gets_100_units_with_at_least_50_genuine():
    chosen, report = dev.sample_units(
        _all(sqli=(500, 300), cmdi=(300, 200), pathtraver=(400, 60)), "s"
    )
    for family in ("sqli", "cmdi", "pathtraver"):
        picked = report[family]["units_selected"]
        assert picked["genuine"] + picked["false_alarm"] == 100
        assert picked["genuine"] >= 50 and report[family]["genuine_at_least_min"]
    assert len(chosen) == 300


def test_a_family_with_few_false_alarms_takes_them_all_and_fills_with_genuine():
    chosen, report = dev.sample_units(
        _all(sqli=(300, 300), cmdi=(300, 300), pathtraver=(444, 12)), "s"
    )
    assert report["pathtraver"]["units_selected"] == {"false_alarm": 12, "genuine": 88}
    assert report["sqli"]["units_selected"] == {"false_alarm": 50, "genuine": 50}


def test_a_small_pool_is_reported_as_a_shortfall():
    _, report = dev.sample_units(_all(sqli=(30, 10), cmdi=(300, 300), pathtraver=(300, 300)), "s")
    assert report["sqli"]["shortfall"] == 60 and not report["sqli"]["genuine_at_least_min"]


def test_sampling_is_deterministic_and_seed_dependent():
    pool = _all(sqli=(400, 400), cmdi=(400, 400), pathtraver=(400, 400))
    a, _ = dev.sample_units(pool, "s")
    again, _ = dev.sample_units(list(reversed(pool)), "s")
    other, _ = dev.sample_units(pool, "t")
    assert a == again and a != other


def test_one_family_does_not_change_the_draw_of_another():
    base = _all(sqli=(400, 400), cmdi=(400, 400), pathtraver=(400, 400))
    changed = _all(sqli=(400, 400), cmdi=(400, 400), pathtraver=(401, 399))
    a, _ = dev.sample_units(base, "s")
    b, _ = dev.sample_units(changed, "s")
    assert [u for u in a if u["family"] == "sqli"] == [u for u in b if u["family"] == "sqli"]


# ── apps ─────────────────────────────────────────────────────────────────────


def test_app_alerts_in_a_ground_truth_location_are_genuine_and_the_rest_pending(tmp_path):
    (tmp_path / "A.java").write_text(
        "class A {\n  void f() {\n    sink();\n  }\n}\n", encoding="utf-8"
    )
    gt = [
        {
            "id": "g1",
            "family": "sqli",
            "source_cwe": "CWE-89",
            "file": "A.java",
            "ranges": [("A.java", 3, 3)],
        },
        {
            "id": "g2",
            "family": "cmdi",
            "source_cwe": "CWE-78",
            "file": "A.java",
            "ranges": [("A.java", 4, 4)],
        },
    ]
    sarif = _sarif(
        [
            _res("java/sql-injection", "A.java", 3, flow=[("A.java", 2), ("A.java", 3)]),
            _res("java/sql-injection", "A.java", 5),
            _res("java/exec-tainted-environment", "A.java", 4),
        ]
    )
    built = dev.app_rows(sarif, gt, copy_name="app-copy", copy_dir=tmp_path, source="webgoat")
    assert [(r["source_id"], r["label"], r["track"]) for r in built["genuine"]] == [
        ("g1", "genuine", "dev")
    ]
    assert [(r["line"], r["label"]) for r in built["pending"]] == [(5, "pending")]
    assert built["gt_entries"] == 2 and built["gt_flagged"] == 1 and built["gt_unflagged"] == ["g2"]
    assert built["stats"]["excluded_rule:java/exec-tainted-environment"] == 1


# ── pooled rule ──────────────────────────────────────────────────────────────


def _rows(**false_alarms):
    return [
        {"family": f, "label": "false_alarm"} for f, n in false_alarms.items() for _ in range(n)
    ]


def test_pooled_rule_names_the_families_below_the_threshold():
    out = dev.pooled_rule(_rows(sqli=50, cmdi=19, pathtraver=12))
    assert out["pooled_families"] == ["cmdi", "pathtraver"]
    assert out["false_alarms_per_family"] == {"sqli": 50, "cmdi": 19, "pathtraver": 12}
    assert out["pooled_false_alarms"] == 81 and out["threshold"] == 20


def test_pooled_rule_not_applied_at_the_threshold():
    assert dev.pooled_rule(_rows(sqli=20, cmdi=20, pathtraver=20))["pooled_families"] == []
