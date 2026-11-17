"""Tests for scripts/exp/b3a_scan_manifest.py (synthetic SARIF and copy, no CodeQL)."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.exp import b3a_scan_manifest as b3a
from scripts.exp._java_ast import MethodSpan

JAVA = """\
package com.acme.app.testcode;
public class {tok} {{
    void doPost(String p) {{
        String s = p;
        run(s);
    }}
    void run(String s) {{
        exec(s);
    }}
}}
"""

RULES = [
    {"id": "java/sql-injection", "properties": {"tags": ["security", "external/cwe/cwe-089"]}},
    {"id": "java/concatenated-sql-query", "properties": {"tags": ["external/cwe/cwe-089"]}},
    {"id": "java/command-line-injection", "properties": {"tags": ["external/cwe/cwe-078"]}},
    {"id": "java/exec-tainted-environment", "properties": {"tags": ["external/cwe/cwe-078"]}},
    {"id": "java/xss", "properties": {"tags": ["external/cwe/cwe-079"]}},
]


def _res(rule, file, line, flow=None):
    out = {
        "ruleId": rule,
        "message": {"text": f"{rule} message"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": line}}}
        ],
    }
    if flow:
        out["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f},
                                        "region": {"startLine": ln},
                                    }
                                }
                            }
                            for f, ln in flow
                        ]
                    }
                ]
            }
        ]
    return out


def _sarif(results):
    return {
        "runs": [
            {
                "tool": {
                    "driver": {"name": "CodeQL", "semanticVersion": "2.27.4", "rules": []},
                    "extensions": [
                        {"name": "codeql/java-queries", "semanticVersion": "1.12.0", "rules": RULES}
                    ],
                },
                "results": results,
            }
        ]
    }


def _setup(tmp_path: Path):
    copy = tmp_path / "copy"
    pkg = copy / "com/acme/app/testcode"
    pkg.mkdir(parents=True)
    toks = {"00001": "Taaa", "00002": "Tbbb", "00003": "Tccc", "00004": "Tddd"}
    for tok in toks.values():
        (pkg / f"{tok}.java").write_text(JAVA.format(tok=tok))
    name_map = {"copy_name": "copy", "testcases": toks}
    csv_path = tmp_path / "expected.csv"
    csv_path.write_text(
        "# header\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
        "BenchmarkTest00003,cmdi,true,78\n"
        "BenchmarkTest00004,xss,true,79\n"
    )
    return copy, name_map, csv_path


def test_parse_alerts_normalizes_cwe_and_reads_flow():
    f = "com/acme/app/testcode/Taaa.java"
    s = _sarif([_res("java/sql-injection", f, 8, flow=[(f, 4), (f, 8)])])
    [a] = b3a.parse_alerts(s)
    assert a["cwe_ids"] == ["CWE-89"]
    assert a["cwe_tags_raw"] == ["external/cwe/cwe-089"]
    assert a["data_flow"] == [{"file": f, "line": 4}, {"file": f, "line": 8}]


def test_manifest_selection_labels_and_leave_method(tmp_path: Path):
    copy, name_map, csv_path = _setup(tmp_path)
    a, b, c, d = (f"com/acme/app/testcode/{t}.java" for t in ("Taaa", "Tbbb", "Tccc", "Tddd"))
    s = _sarif(
        [
            # case 1 (genuine sqli): two candidates; the one with a flow path wins.
            # Flow starts in doPost (lines 3-6) and sinks in run (lines 7-9): leaves the method.
            _res("java/concatenated-sql-query", a, 8),
            _res("java/sql-injection", a, 8, flow=[(a, 4), (a, 8)]),
            # case 2 (false sqli): only a concatenation alert, no flow.
            _res("java/concatenated-sql-query", b, 5),
            # case 3 (genuine cmdi): flow stays inside one method.
            _res("java/command-line-injection", c, 8, flow=[(c, 7), (c, 8)]),
            # excluded rule in a cmdi case: counted, never selected.
            _res("java/exec-tainted-environment", c, 8, flow=[(c, 7), (c, 8)]),
            # xss in an xss case, and a wrong-family alert: not in the three families / wrong case.
            _res("java/xss", d, 5, flow=[(d, 4), (d, 5)]),
        ]
    )
    sarif_path = tmp_path / "x.sarif"
    sarif_path.write_text(json.dumps(s))
    entries, report = b3a.build_manifest(sarif_path, copy, name_map, csv_path, "copy")

    by_case = {e["source_case"]: e for e in entries}
    assert set(by_case) == {"BenchmarkTest00001", "BenchmarkTest00002", "BenchmarkTest00003"}
    assert by_case["BenchmarkTest00001"]["rule_id"] == "java/sql-injection"
    assert by_case["BenchmarkTest00001"]["candidates_for_case"] == 2
    assert by_case["BenchmarkTest00001"]["label"] == "genuine"
    assert by_case["BenchmarkTest00001"]["flow_leaves_method"] is True
    assert by_case["BenchmarkTest00002"]["label"] == "false_alarm"
    assert by_case["BenchmarkTest00002"]["flow_leaves_method"] is None
    assert by_case["BenchmarkTest00003"]["flow_leaves_method"] is False
    assert report["selection_stats"]["excluded_rule:java/exec-tainted-environment"] == 1
    assert report["selection_stats"]["alerts_outside_three_families"] == 1
    # the cmdi case still has its non-excluded alert, so it is not "left out"
    assert not any(k.startswith("cases_left_out") for k in report["selection_stats"])
    assert report["selection_stats"]["extra_alerts_same_case_dropped"] == 1
    assert report["genuine"] == 2 and report["false_alarms"] == 1
    assert report["flow_leaves_method"]["all"]["leaves_method"] == 1
    assert report["flow_leaves_method"]["all"]["share_of_genuine"] == 0.5
    assert report["by_family_label"]["sqli"]["false_cases_without_alert"] == 0
    assert report["by_family_label"]["cmdi"]["genuine_cases_without_alert"] == 0


def test_wrong_family_alert_for_case_is_not_selected(tmp_path: Path):
    copy, name_map, csv_path = _setup(tmp_path)
    c = "com/acme/app/testcode/Tccc.java"  # cmdi case, but only a SQL alert
    sarif_path = tmp_path / "x.sarif"
    sarif_path.write_text(json.dumps(_sarif([_res("java/sql-injection", c, 5, flow=[(c, 4), (c, 5)])])))
    entries, report = b3a.build_manifest(sarif_path, copy, name_map, csv_path, "copy")
    assert entries == []
    assert report["selection_stats"]["alerts_wrong_family_for_case"] == 1
    assert report["by_family_label"]["cmdi"]["genuine_cases_without_alert"] == 1


def test_flow_in_other_file_leaves_method():
    spans = {"a.java": [MethodSpan("f", 1, 9)]}
    alert = {
        "file": "a.java",
        "line": 5,
        "data_flow": [{"file": "b.java", "line": 2}, {"file": "a.java", "line": 5}],
    }
    assert b3a.flow_leaves_method(alert, spans) is True


def test_manifest_file_is_deterministic_with_sha256(tmp_path: Path):
    entries = [{"b": 1, "a": "x"}, {"a": "y", "b": 2}]
    p1, p2 = tmp_path / "m1.jsonl", tmp_path / "m2.jsonl"
    d1, d2 = b3a.write_manifest(entries, p1), b3a.write_manifest(entries, p2)
    assert d1 == d2
    assert (tmp_path / "m1.jsonl.sha256").read_text().startswith(d1)
    assert p1.read_text().splitlines()[0] == '{"a": "x", "b": 1}'


def test_case_with_only_excluded_rule_is_counted_as_left_out(tmp_path: Path):
    copy, name_map, csv_path = _setup(tmp_path)
    c = "com/acme/app/testcode/Tccc.java"
    sarif_path = tmp_path / "x.sarif"
    sarif_path.write_text(
        json.dumps(_sarif([_res("java/exec-tainted-environment", c, 8, flow=[(c, 7), (c, 8)])]))
    )
    entries, report = b3a.build_manifest(sarif_path, copy, name_map, csv_path, "copy")
    assert entries == []
    assert report["selection_stats"]["cases_left_out_only_excluded_rule:cmdi:genuine"] == 1
