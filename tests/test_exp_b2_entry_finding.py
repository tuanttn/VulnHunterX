# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B2: benchmark entries carry CWE ids, raw tags and data-flow into the Finding,
so Java alerts reach their family policy (plan v3.3 §5.2 B2)."""

from __future__ import annotations

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches.base import entry_to_finding
from vuln_hunter_x.verification.policy.loader import load_policy_registry

_REG = load_policy_registry()


def _entry(cwe_id: str = "", rule_id: str = "", **meta) -> GroundTruthEntry:
    return GroundTruthEntry(
        id="e1",
        source_dataset="manifest",
        cwe_id=cwe_id,
        rule_id=rule_id,
        file_path="com/acme/app/m1/T1.java",
        function_name="",
        start_line=40,
        lang="java",
        label="TP",
        code_snippet="",
        metadata=meta,
        sink_line=40,
    )


def _owner(entry: GroundTruthEntry) -> str:
    finding = entry_to_finding(entry)
    policy = _REG.resolve_family(
        cwe_ids=finding.cwe_ids, rule_id=finding.rule_id, lang=finding.lang
    )
    return policy.family if policy else "legacy"


def test_raw_codeql_tags_are_normalized_and_kept():
    entry = _entry(
        cwe_id="CWE-89",
        rule_id="java/sql-injection",
        cwe_ids=["CWE-564", "CWE-89"],
        cwe_tags_raw=["external/cwe/cwe-089", "external/cwe/cwe-564"],
    )
    finding = entry_to_finding(entry)
    assert finding.cwe_ids == ["CWE-564", "CWE-89"]
    assert finding.tags == ["external/cwe/cwe-089", "external/cwe/cwe-564"]


def test_entry_cwe_id_alone_is_normalized():
    finding = entry_to_finding(_entry(cwe_id="external/cwe/cwe-022"))
    assert finding.cwe_ids == ["CWE-22"]
    assert finding.tags == []


def test_no_cwe_gives_empty_list():
    assert entry_to_finding(_entry()).cwe_ids == []


@pytest.mark.parametrize(
    ("rule_id", "tags", "family"),
    [
        ("java/sql-injection", ["external/cwe/cwe-089", "external/cwe/cwe-564"],
         "sql_injection_java"),
        ("java/concatenated-sql-query", ["external/cwe/cwe-089", "external/cwe/cwe-564"],
         "sql_injection_java"),
        ("java/command-line-injection", ["external/cwe/cwe-078", "external/cwe/cwe-088"],
         "command_injection_java"),
        ("java/path-injection", ["external/cwe/cwe-022", "external/cwe/cwe-023",
                                 "external/cwe/cwe-036", "external/cwe/cwe-073"],
         "path_access_java"),
    ],
)
def test_java_alerts_resolve_to_their_family_policy(rule_id, tags, family):
    assert _owner(_entry(rule_id=rule_id, cwe_tags_raw=tags)) == family


def test_sqli_without_cwe_stays_legacy():
    """The audited defect: an empty cwe_ids list never reaches sql_injection_java."""
    assert _owner(_entry(rule_id="java/sql-injection")) == "legacy"
    assert _owner(_entry(cwe_id="CWE-89", rule_id="java/sql-injection")) == "sql_injection_java"


def test_manifest_dataflow_steps_keep_file_and_order():
    finding = entry_to_finding(
        _entry(
            cwe_id="CWE-78",
            dataflow_path=[
                {"file": "com/acme/app/m1/T1.java", "line": 12},
                {"file": "com/acme/app/Util.java", "line": 7, "message": "cmd"},
                {"file": "com/acme/app/m1/T1.java", "line": 40},
            ],
        )
    )
    assert finding.dataflow_path == [
        "line 12 (com/acme/app/m1/T1.java)",
        "line 7 (com/acme/app/Util.java): cmd",
        "line 40 (com/acme/app/m1/T1.java)",
    ]


def test_sarif_string_steps_pass_through():
    steps = ["line 3: request.getParameter(...)", "line 9"]
    assert entry_to_finding(_entry(dataflow_path=steps)).dataflow_path == steps


def test_no_dataflow_gives_empty_list():
    assert entry_to_finding(_entry(cwe_id="CWE-89")).dataflow_path == []
