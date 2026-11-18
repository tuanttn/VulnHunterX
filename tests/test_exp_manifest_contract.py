# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""Manifest contract: no label, source test name or other bookkeeping field of a
manifest can reach the verifier model (plan v3.3 §3.6, "no method reads a label").

The B3c adapter does not exist yet. These tests pin the boundary it must respect:
``entry_to_finding`` and ``vulnhunterx-repo`` read only the allow-listed metadata
keys, and the reference row -> entry mapping used by the routing script copies
only those keys. They also cover the two scripts under ``scripts/exp``."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches import repo_context as rc
from benchmarks.approaches.base import (
    MODEL_VISIBLE_METADATA_KEYS,
    ROUTING_METADATA_KEYS,
    entry_to_finding,
)
from scripts.exp import b2_manifest_routing as routing
from scripts.exp import b2_route_impact as impact

_SENTINEL = "ZZLEAKZZ"


class _SpyDict(dict):
    """A metadata dict that records which keys are read; bulk access records ``*``."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.reads: set[str] = set()

    def get(self, key, default=None):
        self.reads.add(key)
        return super().get(key, default)

    def __getitem__(self, key):
        self.reads.add(key)
        return super().__getitem__(key)

    def __contains__(self, key):
        self.reads.add(key)
        return super().__contains__(key)

    def __iter__(self):
        self.reads.add("*")
        return super().__iter__()

    def keys(self):
        self.reads.add("*")
        return super().keys()

    def values(self):
        self.reads.add("*")
        return super().values()

    def items(self):
        self.reads.add("*")
        return super().items()

    def copy(self):
        self.reads.add("*")
        return super().copy()


def _poisoned_metadata() -> _SpyDict:
    return _SpyDict(
        {
            # model-visible, allowed
            "message": "Query built from a user-provided value.",
            "cwe_ids": ["CWE-89"],
            "cwe_tags_raw": ["external/cwe/cwe-089"],
            "dataflow_path": [{"file": "A.java", "line": 3}],
            # routing, not shown to the model
            "repo_name": "app-java",
            "lang": "java",
            # label-bearing or bookkeeping: must never be read
            "label": f"{_SENTINEL}-label",
            "source_case": f"{_SENTINEL}-BenchmarkTest00001",
            "family": f"{_SENTINEL}-family",
            "expected": f"{_SENTINEL}-real vulnerability",
            "copy_name": f"{_SENTINEL}-copy",
            "ground_truth": f"{_SENTINEL}-gt",
            "flow_leaves_method": True,
        }
    )


def _entry(metadata) -> GroundTruthEntry:
    return GroundTruthEntry(
        id=f"{_SENTINEL}-id",
        source_dataset="manifest",
        cwe_id="",
        rule_id="java/sql-injection",
        file_path="com/acme/A.java",
        function_name=f"{_SENTINEL}-function",
        start_line=3,
        lang="java",
        label="FP",
        code_snippet=f"{_SENTINEL}-snippet",
        metadata=metadata,
        sink_line=3,
    )


# ── the read boundary ────────────────────────────────────────────────────────


def test_entry_to_finding_reads_only_the_allow_listed_metadata_keys():
    meta = _poisoned_metadata()
    finding = entry_to_finding(_entry(meta))
    assert meta.reads <= MODEL_VISIBLE_METADATA_KEYS, meta.reads - MODEL_VISIBLE_METADATA_KEYS
    assert _SENTINEL not in json.dumps(finding.to_dict())


def test_vulnhunterx_repo_reads_only_allow_listed_and_routing_keys(tmp_path):
    repos, out = tmp_path / "repos", tmp_path / "out"
    (repos / "java" / "app-java").mkdir(parents=True)
    ctx = out / "java" / "app-java" / "context"
    ctx.mkdir(parents=True)
    for name in ("functions.csv", "callers.csv", "classes.csv"):
        (ctx / name).write_text("h\n", encoding="utf-8")
    engine = MagicMock()
    engine.verify_findings.return_value = SimpleNamespace(
        verdicts=[
            SimpleNamespace(
                verdict="Needs More Data", confidence="Low", confidence_score=0.3, reasoning="r",
                iterations=1, raw_response="", tokens_used=0, input_tokens=0, output_tokens=0,
                cached_input_tokens=0, cost_usd=0.0, decision_source="policy",
                policy_decision=None,
            )
        ]
    )
    meta = _poisoned_metadata()
    approach = rc.RepoContextApproach(repos_dir=repos, output_dir=out)
    with patch.object(rc, "VerificationEngine", return_value=engine):
        approach.evaluate(_entry(meta))
    allowed = MODEL_VISIBLE_METADATA_KEYS | ROUTING_METADATA_KEYS
    assert meta.reads <= allowed, meta.reads - allowed
    (findings,), _ = engine.verify_findings.call_args
    assert _SENTINEL not in json.dumps(findings[0].to_dict())


def test_allow_list_has_no_label_bearing_key():
    banned = {"label", "source_case", "family", "expected", "ground_truth", "copy_name"}
    assert not (MODEL_VISIBLE_METADATA_KEYS | ROUTING_METADATA_KEYS) & banned


# ── the reference manifest row -> entry mapping ──────────────────────────────

_ROW = {
    "alert_id": "b245808c469d67f3",
    "candidates_for_case": 1,
    "copy_name": f"{_SENTINEL}-copy",
    "cwe_ids": ["CWE-78", "CWE-88"],
    "cwe_tags_raw": ["external/cwe/cwe-078", "external/cwe/cwe-088"],
    "data_flow": [{"file": "com/acme/app/T1.java", "line": 45}],
    "family": f"{_SENTINEL}-cmdi",
    "file": "com/acme/app/T1.java",
    "flow_leaves_method": False,
    "label": f"{_SENTINEL}-genuine",
    "line": 83,
    "message": "This command line depends on a [user-provided value](1).",
    "rule_id": "java/command-line-injection",
    "source_case": f"{_SENTINEL}-BenchmarkTest00575",
}


def test_reference_mapping_copies_only_allow_listed_metadata():
    entry = routing.manifest_row_to_entry(_ROW)
    assert set(entry.metadata) <= MODEL_VISIBLE_METADATA_KEYS
    visible = json.dumps(
        {k: v for k, v in entry.to_dict().items() if k not in ("label", "id")}, default=str
    )
    assert _SENTINEL not in visible
    assert entry.label == "TP" and "genuine" not in entry.label  # placeholder, not the row label


def test_changing_the_row_label_changes_nothing_a_model_can_see():
    a = entry_to_finding(routing.manifest_row_to_entry({**_ROW, "label": "genuine"}))
    b = entry_to_finding(routing.manifest_row_to_entry({**_ROW, "label": "false_alarm"}))
    assert a.to_dict() == b.to_dict()


# ── scripts/exp/b2_manifest_routing.py ───────────────────────────────────────


def _row(rule_id: str, tags: list[str], **extra) -> dict:
    return {**_ROW, "rule_id": rule_id, "cwe_tags_raw": tags, "cwe_ids": [], **extra}


_SQLI = _row("java/sql-injection", ["external/cwe/cwe-089", "external/cwe/cwe-564"])
_CMDI = _row("java/command-line-injection", ["external/cwe/cwe-078"])
_PATH = _row("java/path-injection", ["external/cwe/cwe-022", "external/cwe/cwe-023"])


def test_route_counts_resolve_each_family_once():
    counts = routing.route_counts([_SQLI, _SQLI, _CMDI, _PATH])
    assert dict(counts) == {
        "sql_injection_java": 2, "command_injection_java": 1, "path_access_java": 1,
    }


def test_route_counts_flag_legacy_and_excluded_rows():
    legacy = _row("java/unrelated-rule", ["external/cwe/cwe-330"])
    excluded = _row("java/exec-tainted-environment", ["external/cwe/cwe-078"])
    counts = routing.route_counts([_SQLI, legacy, excluded])
    assert counts["legacy"] == 1 and counts["EXCLUDED_RULE"] == 1


def _write(path: Path, rows: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_script_exit_codes(tmp_path, capsys):
    good = _write(tmp_path / "good.jsonl", [_SQLI, _CMDI, _PATH])
    assert routing.main([str(good), "--expect", "sql_injection_java=1"]) == 0
    assert "entries 3" in capsys.readouterr().out
    assert routing.main([str(good), "--expect", "sql_injection_java=2"]) == 1
    bad = _write(tmp_path / "bad.jsonl", [_SQLI, _row("java/other", ["external/cwe/cwe-330"])])
    assert routing.main([str(bad)]) == 1
    assert routing.main([str(tmp_path / "missing.jsonl")]) == 2
    broken = tmp_path / "broken.jsonl"
    broken.write_text("{not json\n", encoding="utf-8")
    assert routing.main([str(broken)]) == 2


# ── scripts/exp/b2_route_impact.py ───────────────────────────────────────────


def _gt(dataset: str, lang: str, cwe: str, rule: str = "") -> dict:
    return {
        "id": f"{dataset}-{cwe}", "source_dataset": dataset, "cwe_id": cwe, "rule_id": rule,
        "file_path": "a", "function_name": "f", "start_line": 1, "lang": lang, "label": "TP",
        "code_snippet": "", "metadata": {},
    }


def test_impact_reports_only_datasets_whose_route_changes(tmp_path, capsys):
    path = tmp_path / "entries.json"
    path.write_text(
        json.dumps([_gt("d-java", "java", "CWE-89"), _gt("d-c", "c", "CWE-416")]),
        encoding="utf-8",
    )
    assert impact.main([str(path)]) == 0
    out = capsys.readouterr().out
    assert "d-java | java | CWE-89 | legacy -> sql_injection_java | 1 | YES" in out
    assert "d-c | c | CWE-416 | legacy -> legacy | 1 | no" in out
    assert "datasets to re-baseline: d-java" in out


def test_impact_unreadable_input_exits_2(tmp_path):
    assert impact.main([str(tmp_path / "nope.json")]) == 2


def test_bundled_fixtures_include_a_changed_java_sqli_dataset():
    counts = impact.impact(
        [e for p in sorted(impact._FIXTURES.glob("*_sample.json")) for e in impact.load_entries(p)]
    )
    assert counts[("owasp-java", "java", "CWE-89", "legacy", "sql_injection_java")] >= 1


@pytest.mark.parametrize("module", [routing, impact])
def test_scripts_never_read_the_manifest_label(module):
    source = Path(module.__file__).read_text(encoding="utf-8")
    assert 'row["label"]' not in source and "row.get(\"label\")" not in source
