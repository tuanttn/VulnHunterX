# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B2: vulnhunterx-repo records run metadata, fails on missing context and passes
the experiment's iteration / forced-choice options to the engine (mock engine)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches import repo_context as rc
from benchmarks.approaches.base import BenchmarkResult
from benchmarks.approaches.registry import build_approach

_REPO = "app-java"


def _entry() -> GroundTruthEntry:
    return GroundTruthEntry(
        id="e1",
        source_dataset="manifest",
        cwe_id="CWE-89",
        rule_id="java/sql-injection",
        file_path="com/acme/A.java",
        function_name="",
        start_line=10,
        lang="java",
        label="TP",
        code_snippet="",
        metadata={
            "repo_name": _REPO,
            "lang": "java",
            "cwe_tags_raw": ["external/cwe/cwe-089", "external/cwe/cwe-564"],
        },
        sink_line=10,
    )


@pytest.fixture()
def dirs(tmp_path):
    repos = tmp_path / "repos"
    (repos / "java" / _REPO).mkdir(parents=True)
    out = tmp_path / "out"
    return repos, out


def _context(out: Path, names=("functions.csv", "callers.csv", "classes.csv")) -> Path:
    ctx = out / "java" / _REPO / "context"
    ctx.mkdir(parents=True, exist_ok=True)
    for name in names:
        (ctx / name).write_text("h\n", encoding="utf-8")
    return ctx


def _policy_verdict(**kw):
    base = dict(
        verdict="False Positive",
        confidence="High",
        confidence_score=0.85,
        reasoning="r",
        iterations=2,
        raw_response="",
        tokens_used=3,
        input_tokens=2,
        output_tokens=1,
        cached_input_tokens=0,
        cost_usd=0.0,
        decision_source="policy",
        policy_decision={
            "family": "sql_injection_java",
            "version": "1",
            "terminal_reason": "decided",
            "facts": {"sink_binding": "QUALIFYING_SQL_SINK"},
            "evidence_ids": ["L1"],
        },
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _run(approach, verdict):
    engine = MagicMock()
    engine.verify_findings.return_value = SimpleNamespace(verdicts=[verdict])
    captured = {}

    def fake_engine(**kw):
        captured.update(kw)
        return engine

    with patch.object(rc, "VerificationEngine", side_effect=fake_engine):
        result = approach.evaluate(_entry())
    return result, engine, captured


def test_sqli_entry_reaches_engine_with_cwe_ids_and_policy_metadata(dirs):
    repos, out = dirs
    ctx = _context(out)
    a = rc.RepoContextApproach(route="auto", repos_dir=repos, output_dir=out)
    result, engine, _ = _run(a, _policy_verdict())
    (findings,), _ = engine.verify_findings.call_args
    assert findings[0].cwe_ids == ["CWE-89", "CWE-564"]
    meta = result.result_metadata
    assert meta["decision_source"] == "policy"
    assert meta["policy_decision"]["family"] == "sql_injection_java"
    assert meta["policy_decision"]["facts"] == {"sink_binding": "QUALIFYING_SQL_SINK"}
    assert meta["end_reason"] == "decided"
    assert meta["confidence"] == "High" and meta["confidence_score"] == 0.85
    assert meta["context_path"] == str(ctx)
    assert meta["route"] == "auto"
    assert result.predicted_label == "FP"


@pytest.mark.parametrize("present", [(), ("functions.csv", "callers.csv")])
def test_missing_context_is_error_and_engine_not_built(dirs, present):
    repos, out = dirs
    if present:
        _context(out, present)
    a = rc.RepoContextApproach(repos_dir=repos, output_dir=out)
    with patch.object(rc, "VerificationEngine") as eng:
        result = a.evaluate(_entry())
    eng.assert_not_called()
    assert result.predicted_label == "ERROR"
    assert "required context missing" in result.reasoning
    assert "no snippet fallback" in result.reasoning
    assert result.result_metadata["end_reason"] == "context_missing"


def test_require_context_false_keeps_engine_fallback(dirs):
    repos, out = dirs
    a = rc.RepoContextApproach(repos_dir=repos, output_dir=out, require_context=False)
    result, _, captured = _run(a, _policy_verdict())
    assert result.predicted_label == "FP"
    assert result.result_metadata["context_path"] == ""
    assert captured["config"].verification.require_repo_context is False


def test_experiment_options_reach_engine_config(dirs):
    repos, out = dirs
    _context(out)
    a = build_approach(
        "vulnhunterx-repo",
        options={
            "max_iterations": "5",
            "force_decision": "false",
            "route": "legacy",
            "repos_dir": str(repos),
            "output_dir": str(out),
        },
    )
    result, _, captured = _run(a, _policy_verdict(decision_source="legacy_model",
                                                  policy_decision=None))
    cfg = captured["config"].verification
    assert cfg.max_iterations == 5
    assert cfg.force_decision is False
    assert cfg.require_repo_context is True
    meta = result.result_metadata
    assert meta["max_iterations"] == 5 and meta["force_decision"] is False
    assert meta["route"] == "legacy"


def test_unresolved_legacy_run_is_nmd_never_fp(dirs):
    repos, out = dirs
    _context(out)
    a = rc.RepoContextApproach(route="legacy", repos_dir=repos, output_dir=out,
                               force_decision=False, max_iterations=5)
    verdict = _policy_verdict(
        verdict="Needs More Data",
        confidence="Low",
        reasoning="Max iterations (5) reached without final verdict",
        decision_source="legacy_model",
        policy_decision=None,
    )
    result, _, _ = _run(a, verdict)
    assert result.predicted_label == "NMD"
    assert result.result_metadata["end_reason"] == "max_iterations"


def test_result_metadata_round_trips_through_checkpoint_dict(dirs):
    repos, out = dirs
    _context(out)
    a = rc.RepoContextApproach(repos_dir=repos, output_dir=out)
    result, _, _ = _run(a, _policy_verdict())
    data = result.to_dict()
    assert data["result_metadata"]["decision_source"] == "policy"
    assert "metadata" not in data  # the entry's own metadata is never written
    back = BenchmarkResult.from_dict(data)
    assert back.result_metadata == result.result_metadata
    assert back.entry.metadata == {}


def test_result_without_metadata_keeps_historic_dict():
    r = BenchmarkResult(entry=_entry(), predicted_label="TP", confidence="",
                        reasoning="", elapsed_seconds=0.0)
    assert "result_metadata" not in r.to_dict()


@pytest.mark.parametrize(
    ("verdict_kw", "expected"),
    [
        ({"decision_source": "context_gate", "verdict": "Error", "policy_decision": None},
         "context_gate"),
        ({"decision_source": "structural_gate", "verdict": "Needs More Data",
          "policy_decision": None}, "structural_gate"),
        ({"decision_source": "legacy_model", "verdict": "Error", "policy_decision": None},
         "error"),
        ({"decision_source": "legacy_model", "verdict": "True Positive",
          "policy_decision": None}, "model_verdict"),
    ],
)
def test_end_reason_names_the_gate_or_outcome(dirs, verdict_kw, expected):
    repos, out = dirs
    _context(out)
    a = rc.RepoContextApproach(repos_dir=repos, output_dir=out)
    result, _, _ = _run(a, _policy_verdict(**verdict_kw))
    assert result.result_metadata["end_reason"] == expected
