# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B2 + B6 wired end to end: ``vulnhunterx-repo`` -> real engine -> real policy
registry -> real ``LLMClient`` -> mocked ``litellm.completion``.

A tiny synthetic Java repository and context CSVs are built in ``tmp_path``. No
network, no key, no dataset. The model answers with a fixed fact table, so the
verdict is entailed by the policy, not by model quality."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches.registry import build_approach
from vuln_hunter_x.llm.call_log import litellm_version

_REPO = "app-java"
_SOURCE = """package com.acme;

public class A {
    public void run(javax.servlet.http.HttpServletRequest request, java.sql.Statement st)
            throws Exception {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = '" + id + "'";
        st.executeQuery(sql);
    }
}
"""
_TP_FACTS = {
    "sink_binding": {"value": "QUALIFYING_RELATIONAL_SQL_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "query_channel": {"value": "SQL_TEXT_PATH_FOUND", "evidence": ["L1"]},
    "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
    "production_scope": {"value": "PROD", "evidence": ["L1"]},
}


def _response(content: str, model: str = "served-model-2026"):
    choice = MagicMock()
    choice.message.content = content
    choice.finish_reason = "stop"
    usage = SimpleNamespace(
        prompt_tokens=100, completion_tokens=20, total_tokens=120, prompt_tokens_details=None
    )
    return SimpleNamespace(choices=[choice], usage=usage, model=model, id="r1")


def _entry() -> GroundTruthEntry:
    return GroundTruthEntry(
        id="alert-1",
        source_dataset="manifest",
        cwe_id="",
        rule_id="java/sql-injection",
        file_path="com/acme/A.java",
        function_name="",
        start_line=8,
        lang="java",
        label="TP",
        code_snippet="",
        metadata={
            "repo_name": _REPO,
            "lang": "java",
            "message": "Query built from a user-provided value.",
            "cwe_ids": ["CWE-564", "CWE-89"],
            "cwe_tags_raw": ["external/cwe/cwe-089", "external/cwe/cwe-564"],
            "dataflow_path": [
                {"file": "com/acme/A.java", "line": 6},
                {"file": "com/acme/A.java", "line": 7},
                {"file": "com/acme/A.java", "line": 8},
            ],
        },
        sink_line=8,
    )


@pytest.fixture()
def world(tmp_path):
    repos = tmp_path / "repos"
    src = repos / "java" / _REPO / "com" / "acme"
    src.mkdir(parents=True)
    (src / "A.java").write_text(_SOURCE, encoding="utf-8")
    out = tmp_path / "out"
    ctx = out / "java" / _REPO / "context"
    ctx.mkdir(parents=True)
    for name in ("functions.csv", "callers.csv", "classes.csv"):
        (ctx / name).write_text("name,file,start_line,end_line\n", encoding="utf-8")
    return SimpleNamespace(repos=repos, out=out, log=tmp_path / "calls.jsonl")


def _approach(world, **options):
    return build_approach(
        "vulnhunterx-repo",
        options={
            "route": "auto",
            "max_iterations": "5",
            "force_decision": "false",
            "seed": "none",
            "temperature": "none",
            "repos_dir": str(world.repos),
            "output_dir": str(world.out),
            "call_log": str(world.log),
            **options,
        },
    )


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_sqli_alert_takes_policy_path_and_logs_every_call(mock_completion, world):
    mock_completion.side_effect = lambda **kw: _response(
        json.dumps({"fact_slots": _TP_FACTS, "reasoning": "assessed"})
    )
    approach = _approach(world)
    approach.run_labels = {"repeat": 2, "condition": "full"}

    result = approach.evaluate(_entry())

    meta = result.result_metadata
    assert meta["decision_source"] == "policy", result.reasoning
    assert meta["policy_decision"]["family"] == "sql_injection_java"
    assert meta["policy_decision"]["facts"]["query_channel"] == "SQL_TEXT_PATH_FOUND"
    assert result.predicted_label == "TP"
    assert meta["context_path"] == str(world.out / "java" / _REPO / "context")
    assert meta["models_returned"] == ["served-model-2026"]
    assert meta["max_iterations"] == 5 and meta["force_decision"] is False

    # B6: no seed, no temperature, no tools went to the provider.
    sent = mock_completion.call_args.kwargs
    assert "seed" not in sent and "temperature" not in sent
    assert "tools" not in sent and "tool_choice" not in sent

    # One log record per call, all carrying this run's labels.
    rows = [json.loads(x) for x in world.log.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == mock_completion.call_count >= 1
    assert {r["run_id"] for r in rows} == {meta["run_id"]}
    assert {r["entry_id"] for r in rows} == {"alert-1"}
    assert {r["repeat"] for r in rows} == {2} and {r["condition"] for r in rows} == {"full"}
    assert {r["model_returned"] for r in rows} == {"served-model-2026"}
    assert {r["client_version"] for r in rows} == {litellm_version()}
    assert all(r["params_sent"]["seed_sent"] is False for r in rows)
    assert all(r["params_sent"]["temperature_sent"] is False for r in rows)
    # Source text and prompts never reach the log.
    assert "executeQuery" not in world.log.read_text(encoding="utf-8")


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_two_repeats_are_two_sessions_with_distinct_run_ids(mock_completion, world):
    mock_completion.side_effect = lambda **kw: _response(
        json.dumps({"fact_slots": _TP_FACTS, "reasoning": "assessed"})
    )
    approach = _approach(world)
    r1 = approach.evaluate(_entry())
    r2 = approach.evaluate(_entry())
    assert r1.result_metadata["run_id"] != r2.result_metadata["run_id"]
    rows = [json.loads(x) for x in world.log.read_text(encoding="utf-8").splitlines()]
    assert {r["run_id"] for r in rows} == {r1.result_metadata["run_id"], r2.result_metadata["run_id"]}


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_missing_context_makes_no_model_call(mock_completion, world):
    (world.out / "java" / _REPO / "context" / "callers.csv").unlink()
    result = _approach(world).evaluate(_entry())
    assert result.predicted_label == "ERROR"
    assert result.result_metadata["end_reason"] == "context_missing"
    mock_completion.assert_not_called()
    assert not world.log.exists()


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_no_verdict_after_iteration_limit_is_unresolved_not_dismissed(mock_completion, world):
    """The model never fills the table: the run ends NMD (unresolved), never FP."""
    mock_completion.side_effect = lambda **kw: _response(
        json.dumps({"fact_slots": {}, "reasoning": "unsure"})
    )
    result = _approach(world, max_iterations="2").evaluate(_entry())
    assert result.predicted_label == "NMD"
    assert result.result_metadata["decision_source"] == "policy"
    assert mock_completion.call_count <= 3


_LEAK = "ZZLEAKZZ"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_labels_and_bookkeeping_never_reach_any_model_message_or_the_call_log(
    mock_completion, world
):
    """Sentinels in every label-bearing field must be absent from every prompt sent
    to the model and from the call log. A control sentinel in the allowed ``message``
    field must appear, proving the capture sees the prompt text."""
    sent_messages: list[str] = []

    def fake(**kw):
        sent_messages.append(json.dumps(kw["messages"]))
        return _response(json.dumps({"fact_slots": _TP_FACTS, "reasoning": "assessed"}))

    mock_completion.side_effect = fake
    entry = _entry()
    entry.label = "FP"
    entry.id = f"{_LEAK}-id"
    entry.function_name = f"{_LEAK}-function"
    entry.code_snippet = f"{_LEAK}-snippet"
    entry.metadata = {
        **entry.metadata,
        "message": "CONTROL-ALLOWED-MESSAGE",
        "label": f"{_LEAK}-label",
        "source_case": f"{_LEAK}-BenchmarkTest00001",
        "family": f"{_LEAK}-family",
        "expected": f"{_LEAK}-real vulnerability",
        "ground_truth": f"{_LEAK}-gt",
    }

    _approach(world).evaluate(entry)

    assert sent_messages, "the engine made no model call"
    everything = "\n".join(sent_messages)
    assert "CONTROL-ALLOWED-MESSAGE" in everything
    assert _LEAK not in everything
    # The call log is not model-visible and names the entry (``entry_id``) by design;
    # no other field of it may carry anything taken from the entry.
    for line in world.log.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        assert record["entry_id"] == f"{_LEAK}-id"
        record.pop("entry_id")
        assert _LEAK not in json.dumps(record)
