# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B6: plain completions, no seed assumption, per-call JSONL log with the returned
model ID, and one client (session) per verified alert. Mocked litellm only."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches import repo_context as rc
from vuln_hunter_x.core.config import Config
from vuln_hunter_x.llm.call_log import JsonlCallLog, litellm_version, shared_call_log
from vuln_hunter_x.llm.client import LLMClient

MSGS = [{"role": "user", "content": "SECRET-PROMPT-TEXT"}]


def _response(content: str = '{"verdict": "True Positive"}', model: str = "served-model-2026"):
    choice = MagicMock()
    choice.message.content = content
    choice.finish_reason = "stop"
    usage = SimpleNamespace(
        prompt_tokens=11, completion_tokens=7, total_tokens=18, prompt_tokens_details=None
    )
    return SimpleNamespace(choices=[choice], usage=usage, model=model, id="resp-1")


# ── sampling parameters ──────────────────────────────────────────────────────


def test_seed_none_and_temperature_none_send_neither():
    client = LLMClient(provider="anthropic", model="m", seed=None, temperature=None)
    kwargs = client._build_completion_kwargs(MSGS)
    assert "seed" not in kwargs and "temperature" not in kwargs


def test_explicit_temperature_is_sent():
    client = LLMClient(provider="anthropic", model="m", seed=None, temperature=0.7)
    assert client._build_completion_kwargs(MSGS)["temperature"] == 0.7


def test_client_defaults_unchanged():
    """CLI behaviour is kept: the defaults still send temperature 0.0 and seed 42."""
    kwargs = LLMClient(provider="anthropic", model="m")._build_completion_kwargs(MSGS)
    assert kwargs["temperature"] == 0.0 and kwargs["seed"] == 42


def test_config_passes_none_through():
    cfg = Config.from_dict({"seed": None, "temperature": None})
    assert cfg.llm.seed is None and cfg.llm.temperature is None


def test_plain_completion_has_no_tools_or_cache_params():
    kwargs = LLMClient(provider="anthropic", model="m", seed=None)._build_completion_kwargs(MSGS)
    for key in ("tools", "tool_choice", "functions", "caching", "cache"):
        assert key not in kwargs


# ── per-call log ─────────────────────────────────────────────────────────────


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_every_call_logs_returned_model_tokens_and_run_id(mock_completion, tmp_path):
    mock_completion.return_value = _response()
    log_path = tmp_path / "calls.jsonl"
    client = LLMClient(
        provider="anthropic",
        model="pinned-model",
        seed=None,
        temperature=None,
        call_logger=JsonlCallLog(log_path),
        call_context={"run_id": "run-a", "entry_id": "e1", "repeat": 2, "condition": "full"},
    )
    client._complete_and_meter(MSGS, None)
    client._complete_and_meter(MSGS, None)

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec["run_id"] == "run-a" and rec["entry_id"] == "e1"
    assert rec["repeat"] == 2 and rec["condition"] == "full"
    assert rec["model_requested"] == "anthropic/pinned-model"
    assert rec["model_returned"] == "served-model-2026"
    assert rec["client"] == "litellm" and rec["client_version"] == litellm_version() != ""
    assert rec["usage"] == {
        "input_tokens": 11, "output_tokens": 7, "total_tokens": 18, "cached_input_tokens": 0,
    }
    assert rec["params_sent"]["seed_sent"] is False
    assert rec["params_sent"]["temperature_sent"] is False
    assert rec["params_sent"]["tools_sent"] is False
    assert rec["finish_reason"] == "stop"
    assert [json.loads(x)["call_index"] for x in lines] == [1, 2]
    assert client.models_returned == ["served-model-2026"]
    assert "SECRET-PROMPT-TEXT" not in log_path.read_text(encoding="utf-8")


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_failed_call_is_logged_without_message_and_reraised(mock_completion, tmp_path):
    class ProviderError(Exception):
        status_code = 429

    mock_completion.side_effect = ProviderError("body echoing SECRET-PROMPT-TEXT")
    log_path = tmp_path / "calls.jsonl"
    client = LLMClient(provider="anthropic", model="m", call_logger=JsonlCallLog(log_path))
    with pytest.raises(ProviderError):
        client._complete_and_meter(MSGS, None)
    rec = json.loads(log_path.read_text(encoding="utf-8"))
    assert rec["error"] == {"type": "ProviderError", "status_code": 429}
    assert rec["model_returned"] is None
    assert "SECRET-PROMPT-TEXT" not in log_path.read_text(encoding="utf-8")


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_no_logger_no_file(mock_completion, tmp_path):
    mock_completion.return_value = _response()
    client = LLMClient(provider="anthropic", model="m")
    client._complete_and_meter(MSGS, None)
    assert client.models_returned == []
    assert list(tmp_path.iterdir()) == []


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_cached_tokens_recorded(mock_completion, tmp_path):
    resp = _response()
    resp.usage.prompt_tokens_details = SimpleNamespace(cached_tokens=5)
    mock_completion.return_value = resp
    log_path = tmp_path / "calls.jsonl"
    LLMClient(provider="anthropic", model="m", call_logger=JsonlCallLog(log_path))._complete_and_meter(
        MSGS, None
    )
    assert json.loads(log_path.read_text(encoding="utf-8"))["usage"]["cached_input_tokens"] == 5


def test_shared_log_writes_whole_lines_from_threads(tmp_path):
    log = shared_call_log(tmp_path / "c.jsonl")
    assert shared_call_log(tmp_path / "c.jsonl") is log

    def work(k: int) -> None:
        for i in range(50):
            log({"k": k, "i": i, "pad": "x" * 200})

    threads = [threading.Thread(target=work, args=(k,)) for k in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    rows = [json.loads(x) for x in (tmp_path / "c.jsonl").read_text().splitlines()]
    assert len(rows) == 200


# ── one session per run (vulnhunterx-repo) ───────────────────────────────────


def _entry(eid: str = "e1") -> GroundTruthEntry:
    return GroundTruthEntry(
        id=eid,
        source_dataset="manifest",
        cwe_id="CWE-89",
        rule_id="java/sql-injection",
        file_path="com/acme/A.java",
        function_name="",
        start_line=10,
        lang="java",
        label="TP",
        code_snippet="",
        metadata={"repo_name": "app-java", "lang": "java"},
        sink_line=10,
    )


@pytest.fixture()
def dirs(tmp_path):
    repos = tmp_path / "repos"
    (repos / "java" / "app-java").mkdir(parents=True)
    ctx = tmp_path / "out" / "java" / "app-java" / "context"
    ctx.mkdir(parents=True)
    for name in ("functions.csv", "callers.csv", "classes.csv"):
        (ctx / name).write_text("h\n", encoding="utf-8")
    return repos, tmp_path / "out"


def _verdict():
    return SimpleNamespace(
        verdict="Needs More Data", confidence="Low", confidence_score=0.3, reasoning="r",
        iterations=1, raw_response="", tokens_used=0, input_tokens=0, output_tokens=0,
        cached_input_tokens=0, cost_usd=0.0, decision_source="policy", policy_decision=None,
    )


def test_each_run_builds_its_own_client_with_its_own_run_id(dirs, tmp_path):
    repos, out = dirs
    log_path = tmp_path / "run" / "llm_calls.jsonl"
    a = rc.RepoContextApproach(
        repos_dir=repos, output_dir=out, seed="none", temperature="none", call_log=log_path
    )
    a.run_labels = {"repeat": 1, "condition": "full"}
    engines = []

    def fake_engine(**kw):
        engine = MagicMock()
        engine.config = kw["config"]
        engine.llm_client = SimpleNamespace(models_returned=["served-model-2026"])
        engine.verify_findings.return_value = SimpleNamespace(verdicts=[_verdict()])
        engines.append(engine)
        return engine

    with patch.object(rc, "VerificationEngine", side_effect=fake_engine):
        r1 = a.evaluate(_entry())
        r2 = a.evaluate(_entry())

    assert len(engines) == 2 and engines[0].llm_client is not engines[1].llm_client
    c1, c2 = (e.llm_client.call_context for e in engines)
    assert c1["run_id"] != c2["run_id"]
    assert c1["run_id"] == r1.result_metadata["run_id"]
    assert c2["run_id"] == r2.result_metadata["run_id"]
    assert c1["repeat"] == 1 and c1["condition"] == "full" and c1["entry_id"] == "e1"
    assert engines[0].llm_client.call_logger is engines[1].llm_client.call_logger
    assert r1.result_metadata["models_returned"] == ["served-model-2026"]
    cfg = engines[0].config.llm
    assert cfg.seed is None and cfg.temperature is None
    assert r1.result_metadata["seed"] is None and r1.result_metadata["temperature"] is None


def test_sampling_options_default_keep_client_defaults(dirs):
    repos, out = dirs
    a = rc.RepoContextApproach(repos_dir=repos, output_dir=out)
    assert a._sampling == {}
    meta = a._run_metadata()
    assert meta["seed"] == "default" and meta["temperature"] == "default"


@pytest.mark.parametrize(
    ("seed", "temperature", "expected"),
    [("none", "none", {"seed": None, "temperature": None}),
     ("7", "0.5", {"seed": 7, "temperature": 0.5}),
     ("default", "1", {"temperature": 1.0})],
)
def test_sampling_option_parsing(seed, temperature, expected):
    a = rc.RepoContextApproach(seed=seed, temperature=temperature)
    assert a._sampling == expected


def test_bad_sampling_option_rejected():
    with pytest.raises(ValueError):
        rc.RepoContextApproach(temperature="warm")


def test_real_engine_client_gets_logger_and_sampling(dirs, tmp_path):
    """Without mocking the engine: the engine-built client sends no seed/temperature."""
    repos, out = dirs
    a = rc.RepoContextApproach(
        provider="anthropic", model="m", repos_dir=repos, output_dir=out,
        seed="none", temperature="none", call_log=tmp_path / "calls.jsonl",
    )
    engine = a._build_engine({"run_id": "r"})
    client = engine.llm_client
    assert client.call_context == {"run_id": "r"}
    assert isinstance(client.call_logger, JsonlCallLog)
    kwargs = client._build_completion_kwargs(MSGS)
    assert "seed" not in kwargs and "temperature" not in kwargs
    assert Path(client.call_logger.path) == (tmp_path / "calls.jsonl").resolve()


# ── single-shot-cwe (the "single call" method) uses the same client rules ────


def _snippet_entry() -> GroundTruthEntry:
    return GroundTruthEntry(
        id="s1", source_dataset="manifest", cwe_id="CWE-89", rule_id="java/sql-injection",
        file_path="A.java", function_name="", start_line=3, lang="java", label="TP",
        code_snippet='String q = "x" + id;\nst.executeQuery(q);\n', metadata={}, sink_line=2,
    )


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_single_shot_logs_call_and_sends_no_seed_or_temperature(mock_completion, tmp_path):
    from benchmarks.approaches.registry import build_approach

    mock_completion.return_value = _response(
        '{"verdict": "TP", "confidence": "High", "rationale": "line 2"}'
    )
    log_path = tmp_path / "single.jsonl"
    approach = build_approach(
        "single-shot-cwe",
        options={"seed": "none", "temperature": "none", "call_log": str(log_path)},
    )
    approach.run_labels = {"repeat": 1, "condition": "full"}
    r1 = approach.evaluate(_snippet_entry())
    r2 = approach.evaluate(_snippet_entry())

    sent = mock_completion.call_args.kwargs
    assert "seed" not in sent and "temperature" not in sent
    assert r1.predicted_label == "TP"
    assert r1.result_metadata["models_returned"] == ["served-model-2026"]
    assert r1.result_metadata["run_id"] != r2.result_metadata["run_id"]
    rows = [json.loads(x) for x in log_path.read_text(encoding="utf-8").splitlines()]
    assert [r["run_id"] for r in rows] == [
        r1.result_metadata["run_id"], r2.result_metadata["run_id"],
    ]
    assert {r["model_returned"] for r in rows} == {"served-model-2026"}
    assert {r["condition"] for r in rows} == {"full"}


def test_single_shot_default_options_keep_client_defaults():
    from benchmarks.approaches.registry import build_approach

    approach = build_approach("single-shot-cwe")
    assert approach._sampling == {} and approach._call_log is None
    client = approach._get_client()
    assert client.temperature == 0.0 and client.seed == 42  # unchanged for other users


# ── parameters litellm may drop (drop_params) ────────────────────────────────


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_seed_sent_to_a_model_without_seed_support_is_flagged(mock_completion, tmp_path):
    """anthropic/* has no ``seed`` in litellm's list: with drop_params it vanishes silently."""
    mock_completion.return_value = _response()
    log_path = tmp_path / "calls.jsonl"
    client = LLMClient(
        provider="anthropic", model="claude-sonnet-4-20250514", seed=42,
        call_logger=JsonlCallLog(log_path),
    )
    client._complete_and_meter(MSGS, None)
    rec = json.loads(log_path.read_text(encoding="utf-8"))
    assert rec["params_sent"]["seed_sent"] is True
    assert rec["params_outside_litellm_supported_list"] == ["seed"]
    assert rec["params_sent"]["names"] == ["max_tokens", "seed", "temperature"]
    assert rec["params_sent"]["drop_params"] is True


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_no_flag_when_sent_params_are_supported(mock_completion, tmp_path):
    mock_completion.return_value = _response()
    log_path = tmp_path / "calls.jsonl"
    client = LLMClient(
        provider="anthropic", model="claude-sonnet-4-20250514", seed=None,
        call_logger=JsonlCallLog(log_path),
    )
    client._complete_and_meter(MSGS, None)
    rec = json.loads(log_path.read_text(encoding="utf-8"))
    assert rec["params_outside_litellm_supported_list"] == []


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_unknown_model_is_recorded_as_unknown_not_as_clean(mock_completion, tmp_path):
    mock_completion.return_value = _response()
    log_path = tmp_path / "calls.jsonl"
    with patch(
        "vuln_hunter_x.llm.client.litellm.get_supported_openai_params", return_value=None
    ):
        client = LLMClient(
            provider="ollama", model="never-seen-model", call_logger=JsonlCallLog(log_path)
        )
        client._complete_and_meter(MSGS, None)
    rec = json.loads(log_path.read_text(encoding="utf-8"))
    assert rec["params_outside_litellm_supported_list"] is None


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_configured_retries_are_recorded_but_not_observed(mock_completion, tmp_path):
    """litellm retries inside one ``completion`` call: the log holds one record for them."""
    mock_completion.return_value = _response()
    log_path = tmp_path / "calls.jsonl"
    client = LLMClient(
        provider="anthropic", model="m", num_retries=3, call_logger=JsonlCallLog(log_path)
    )
    client._complete_and_meter(MSGS, None)
    rec = json.loads(log_path.read_text(encoding="utf-8"))
    assert rec["params_sent"]["num_retries_configured"] == 3
    assert len(log_path.read_text(encoding="utf-8").splitlines()) == 1
