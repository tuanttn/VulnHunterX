# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B2: ``--repeats`` / ``--condition`` give every repeat its own checkpoint, a
fresh approach and run labels (plan v3.3 Â§5.2 B2). Stub approach, no model."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches.base import BenchmarkApproach, BenchmarkResult
from benchmarks.scripts import run_benchmark as rb


def _entries(n: int = 3) -> list[GroundTruthEntry]:
    return [
        GroundTruthEntry(
            id=f"e{i}",
            source_dataset="synthetic",
            cwe_id="CWE-89",
            rule_id="java/sql-injection",
            file_path="A.java",
            function_name="",
            start_line=i + 1,
            lang="java",
            label="TP" if i % 2 == 0 else "FP",
            code_snippet="",
            metadata={},
            sink_line=i + 1,
        )
        for i in range(n)
    ]


class _Stub(BenchmarkApproach):
    name = "vulnhunterx-repo"
    line_anchored = True
    instances: list[_Stub] = []

    def __init__(self, options: dict) -> None:
        self.options = options
        self.seen: list[str] = []
        _Stub.instances.append(self)

    def evaluate(self, entry: GroundTruthEntry) -> BenchmarkResult:
        self.seen.append(entry.id)
        return BenchmarkResult(
            entry=entry,
            predicted_label="NMD",
            confidence="Low",
            reasoning="stub",
            elapsed_seconds=0.0,
            result_metadata={"decision_source": "policy"},
        )


@pytest.fixture()
def harness(monkeypatch, tmp_path):
    _Stub.instances = []
    monkeypatch.setattr(rb, "_load_dataset", lambda *a, **k: _entries())
    monkeypatch.setattr(
        rb, "_build_approach", lambda name, model, provider, dry, options=None: _Stub(options)
    )

    def run(*extra: str, dry: bool = True) -> Path:
        run_dir = tmp_path / "run"
        mode = ["--dry-run"] if dry else ["--ignore-quality-check"]
        argv = [
            "run_benchmark.py",
            "--dataset", "exp-stub",
            "--approach", "vulnhunterx-repo",
            *mode, "--skip-preflight", "--quiet",
            "--anchor", "none",
            "--run-dir", str(run_dir),
            *extra,
        ]
        monkeypatch.setattr(sys, "argv", argv)
        monkeypatch.setattr(rb, "_setup_logging", lambda _d: None)
        assert rb.main() == 0
        return run_dir

    return run


# Everything an experiment run with a real model must state (config.md §1.7).
BASE = [
    "--model", "pinned-model", "--provider", "anthropic",
    "--approach-option", "max_iterations=5",
    "--approach-option", "force_decision=false",
    "--no-force-decision",
    # The guard only needs a stated temperature; which one is Tuannt's decision.
    "--approach-option", "temperature=none",
]
FULL = [*BASE, "--approach-option", "seed=none"]


def _drop_option(args: list[str], name: str) -> list[str]:
    """``args`` without the ``--approach-option <name>=<value>`` pair."""
    out: list[str] = []
    i = 0
    while i < len(args):
        if args[i] == "--approach-option" and args[i + 1].split("=", 1)[0] == name:
            i += 2
            continue
        out.append(args[i])
        i += 1
    return out


def _rows(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["results"]


def test_three_repeats_write_three_named_checkpoints(harness):
    run_dir = harness(
        "--repeats", "3", "--condition", "full",
        "--approach-option", "route=auto",
        "--approach-option", "max_iterations=5",
        "--approach-option", "force_decision=false",
        "--no-force-decision",
    )
    names = sorted(p.name for p in run_dir.glob("*_results.json"))
    assert names == [
        f"exp-stub_vulnhunterx-repo_auto_full_r{k}_results.json" for k in (1, 2, 3)
    ]
    assert len(_Stub.instances) == 3  # a fresh approach (engine, client) per repeat
    for stub in _Stub.instances:
        assert stub.seen == ["e0", "e1", "e2"]
        assert stub.options["max_iterations"] == "5"
        assert stub.options["force_decision"] == "false"

    run_ids = set()
    for k in (1, 2, 3):
        rows = _rows(run_dir / f"exp-stub_vulnhunterx-repo_auto_full_r{k}_results.json")
        assert [r["result_metadata"]["repeat"] for r in rows] == [k, k, k]
        assert {r["result_metadata"]["condition"] for r in rows} == {"full"}
        assert {r["result_metadata"]["decision_source"] for r in rows} == {"policy"}
        run_ids |= {r["result_metadata"]["run_id"] for r in rows}
    assert len(run_ids) == 9  # one run ID per (alert, repeat)

    log = [json.loads(line) for line in (run_dir / "findings.jsonl").read_text().splitlines()]
    assert sorted({(r["repeat"], r["condition"]) for r in log}) == [
        (1, "full"), (2, "full"), (3, "full"),
    ]
    config = json.loads((run_dir / "run_config.json").read_text(encoding="utf-8"))
    assert config["repeats"] == 3 and config["condition"] == "full"
    assert config["approach_options"]["max_iterations"] == "5"
    assert config["force_decision"] is False


def test_route_default_used_in_name_when_not_passed(harness):
    run_dir = harness("--condition", "funconly")
    assert [p.name for p in run_dir.glob("*_results.json")] == [
        "exp-stub_vulnhunterx-repo_auto_funconly_r1_results.json"
    ]


def test_without_repeat_flags_keeps_historic_name(harness):
    run_dir = harness()
    assert [p.name for p in run_dir.glob("*_results.json")] == [
        "exp-stub_vulnhunterx-repo_results.json"
    ]
    rows = _rows(run_dir / "exp-stub_vulnhunterx-repo_results.json")
    assert "repeat" not in rows[0]["result_metadata"]


def test_resume_reruns_only_unfinished_repeat(harness):
    run_dir = harness("--repeats", "2")
    second = run_dir / "exp-stub_vulnhunterx-repo_auto_full_r2_results.json"
    second.unlink()
    _Stub.instances = []
    harness("--repeats", "2", "--resume")
    seen = [stub.seen for stub in _Stub.instances]
    assert seen == [[], ["e0", "e1", "e2"]]
    assert second.exists()


@pytest.mark.parametrize(
    "bad",
    [["--repeats", "0"], ["--condition", "Full"], ["--repeats", "2", "--iteration-sweep"]],
)
def test_invalid_repeat_flags_rejected(harness, bad):
    with pytest.raises(SystemExit):
        harness(*bad)


def test_call_log_path_per_repeat_when_not_dry_run(harness):
    """The stub makes no model call; only the option the approach receives is checked."""
    run_dir = harness("--repeats", "2", *FULL, dry=False)
    paths = [stub.options["call_log"] for stub in _Stub.instances]
    assert paths == [
        str(run_dir / f"llm_calls_exp-stub_vulnhunterx-repo_auto_full_r{k}.jsonl")
        for k in (1, 2)
    ]
    config = json.loads((run_dir / "run_config.json").read_text(encoding="utf-8"))
    assert config["model_client"]["client"] == "litellm"
    assert config["model_client"]["client_version"]
    assert config["model_client"]["litellm_cache_enabled"] is False


def test_dry_run_sets_no_call_log(harness):
    harness("--repeats", "1")
    assert "call_log" not in _Stub.instances[0].options


def test_run_refused_when_litellm_cache_is_enabled(harness, monkeypatch):
    import litellm

    monkeypatch.setattr(litellm, "cache", object(), raising=False)
    with pytest.raises(AssertionError):  # harness() asserts main() == 0; the run exits 2
        harness("--repeats", "2", *FULL, dry=False)
    assert _Stub.instances == []


def test_dry_run_with_cache_still_allowed(harness, monkeypatch):
    import litellm

    monkeypatch.setattr(litellm, "cache", object(), raising=False)
    harness("--repeats", "1")
    assert len(_Stub.instances) == 1


@pytest.mark.parametrize("seed_args", [[], ["--approach-option", "seed=default"]])
def test_real_experiment_run_without_seed_none_is_refused(harness, capsys, seed_args):
    with pytest.raises(SystemExit) as exc:
        harness("--repeats", "2", *BASE, *seed_args, dry=False)
    assert exc.value.code == 2
    assert "seed=none" in capsys.readouterr().err
    assert _Stub.instances == []  # refused before any approach was built


def test_dry_run_needs_no_seed(harness):
    harness("--repeats", "2")  # dry run, seed unset: allowed
    assert len(_Stub.instances) == 2


def test_run_without_repeat_flags_is_not_forced_to_set_a_seed(harness):
    """Other users of the harness keep the client default; only experiment runs are guarded."""
    harness(dry=False)
    assert len(_Stub.instances) == 1


def test_fixed_seed_is_allowed_but_warned(harness, caplog):
    import logging

    with caplog.at_level(logging.WARNING):
        harness("--repeats", "1", *BASE, "--approach-option", "seed=7", dry=False)
    assert any("fixed seed" in r.getMessage() for r in caplog.records)


def test_seed_option_problems_ignores_approaches_without_a_seed_option():
    missing, fixed = rb._seed_option_problems(["raw-sast", "vulnhunterx-repo"], {"seed": "none"})
    assert missing == [] and fixed == []
    missing, fixed = rb._seed_option_problems(
        ["raw-sast", "vulnhunterx-repo", "single-shot-cwe"], {}
    )
    assert missing == ["vulnhunterx-repo", "single-shot-cwe"]


# ── every other default that differs from the fixed configuration ────────────


def _refused(harness, capsys, *args: str) -> str:
    with pytest.raises(SystemExit) as exc:
        harness("--repeats", "2", *args, dry=False)
    assert exc.value.code == 2
    assert _Stub.instances == []  # refused before any approach was built
    return capsys.readouterr().err


def test_full_configuration_is_accepted(harness):
    harness("--repeats", "2", *FULL, dry=False)
    assert len(_Stub.instances) == 2


def test_run_without_a_chosen_model_or_provider_is_refused(harness, capsys, monkeypatch):
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    err = _refused(
        harness, capsys,
        "--approach-option", "seed=none", "--approach-option", "max_iterations=5",
        "--approach-option", "force_decision=false", "--no-force-decision",
        "--approach-option", "temperature=none",
    )
    assert "no model chosen" in err and "no provider chosen" in err


def test_model_from_environment_counts_as_chosen(harness, monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "pinned-model")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    harness(
        "--repeats", "1",
        "--approach-option", "seed=none", "--approach-option", "max_iterations=5",
        "--approach-option", "force_decision=false", "--no-force-decision",
        "--approach-option", "temperature=0.7",
        dry=False,
    )
    assert len(_Stub.instances) == 1


def test_missing_max_iterations_is_refused(harness, capsys):
    err = _refused(harness, capsys, *_drop_option(FULL, "max_iterations"))
    assert "max_iterations is not set" in err and "default of 10" in err


def test_other_max_iterations_is_allowed_but_warned(harness, caplog):
    import logging

    args = [("max_iterations=3" if a == "max_iterations=5" else a) for a in FULL]
    with caplog.at_level(logging.WARNING):
        harness("--repeats", "1", *args, dry=False)
    assert any("plan fixes 5" in r.getMessage() for r in caplog.records)


def test_forced_choice_option_on_is_refused(harness, capsys):
    args = [("force_decision=true" if a == "force_decision=false" else a) for a in FULL]
    assert "forced choice is on" in _refused(harness, capsys, *args)


def test_forced_choice_option_missing_is_refused(harness, capsys):
    err = _refused(harness, capsys, *_drop_option(FULL, "force_decision"))
    assert "forced choice is on" in err and "missing" in err


def test_force_decision_flag_left_on_is_refused(harness, capsys):
    err = _refused(harness, capsys, *[a for a in FULL if a != "--no-force-decision"])
    assert "--no-force-decision" in err


def test_require_context_false_is_refused(harness, capsys):
    err = _refused(harness, capsys, *FULL, "--approach-option", "require_context=false")
    assert "snippet fallback" in err


def test_nmd_counted_as_fp_is_refused(harness, capsys):
    err = _refused(harness, capsys, *FULL, "--nmd-handling", "fp")
    assert "never be scored as a dismissal" in err


@pytest.mark.parametrize("value", ["none", "0", "0.7", "1"])
def test_any_stated_temperature_is_accepted(harness, value):
    """The harness does not choose the value; it only requires that one is stated."""
    args = [("temperature=" + value if a == "temperature=none" else a) for a in FULL]
    harness("--repeats", "1", *args, dry=False)
    assert len(_Stub.instances) == 1


@pytest.mark.parametrize("extra", [[], ["--approach-option", "temperature=default"]])
def test_missing_or_default_temperature_is_refused(harness, capsys, extra):
    err = _refused(harness, capsys, *_drop_option(FULL, "temperature"), *extra)
    assert "temperature is not set" in err and "0.0" in err


def test_invalid_temperature_is_refused(harness, capsys):
    args = [("temperature=warm" if a == "temperature=none" else a) for a in FULL]
    assert "neither 'none' nor a number" in _refused(harness, capsys, *args)


def test_temperature_guard_applies_to_the_single_call_approach_too():
    errors, _ = rb._experiment_config_problems(
        ["single-shot-cwe"],
        {"seed": "none"},
        model_explicit=True, provider_explicit=True, force_decision_flag=False,
        nmd_handling="exclude",
    )
    assert any("single-shot-cwe: temperature is not set" in e for e in errors)


def test_all_problems_are_reported_together(harness, capsys):
    err = _refused(harness, capsys)
    for fragment in (
        "seed is not set", "max_iterations is not set", "forced choice is on",
        "temperature is not set",
    ):
        assert fragment in err


def test_dry_run_is_exempt_from_every_check(harness):
    harness("--repeats", "2")
    assert len(_Stub.instances) == 2
