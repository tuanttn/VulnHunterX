# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""Handoff combiner when a route returns an Error verdict (follow-up of run_log
day 3-4, item 5).

``tests/test_p3c_handoff_combiner.py`` covers TP / FP / Needs-More-Data. An Error
verdict (a failed model call, or the B2 context gate) is neither TP nor FP, so the
combiner treats the handoff as UNRESOLVED. The property that matters: an Error on
either route can never turn into a dismissal.

Handoff families exist only for PHP, C#, Go, JavaScript and Python
(``handoff_from`` in ``config/policies``); the Java families are primary owners, so
the Java experiment never reaches this code. These tests guard the shared engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from benchmarks.approaches.base import verdict_to_pred
from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.core.config import Config, load_config
from vuln_hunter_x.core.types import CodeContext, Finding, Verdict
from vuln_hunter_x.verification.engine import VerificationEngine
from vuln_hunter_x.verification.policy.loader import PolicyRegistry, load_policy_from_mapping

_TAINTED_FILENAME = "php.lang.security.injection.tainted-filename.tainted-filename"
_QUALIFYING = {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}


def _path_access():
    return load_policy_from_mapping(
        {
            "family": "path_access",
            "selectors": {"languages": ["php"], "cwes": ["CWE-22"]},
            "handoff_from": {"languages": ["php"], "rule_aliases": [_TAINTED_FILENAME]},
            "applicability": {
                "slot": "sink_binding",
                "applicable_values": ["QUALIFYING_PATH_ACCESS_SINK"],
                "not_applicable_values": ["NOT_PATH_ACCESS_SINK"],
            },
            "fact_slots": {
                "sink_binding": ["QUALIFYING_PATH_ACCESS_SINK", "NOT_PATH_ACCESS_SINK"]
            },
            "admissibility": {
                "sink_binding": {
                    "QUALIFYING_PATH_ACCESS_SINK": "LOCAL_POSITIVE",
                    "NOT_PATH_ACCESS_SINK": "LOCAL_POSITIVE",
                }
            },
            "decisive_slots": ["sink_binding"],
            "entailment": {"true_positive": {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}},
        }
    )


def _finding() -> Finding:
    return Finding(
        rule_id=_TAINTED_FILENAME, message="m", file="vulnerabilities/view_help.php",
        start_line=20, end_line=20, repo_name="dvwa", lang="php", cwe_ids=["CWE-918"],
    )


def _verdict(verdict: str, *, source: str = "legacy_model", facts: dict | None = None) -> Verdict:
    return Verdict(
        finding=_finding(), verdict=verdict, confidence="", reasoning=f"{verdict} from {source}",
        answers=[], raw_response="", model="t", decision_source=source,
        policy_decision={"family": "path_access", "facts": facts} if facts is not None else None,
    )


def _engine(handoff: Verdict, base: Verdict) -> VerificationEngine:
    engine = VerificationEngine(load_config())
    engine._policy_registry = PolicyRegistry([_path_access()])
    engine._base_calls = 0

    def _policy(finding, policy, questions=None):
        return handoff

    def _legacy(finding):
        engine._base_calls += 1
        return base

    engine._verify_policy_finding = _policy
    engine._verify_legacy_finding = _legacy
    return engine


def test_error_on_both_routes_is_error_never_a_dismissal():
    handoff = _verdict("Error", source="policy")
    engine = _engine(handoff, _verdict("Error"))
    result = engine._verify_single_finding(_finding())
    assert result is handoff  # the unresolved handoff outcome is returned as is
    assert result.verdict == "Error"
    assert engine._base_calls == 1  # the base route was still tried
    assert verdict_to_pred(result.verdict) == "ERROR"  # harness: a failed run, not FP


@pytest.mark.parametrize("handoff_facts", [None, {}, _QUALIFYING])
def test_handoff_error_with_base_false_positive_does_not_dismiss(handoff_facts):
    """A base FP must not stand over an unresolved (errored) handoff."""
    handoff = _verdict("Error", source="policy", facts=handoff_facts)
    result = _engine(handoff, _verdict("False Positive"))._verify_single_finding(_finding())
    assert result.verdict == "Error"


def test_handoff_error_with_base_true_positive_keeps_the_true_positive():
    """An unresolved handoff never hides a real-bug possibility: base TP stands."""
    engine = _engine(_verdict("Error", source="policy"), _verdict("True Positive"))
    assert engine._verify_single_finding(_finding()).verdict == "True Positive"


def test_base_error_after_unresolved_nmd_handoff_stays_unresolved():
    result = _engine(
        _verdict("Needs More Data", source="policy", facts=_QUALIFYING), _verdict("Error")
    )._verify_single_finding(_finding())
    assert result.verdict == "Needs More Data"


def test_applicable_handoff_false_positive_then_base_error_returns_the_base_error():
    """The handoff FP refutes only the candidate family; the base route decides, and
    its Error is not converted into a dismissal."""
    engine = _engine(
        _verdict("False Positive", source="policy", facts=_QUALIFYING), _verdict("Error")
    )
    assert engine._verify_single_finding(_finding()).verdict == "Error"


# ── the real path: B2 context gate on both routes, no model call ──────────────


def _gated_engine(tmp_path: Path) -> VerificationEngine:
    out, repos = tmp_path / "out", tmp_path / "repos"
    (repos / "php" / "dvwa").mkdir(parents=True)
    (out / "php" / "dvwa" / "context").mkdir(parents=True)  # directory only, no CSVs
    config = Config.from_dict(
        {
            "provider": "openai", "model": "mock-model", "verbosity": "quiet",
            "require_repo_context": True,
            "paths": {"repos_dir": str(repos), "output_dir": str(out)},
        }
    )
    extractor = MagicMock()
    extractor.get_context.return_value = CodeContext(
        code="include($_GET['f']);", function_name="f", start_line=18, end_line=22
    )
    engine = VerificationEngine(
        config=config,
        context_extractor=extractor,
        context_provider=ContextProvider(out, repos),
        llm_client=MagicMock(model="mock-model"),
        jobs=1,
    )
    engine._policy_registry = PolicyRegistry([_path_access()])
    return engine


def test_context_gate_on_handoff_and_base_returns_one_error_and_asks_no_model(tmp_path):
    engine = _gated_engine(tmp_path)
    result = engine._verify_single_finding(_finding())
    assert result.verdict == "Error"
    assert result.decision_source == "context_gate"
    assert "no snippet fallback" in result.reasoning
    assert verdict_to_pred(result.verdict) == "ERROR"
    engine.llm_client.analyze.assert_not_called()


def test_context_gate_through_verify_findings_yields_an_error_row_not_a_dismissal(tmp_path):
    engine = _gated_engine(tmp_path)
    outcome = engine.verify_findings([_finding()])
    assert [v.verdict for v in outcome.verdicts] == ["Error"]
    assert outcome.verdicts[0].decision_source == "context_gate"
