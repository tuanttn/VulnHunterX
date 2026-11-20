# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B2: with ``require_repo_context`` a repository without full context CSVs is an
Error verdict on both routes, never a snippet fallback (plan v3.3 §5.2 B2)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vuln_hunter_x.context.provider import REQUIRED_CONTEXT_FILES, ContextProvider
from vuln_hunter_x.context.snippet_provider import SnippetContextProvider
from vuln_hunter_x.core.config import Config
from vuln_hunter_x.core.types import CodeContext, Finding
from vuln_hunter_x.verification.engine import VerificationEngine

_REPO = "app-java"


def _finding(rule_id: str, cwe_ids: list[str]) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="m",
        file="com/acme/A.java",
        start_line=10,
        end_line=10,
        repo_name=_REPO,
        lang="java",
        cwe_ids=cwe_ids,
    )


def _engine(tmp_path: Path, *, require: bool, csvs: tuple[str, ...] = ()) -> VerificationEngine:
    out = tmp_path / "out"
    repos = tmp_path / "repos"
    (repos / "java" / _REPO).mkdir(parents=True)
    ctx = out / "java" / _REPO / "context"
    ctx.mkdir(parents=True)
    for name in csvs:
        (ctx / name).write_text("h\n", encoding="utf-8")
    config = Config.from_dict(
        {
            "provider": "openai",
            "model": "mock-model",
            "verbosity": "quiet",
            "require_repo_context": require,
            "paths": {"repos_dir": str(repos), "output_dir": str(out)},
        }
    )
    extractor = MagicMock()
    extractor.get_context.return_value = CodeContext(
        code="int x = 1;", function_name="f", start_line=8, end_line=12
    )
    return VerificationEngine(
        config=config,
        context_extractor=extractor,
        context_provider=ContextProvider(out, repos),
        llm_client=MagicMock(model="mock-model"),
        jobs=1,
    )


@pytest.mark.parametrize(
    ("rule_id", "cwe_ids"),
    [
        ("java/sql-injection", ["CWE-89"]),  # policy route (sql_injection_java)
        ("synthetic/no-family", ["CWE-1234"]),  # legacy route
    ],
)
def test_missing_context_is_error_on_both_routes(tmp_path, rule_id, cwe_ids):
    engine = _engine(tmp_path, require=True, csvs=("functions.csv",))
    verdict = engine._verify_single_finding(_finding(rule_id, cwe_ids))
    assert verdict.verdict == "Error"
    assert verdict.decision_source == "context_gate"
    assert "callers.csv" in verdict.reasoning and "classes.csv" in verdict.reasoning
    assert "no snippet fallback" in verdict.reasoning
    engine.llm_client.analyze.assert_not_called()


def test_complete_context_passes_the_gate(tmp_path):
    engine = _engine(tmp_path, require=True, csvs=REQUIRED_CONTEXT_FILES)
    finding = _finding("java/sql-injection", ["CWE-89"])
    assert engine._missing_required_context(finding) is None
    ctx = CodeContext(code="x", function_name="f", start_line=1, end_line=1)
    assert engine._effective_context_provider(finding, ctx) is engine.context_provider


def test_gate_off_keeps_snippet_fallback(tmp_path):
    engine = _engine(tmp_path, require=False)
    finding = _finding("java/sql-injection", ["CWE-89"])
    assert engine._missing_required_context(finding) is None
    ctx = CodeContext(code="x", function_name="f", start_line=1, end_line=1)
    # Directory exists but is empty: the historic check only looks at the directory.
    (tmp_path / "out" / "java" / _REPO / "context").rmdir()
    assert isinstance(engine._effective_context_provider(finding, ctx), SnippetContextProvider)


def test_missing_context_files_lists_absent_csvs(tmp_path):
    provider = ContextProvider(tmp_path / "out", tmp_path / "repos")
    assert provider.missing_context_files("nope", "java") == list(REQUIRED_CONTEXT_FILES)
    assert provider.context_dir_for("nope", "java") == tmp_path / "out" / "java" / "nope" / "context"


def test_default_config_does_not_require_context():
    assert Config.from_dict({}).verification.require_repo_context is False
