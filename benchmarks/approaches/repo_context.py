# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""VulnHunterX with full-repository context (``vulnhunterx-repo``).

Same engine, questions and prompts as the ``vulnhunterx`` approach, but the
verifier reads the real checked-out repository (``repos/<lang>/<repo_name>``)
through the engine's default repo-scoped extractor/context provider instead of
the in-memory snippet provider. The finding is built with an explicit
``repo_name`` taken from ``entry.metadata['repo_name']`` (e.g.
``<repo>__<sha8>`` from the revision-pair builder) and the engine is driven via
``verify_findings`` directly, NOT ``verify --sarif`` (which would derive the
repo name from the SARIF file stem).

Missing repository -> ERROR with a reason; there is deliberately no silent
fallback to snippet mode. Missing context CSVs (``functions.csv``,
``callers.csv``, ``classes.csv`` under ``output/<lang>/<repo>/context``) are an
ERROR too while ``require_context`` is on (the default); with
``require_context=false`` the engine's snippet fallback is used as before.

Each result carries ``result_metadata``: run ID, route, decision source, policy
record (family, terminal reason, facts), end reason, confidence, iterations,
the context path used and the model IDs the service returned.

Model client (B6): every verified alert builds its own engine and therefore its
own ``LLMClient`` (separate session, no shared messages or cache). ``seed`` and
``temperature`` are ``default`` (the client defaults), ``none`` (not sent) or a
number. ``call_log`` names a JSONL file that receives one record per model
call (see ``vuln_hunter_x/llm/call_log.py``).

Options: ``route=auto`` uses the policy registry; ``route=legacy`` empties it
(``PolicyRegistry([])``) so every finding takes the legacy multi-turn path.
"""

from __future__ import annotations

import dataclasses
import time
import uuid
from pathlib import Path
from typing import Any

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.adapters.registry import OptionSpec, _to_bool
from benchmarks.approaches.base import (
    PRED_ERROR,
    SAMPLING_DEFAULT,
    BenchmarkResult,
    _dry_run_result,
    entry_to_finding,
    parse_sampling_option,
    verdict_to_pred,
)
from benchmarks.approaches.registry import (
    LLMConfig,
    register_approach,
)
from benchmarks.approaches.vulnhunterx import VulnHunterXApproach
from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.context.repo_paths import resolve_repo_root
from vuln_hunter_x.core.config import Config
from vuln_hunter_x.llm.call_log import shared_call_log
from vuln_hunter_x.verification.engine import VerificationEngine
from vuln_hunter_x.verification.policy.loader import PolicyRegistry

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _safe_component(value: str) -> bool:
    return bool(value) and "/" not in value and "\\" not in value and value not in (".", "..")


@register_approach
class RepoContextApproach(VulnHunterXApproach):
    """vulnhunterx with full repository context instead of snippet-only context."""

    name = "vulnhunterx-repo"
    line_anchored = True
    option_schema = {
        "max_iterations": OptionSpec(int, default=3, help="Max LLM turns per finding."),
        "force_decision": OptionSpec(
            _to_bool, default=True, help="Force TP/FP after max_iterations."
        ),
        "route": OptionSpec(
            str, default="auto", help="auto (policy registry) | legacy (no policies)."
        ),
        "repos_dir": OptionSpec(str, default="", help="Repos root (default: project repos/)."),
        "output_dir": OptionSpec(
            str, default="", help="Context/output root (default: project output/)."
        ),
        "require_context": OptionSpec(
            _to_bool,
            default=True,
            help="Missing context CSVs -> ERROR (no snippet fallback).",
        ),
        "seed": OptionSpec(
            str, default="default", help="default (client seed) | none (not sent) | <int>."
        ),
        "temperature": OptionSpec(
            str,
            default="default",
            help="default (client temperature) | none (not sent) | <float>.",
        ),
        "call_log": OptionSpec(
            str, default="", help="JSONL path for one record per model call (empty: off)."
        ),
    }

    @classmethod
    def from_options(cls, llm: LLMConfig | None, options: dict[str, Any]) -> RepoContextApproach:
        llm = llm or LLMConfig()
        return cls(
            provider=llm.provider,
            model=llm.model,
            dry_run=llm.dry_run,
            max_iterations=options.get("max_iterations", 3),
            force_decision=options.get("force_decision", True),
            route=options.get("route", "auto"),
            repos_dir=Path(options["repos_dir"]) if options.get("repos_dir") else None,
            output_dir=Path(options["output_dir"]) if options.get("output_dir") else None,
            require_context=options.get("require_context", True),
            seed=options.get("seed", "default"),
            temperature=options.get("temperature", "default"),
            call_log=Path(options["call_log"]) if options.get("call_log") else None,
        )

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        max_iterations: int = 3,
        prompts_dir: Path | None = None,
        dry_run: bool = False,
        force_decision: bool = True,
        route: str = "auto",
        repos_dir: Path | None = None,
        output_dir: Path | None = None,
        require_context: bool = True,
        seed: str | int | None = "default",
        temperature: str | float | None = "default",
        call_log: Path | None = None,
    ) -> None:
        if route not in ("auto", "legacy"):
            raise ValueError(f"route must be 'auto' or 'legacy', got {route!r}")
        super().__init__(
            provider=provider,
            model=model,
            max_iterations=max_iterations,
            prompts_dir=prompts_dir,
            dry_run=dry_run,
            force_decision=force_decision,
        )
        self._route = route
        self._repos_dir = repos_dir or (_PROJECT_ROOT / "repos")
        self._output_dir = output_dir or (_PROJECT_ROOT / "output")
        self._require_context = require_context
        # Sampling overrides forwarded to Config; an absent key keeps the default.
        self._sampling: dict[str, Any] = {}
        parsed_seed = parse_sampling_option("seed", seed, int)
        if parsed_seed is not SAMPLING_DEFAULT:
            self._sampling["seed"] = parsed_seed
        parsed_temperature = parse_sampling_option("temperature", temperature, float)
        if parsed_temperature is not SAMPLING_DEFAULT:
            self._sampling["temperature"] = parsed_temperature
        self._call_log = shared_call_log(call_log) if call_log else None
        # Repeat / condition labels set by the harness (``--repeats``, ``--condition``).
        self.run_labels: dict[str, Any] = {}

    def _run_metadata(self) -> dict[str, Any]:
        """Settings of this run that every result records."""
        return {
            **self.run_labels,
            "route": self._route,
            "max_iterations": self._max_iterations,
            "force_decision": self._force_decision,
            "require_context": self._require_context,
            "seed": self._sampling.get("seed", "default"),
            "temperature": self._sampling.get("temperature", "default"),
        }

    def _error(
        self,
        entry: GroundTruthEntry,
        start: float,
        reason: str,
        end_reason: str = "error",
        **extra: Any,
    ) -> BenchmarkResult:
        return BenchmarkResult(
            entry=entry,
            predicted_label=PRED_ERROR,
            confidence="",
            reasoning=reason,
            elapsed_seconds=time.monotonic() - start,
            result_metadata={**self._run_metadata(), "end_reason": end_reason, **extra},
        )

    def _build_engine(self, call_context: dict[str, Any] | None = None) -> VerificationEngine:
        """A fresh engine (and LLM client) per verified alert: one session per run."""
        config = Config.from_dict(
            {
                "provider": self._provider,
                "model": self._model,
                "max_iterations": self._max_iterations,
                "verbosity": "quiet",
                "force_decision": self._force_decision,
                "require_repo_context": self._require_context,
                **self._sampling,
                "paths": {
                    "repos_dir": str(self._repos_dir),
                    "output_dir": str(self._output_dir),
                },
            }
        )
        engine = VerificationEngine(
            config=config,
            questions_loader=self._questions_loader,
            jobs=1,
        )
        if self._route == "legacy":
            engine._policy_registry = PolicyRegistry([])
        if self._call_log is not None:
            engine.llm_client.call_logger = self._call_log
            engine.llm_client.call_context = dict(call_context or {})
        return engine

    def evaluate(self, entry: GroundTruthEntry) -> BenchmarkResult:
        if self._dry_run:
            return _dry_run_result(entry, self.name)
        start = time.monotonic()
        run_id = uuid.uuid4().hex
        meta = entry.metadata or {}
        repo_name = str(meta.get("repo_name") or "")
        lang = str(meta.get("lang") or entry.lang or "")
        if not (_safe_component(repo_name) and _safe_component(lang)):
            return self._error(
                entry,
                start,
                f"vulnhunterx-repo needs safe metadata repo_name/lang "
                f"(got repo_name={repo_name!r}, lang={lang!r}); no snippet fallback",
            )
        if resolve_repo_root(self._repos_dir, lang, repo_name) is None:
            return self._error(
                entry,
                start,
                f"repository not checked out: {self._repos_dir / lang / repo_name}; "
                "no snippet fallback",
            )

        context_dir, missing = _context_status(self._output_dir, self._repos_dir, repo_name, lang)
        if missing and self._require_context:
            return self._error(
                entry,
                start,
                f"required context missing: {context_dir} (missing {', '.join(missing)}); "
                "no snippet fallback",
                end_reason="context_missing",
                context_path=str(context_dir),
            )
        context_path = "" if missing else str(context_dir)

        finding = dataclasses.replace(entry_to_finding(entry), repo_name=repo_name, lang=lang)
        engine = self._build_engine(
            {
                **self.run_labels,
                "run_id": run_id,
                "entry_id": entry.id,
                "approach": self.name,
                "route": self._route,
            }
        )
        _, match_type = self._questions_loader.get_questions_with_match_info(
            finding.rule_id,
            cwe_ids=finding.cwe_ids,
            lang=finding.lang,
        )
        result = engine.verify_findings([finding])
        elapsed = time.monotonic() - start
        if not result.verdicts:
            return BenchmarkResult(
                entry=entry,
                predicted_label=PRED_ERROR,
                confidence="",
                reasoning="No verdict returned",
                elapsed_seconds=elapsed,
                question_match_type=match_type,
                result_metadata={
                    **self._run_metadata(),
                    "run_id": run_id,
                    "end_reason": "no_verdict",
                    "context_path": context_path,
                    "models_returned": _models_returned(engine),
                },
            )
        v = result.verdicts[0]
        source = getattr(v, "decision_source", "legacy_model")
        policy_decision = getattr(v, "policy_decision", None)
        metadata = {
            **self._run_metadata(),
            "run_id": run_id,
            "models_returned": _models_returned(engine),
            "decision_source": source,
            "verdict": v.verdict,
            "end_reason": _end_reason(v, source, policy_decision),
            "policy_decision": policy_decision,
            "confidence": v.confidence,
            "confidence_score": getattr(v, "confidence_score", None),
            "iterations": v.iterations,
            "context_path": context_path,
            "cwe_ids": list(finding.cwe_ids),
        }
        return BenchmarkResult(
            entry=entry,
            predicted_label=verdict_to_pred(v.verdict),
            confidence=v.confidence,
            reasoning=f"[decision_source={source}] {v.reasoning}",
            elapsed_seconds=elapsed,
            iterations=v.iterations,
            raw_response=v.raw_response,
            tokens_used=v.tokens_used,
            input_tokens=v.input_tokens,
            output_tokens=v.output_tokens,
            cached_input_tokens=v.cached_input_tokens,
            cost_usd=v.cost_usd,
            question_match_type=match_type,
            result_metadata=metadata,
        )


def _models_returned(engine: Any) -> list[str]:
    """Model IDs the service returned during this run (``response.model``)."""
    returned = getattr(getattr(engine, "llm_client", None), "models_returned", None)
    return [str(m) for m in returned] if isinstance(returned, list) else []


def _context_status(
    output_dir: Path, repos_dir: Path, repo_name: str, lang: str
) -> tuple[Path, list[str]]:
    """Return (context dir, missing required CSVs) as the engine's provider sees them."""
    provider = ContextProvider(output_dir, repos_dir)
    return (
        provider.context_dir_for(repo_name, lang),
        provider.missing_context_files(repo_name, lang),
    )


def _end_reason(verdict: Any, source: str, policy_decision: dict | None) -> str:
    """Why the run stopped: the policy terminal reason, a gate, or the legacy outcome."""
    if source == "policy" and policy_decision:
        return str(policy_decision.get("terminal_reason") or "policy")
    if source != "legacy_model":
        return source
    if verdict.verdict == "Error":
        return "error"
    if "Max iterations" in (verdict.reasoning or "") and verdict.verdict == "Needs More Data":
        return "max_iterations"
    return "model_verdict"
