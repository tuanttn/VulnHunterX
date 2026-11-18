# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Abstract base class and shared utilities for benchmark approaches."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from benchmarks.adapters.ground_truth import GroundTruthEntry
from vuln_hunter_x.context.extractor import ContextExtractor, SlicedContextExtractor
from vuln_hunter_x.core.types import CodeContext, Finding
from vuln_hunter_x.sarif.parser import _normalize_cwe

# Predicted label values produced by approaches
PRED_TP = "TP"       # Approach predicted: vulnerable
PRED_FP = "FP"       # Approach predicted: safe / false positive
PRED_NMD = "NMD"     # Approach returned: Needs More Data (inconclusive)
PRED_ERROR = "ERROR" # Approach returned an error

# Map VulnHunterX verdict strings â†’ benchmark prediction labels
_VERDICT_MAP: dict[str, str] = {
    "True Positive": PRED_TP,
    "False Positive": PRED_FP,
    "Needs More Data": PRED_NMD,
    "Error": PRED_ERROR,
}


@dataclass
class BenchmarkResult:
    """The result of one approach evaluating one GroundTruthEntry."""

    entry: GroundTruthEntry
    predicted_label: str   # PRED_TP | PRED_FP | PRED_NMD | PRED_ERROR
    confidence: str        # "High" | "Medium" | "Low" | ""
    reasoning: str
    elapsed_seconds: float
    tokens_used: int = 0
    input_tokens: int = 0       # prompt tokens (provider usage telemetry)
    output_tokens: int = 0      # completion tokens (provider usage telemetry)
    # Subset of input_tokens that hit the provider's prompt cache, as
    # reported by the provider (e.g. DeepSeek / OpenAI cached_tokens).
    cached_input_tokens: int = 0
    cost_usd: float = 0.0       # real cost reported by the provider
    iterations: int = 0
    raw_response: str = ""
    question_match_type: str = ""  # "exact"|"normalized"|"prefix"|"lang_prefix"|"default"|"generic"
    # Per-run record written by the approach (decision source, policy facts,
    # end reason, context path, run id, ...). Serialized as ``result_metadata``
    # so it never mixes with the ground-truth entry's own ``metadata``.
    result_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = {
            "entry_id": self.entry.id,
            "source_dataset": self.entry.source_dataset,
            "cwe_id": self.entry.cwe_id,
            "rule_id": self.entry.rule_id,
            "lang": self.entry.lang,
            "ground_truth_label": self.entry.label,
            "predicted_label": self.predicted_label,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "elapsed_seconds": self.elapsed_seconds,
            "tokens_used": self.tokens_used,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "cost_usd": self.cost_usd,
            "iterations": self.iterations,
            "question_match_type": self.question_match_type,
        }
        if self.result_metadata:
            data["result_metadata"] = self.result_metadata
        return data

    @classmethod
    def from_dict(cls, data: dict) -> BenchmarkResult:
        """Reconstruct a BenchmarkResult from a checkpoint dict.

        The ``entry`` field is rebuilt as a minimal stub from the stored
        ``entry_id``, ``source_dataset``, and ``ground_truth_label`` fields so
        that metrics evaluation and deduplication can work without the original
        dataset being fully loaded during resume.
        """
        from benchmarks.adapters.ground_truth import GroundTruthEntry

        # Build a stub entry sufficient for metrics recomputation
        stub_entry = GroundTruthEntry(
            id=data["entry_id"],
            source_dataset=data.get("source_dataset", ""),
            cwe_id=data.get("cwe_id", ""),
            rule_id=data.get("rule_id", ""),
            file_path=data.get("file_path", ""),
            function_name=data.get("function_name", ""),
            start_line=data.get("start_line", 1),
            lang=data.get("lang", "c"),
            label=data["ground_truth_label"],
            code_snippet="",  # not stored; not needed for resume metrics
            metadata=data.get("metadata", {}),
        )
        return cls(
            entry=stub_entry,
            predicted_label=data.get("predicted_label", "ERROR"),
            confidence=data.get("confidence", ""),
            reasoning=data.get("reasoning", ""),
            elapsed_seconds=float(data.get("elapsed_seconds", 0.0)),
            tokens_used=int(data.get("tokens_used", 0)),
            input_tokens=int(data.get("input_tokens", 0)),
            output_tokens=int(data.get("output_tokens", 0)),
            cached_input_tokens=int(data.get("cached_input_tokens", 0)),
            cost_usd=float(data.get("cost_usd", 0.0)),
            iterations=int(data.get("iterations", 0)),
            question_match_type=data.get("question_match_type", ""),
            result_metadata=dict(data.get("result_metadata") or {}),
        )


class BenchmarkApproach(ABC):
    """Abstract base for all benchmark approaches."""

    name: str = "unnamed"
    # True for approaches that anchor the verifier on a specific flagged line
    # (they call entry_to_finding). Line-unanchored, function-granularity
    # entries are excluded from these approaches so the line-aware verifier is
    # not penalised for correctly rejecting a fabricated anchor (#125).
    line_anchored: bool = False

    @abstractmethod
    def evaluate(self, entry: GroundTruthEntry) -> BenchmarkResult:
        """Evaluate a single ground truth entry."""
        ...


# CWE-specific messages that help variable-extraction patterns match
_CWE_MESSAGES: dict[str, str] = {
    "CWE-416": "use of freed memory: variable accessed after free()",
    "CWE-787": "out-of-bounds write: buffer overwritten beyond its bounds",
    "CWE-125": "out-of-bounds read: buffer read beyond its size",
    "CWE-476": "null pointer dereference: pointer dereferenced without NULL check",
    "CWE-190": "integer overflow: arithmetic result exceeds integer range",
    "CWE-401": "memory leak: allocated memory not released before function exit",
    "CWE-134": "uncontrolled format string: user-controlled input used as format",
    "CWE-79":  "cross-site scripting: unsanitized user input rendered in HTML",
}


# The only ``GroundTruthEntry.metadata`` keys ``entry_to_finding`` reads, i.e. the
# only metadata a verifier model can see. A manifest adapter must put nothing
# else a model should not see (label, source test name, family, ...) under these
# keys, and ``tests/test_exp_manifest_contract.py`` fails if this function starts
# reading another key. ``vulnhunterx-repo`` additionally reads the routing keys
# below to locate the checked-out repository; those are not shown to the model.
MODEL_VISIBLE_METADATA_KEYS: frozenset[str] = frozenset(
    {"message", "cwe_ids", "cwe_tags_raw", "dataflow_path"}
)
ROUTING_METADATA_KEYS: frozenset[str] = frozenset({"repo_name", "lang"})


def entry_to_finding(entry: GroundTruthEntry) -> Finding:
    """Convert a GroundTruthEntry to a VulnHunterX Finding for use with VerificationEngine.

    Requires a real scanner-derived anchor (``entry.sink_line``). Line-unanchored
    entries (function-granularity datasets) must be excluded upstream by
    line-anchored approaches: anchoring them at a fabricated line makes the
    line-aware verifier dismiss real bugs as False Positive (#125).
    """
    if entry.sink_line is None:
        raise ValueError(
            f"entry {entry.id!r} ({entry.source_dataset}) is line-unanchored; "
            "line-anchored verifier approaches must exclude it (#125)"
        )
    meta = entry.metadata or {}
    cwe_ids, cwe_tags = _entry_cwes(entry)
    return Finding(
        rule_id=entry.rule_id or f"benchmark/{entry.cwe_id.lower().replace('-', '')}",
        message=meta.get(
            "message",
            _CWE_MESSAGES.get(entry.cwe_id, f"{entry.cwe_id or 'vulnerability'} detected"),
        ),
        file=entry.file_path or "benchmark_snippet.c",
        start_line=entry.sink_line,
        end_line=entry.sink_line,
        repo_name=entry.source_dataset,
        lang=entry.lang,
        tool="benchmark",
        dataflow_path=_entry_dataflow(meta.get("dataflow_path")),
        cwe_ids=cwe_ids,
        tags=cwe_tags,
    )


SAMPLING_DEFAULT: Any = object()


def parse_sampling_option(name: str, value: Any, kind: type) -> Any:
    """Parse a ``seed`` / ``temperature`` approach option.

    ``default`` (or empty) -> ``SAMPLING_DEFAULT`` (keep the client default),
    ``none`` -> ``None`` (do not send the parameter), otherwise a ``kind`` number.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("", "default"):
        return SAMPLING_DEFAULT
    if text == "none":
        return None
    try:
        return kind(text)
    except ValueError:
        raise ValueError(f"{name} must be 'default', 'none' or a number, got {value!r}") from None


def _entry_cwes(entry: GroundTruthEntry) -> tuple[list[str], list[str]]:
    """Return (normalized CWE ids, raw scanner CWE tags) for an entry.

    Sources, in order: ``metadata['cwe_ids']``, ``metadata['cwe_tags_raw']``,
    then ``entry.cwe_id``. Every value is normalized to ``CWE-<n>`` with the
    SARIF parser's rule (``external/cwe/cwe-089`` -> ``CWE-89``); the raw tags
    are kept unchanged so the scanner's own form stays on record. Policy
    selection matches on these ids, so an empty list sends every finding to
    the legacy path.
    """
    meta = entry.metadata or {}
    raw_tags = [str(t) for t in (meta.get("cwe_tags_raw") or []) if str(t).strip()]
    candidates: list[str] = [str(c) for c in (meta.get("cwe_ids") or [])]
    candidates += raw_tags
    if entry.cwe_id:
        candidates.append(entry.cwe_id)
    ids: list[str] = []
    for value in candidates:
        cwe = _normalize_cwe(value)
        if cwe and cwe not in ids:
            ids.append(cwe)
    return ids, raw_tags


def _entry_dataflow(steps: Any) -> list[str]:
    """Render a manifest data-flow path as the Finding's ``dataflow_path``.

    Accepts the SARIF parser's string form (``"line 12: message"``, kept as is)
    or manifest steps ``{"file", "line", "message"?}``, rendered as
    ``"line 12 (dir/File.java): message"`` so the step keeps its file (the
    SARIF parser drops it) and ``": "`` still separates the message.
    """
    rendered: list[str] = []
    for step in steps or []:
        if isinstance(step, str):
            if step.strip():
                rendered.append(step)
            continue
        if not isinstance(step, dict) or not step.get("line"):
            continue
        text = f"line {int(step['line'])}"
        if step.get("file"):
            text += f" ({step['file']})"
        if step.get("message"):
            text += f": {step['message']}"
        rendered.append(text)
    return rendered


def filter_for_approach(
    entries: list[GroundTruthEntry], approach: BenchmarkApproach
) -> tuple[list[GroundTruthEntry], int]:
    """Drop line-unanchored entries for a line-anchored approach (#125).

    Returns ``(kept_entries, dropped_count)``. Non-line-anchored approaches
    (e.g. raw-sast) keep every entry.
    """
    if not getattr(approach, "line_anchored", False):
        return list(entries), 0
    kept = [e for e in entries if e.is_line_anchored]
    return kept, len(entries) - len(kept)


def verdict_to_pred(verdict_str: str) -> str:
    """Map a VulnHunterX verdict string to a benchmark prediction label."""
    return _VERDICT_MAP.get(verdict_str, PRED_ERROR)


class _SnippetContextExtractor(ContextExtractor):
    """A ContextExtractor that returns an in-memory code snippet.

    Used by benchmark approaches so code from GroundTruthEntry.code_snippet
    is passed directly to the LLM without needing files on disk.

    When ``use_slicing=True``, delegates to ``SlicedContextExtractor`` for
    variable-aware code slicing instead of returning the full snippet.
    """

    def __init__(
        self,
        code_snippet: str,
        function_name: str,
        use_slicing: bool = False,
        finding: Finding | None = None,
    ) -> None:
        # Do not call super().__init__ â€” we bypass disk I/O entirely
        self._snippet = code_snippet
        self._func_name = function_name
        self._use_slicing = use_slicing
        self._finding = finding

    def get_context(
        self,
        file_path: str,
        line: int,
        lang: str,
        context_lines: int = 50,
        repo_name: str = "",
    ) -> CodeContext:  # type: ignore[override]
        if self._use_slicing and self._finding is not None:
            # Use the last non-empty line as target_line â€” vulnerabilities are typically
            # near the end of a function (after setup code), not at line 1.
            snippet_lines = self._snippet.splitlines()
            last_nonempty = max(
                (i + 1 for i, ln in enumerate(snippet_lines) if ln.strip()),
                default=1,
            )
            slicer = SlicedContextExtractor(
                code=self._snippet,
                target_line=last_nonempty,
                message=self._finding.message,
            )
            return slicer.extract(self._finding)
        return CodeContext(
            code=self._snippet,
            function_name=self._func_name or "<benchmark>",
            start_line=1,
            end_line=len(self._snippet.splitlines()),
            file_path=file_path,
        )


def _dry_run_result(entry: GroundTruthEntry, approach_name: str) -> BenchmarkResult:
    """Return a deterministic mock result for dry-run testing."""
    import hashlib

    seed = int(hashlib.md5(entry.id.encode()).hexdigest()[:4], 16) % 3  # noqa: S324
    labels = ["TP", "FP", "NMD"]
    return BenchmarkResult(
        entry=entry,
        predicted_label=labels[seed],
        confidence="Medium",
        reasoning=f"[dry-run] {approach_name} mock result",
        elapsed_seconds=0.001,
        tokens_used=0,
        cost_usd=0.0,
        iterations=1,
    )
