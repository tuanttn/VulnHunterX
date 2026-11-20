# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the experiment's alert manifests (B3c, plan v3.3 §5.2).

A manifest is a JSONL file of CodeQL alerts, one alert per test case, written by
the B3a/B7 scripts under ``scripts/exp`` and kept outside the scanned copies. The
adapter turns each row into one ``GroundTruthEntry``. It serves every track: the
OWASP test manifest, the development manifest, the real-application and the
AI-track manifests share one schema.

What a model may see is only what ``entry_to_finding`` reads from the metadata
(``MODEL_VISIBLE_METADATA_KEYS``): ``message``, ``cwe_ids``, ``cwe_tags_raw`` and
``dataflow_path``. ``repo_name`` and ``lang`` only locate the checked-out copy.
The label comes from the manifest and becomes ``entry.label``; fields that carry
it indirectly (the original test name, the source id and CWE) are never copied
into the entry.

The adapter is strict, because the manifest is a frozen input (it is hashed into
``freeze.sha256``): a missing or wrong ``<manifest>.sha256``, an unknown label or
family, a duplicated alert ID, an unsafe path or copy name is an error, never a
skipped row. No redaction rule is registered for it: the copies on disk are
already prepared, and a rule would rewrite ``file_path``.

Manifest content is untrusted data.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

from benchmarks.adapters.cvefixes_diff_adapter import verify_sha256_sidecar
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.adapters.registry import DatasetAdapter, OptionSpec, _to_bool, register_adapter
from vuln_hunter_x.context.repo_paths import resolve_repo_file

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DATASET = "alert-manifest"

# Family of the manifest -> the CWE the benchmark reports it under.
FAMILY_CWE: dict[str, str] = {"sqli": "CWE-89", "cmdi": "CWE-78", "pathtraver": "CWE-22"}
LABELS: dict[str, str] = {"genuine": LABEL_TP, "false_alarm": LABEL_FP}
_REQUIRED = ("alert_id", "rule_id", "file", "line", "label", "family", "copy_name")


class ManifestError(ValueError):
    """A manifest row or the manifest file itself is not acceptable."""


def _safe_component(value: str) -> bool:
    return bool(value) and "/" not in value and "\\" not in value and value not in (".", "..")


def _safe_relative_path(value: str) -> bool:
    if not value or "\\" in value or value.startswith("/"):
        return False
    parts = PurePosixPath(value).parts
    return bool(parts) and ".." not in parts and ":" not in parts[0]


def numbered_window(text: str, line: int, window: int) -> str:
    """``window`` lines either side of ``line`` (1-based), each prefixed ``N: ``."""
    lines = text.splitlines()
    lo = max(1, line - window)
    hi = min(len(lines), line + window)
    return "\n".join(f"{n}: {lines[n - 1]}" for n in range(lo, hi + 1))


def _data_flow(row: dict[str, Any], where: str) -> list[dict[str, Any]]:
    steps = row.get("data_flow") or []
    if not isinstance(steps, list):
        raise ManifestError(f"{where}: data_flow must be a list")
    for step in steps:
        if not isinstance(step, dict) or "file" not in step or "line" not in step:
            raise ManifestError(f"{where}: a data_flow step needs file and line")
    return steps


def row_to_entry(row: dict[str, Any], where: str = "row") -> GroundTruthEntry:
    """Validate one manifest row and build its entry (no snippet yet)."""
    missing = [k for k in _REQUIRED if k not in row]
    if missing:
        raise ManifestError(f"{where}: missing {', '.join(missing)}")
    label = LABELS.get(str(row["label"]))
    if label is None:
        raise ManifestError(
            f"{where}: label {row['label']!r} is not one of {sorted(LABELS)} "
            "(rows waiting for a student label do not belong in a test manifest)"
        )
    family = str(row["family"])
    if family not in FAMILY_CWE:
        raise ManifestError(f"{where}: family {family!r} is not one of {sorted(FAMILY_CWE)}")
    file_path = str(row["file"])
    if not _safe_relative_path(file_path):
        raise ManifestError(f"{where}: unsafe file path {file_path!r}")
    copy_name = str(row["copy_name"])
    if not _safe_component(copy_name):
        raise ManifestError(f"{where}: unsafe copy name {copy_name!r}")
    try:
        line = int(row["line"])
    except (TypeError, ValueError) as exc:
        raise ManifestError(f"{where}: line is not a number") from exc
    if line < 1:
        raise ManifestError(f"{where}: line must be >= 1")
    flow = _data_flow(row, where)
    for step in flow:
        if not _safe_relative_path(str(step["file"])):
            raise ManifestError(f"{where}: unsafe data_flow path {step['file']!r}")

    metadata: dict[str, Any] = {
        # Read by the approaches (see MODEL_VISIBLE_METADATA_KEYS / ROUTING_METADATA_KEYS).
        "repo_name": copy_name,
        "lang": "java",
        "message": str(row.get("message", "")),
        "cwe_ids": list(row.get("cwe_ids") or []),
        "cwe_tags_raw": list(row.get("cwe_tags_raw") or []),
        "dataflow_path": flow,
        # Bookkeeping that no approach reads.
        "track": str(row.get("track", "")),
        "source": str(row.get("source", "")),
        "family": family,
        "copy_name": copy_name,
        "alert_id": str(row["alert_id"]),
    }
    return GroundTruthEntry(
        id=str(row["alert_id"]),
        source_dataset=SOURCE_DATASET,
        cwe_id=FAMILY_CWE[family],
        rule_id=str(row["rule_id"]),
        file_path=file_path,
        function_name="",
        start_line=line,
        lang="java",
        label=label,
        code_snippet="",
        metadata=metadata,
        sink_line=line,
    )


@register_adapter
class ManifestAdapter(DatasetAdapter):
    """Load a frozen alert manifest into one entry per alert."""

    name = SOURCE_DATASET
    langs = ("java",)
    family = "exp"
    option_schema: ClassVar[dict[str, OptionSpec]] = {
        "manifest": OptionSpec(
            coerce=str, default="", help="Path to the manifest JSONL (required)."
        ),
        "repos_dir": OptionSpec(
            coerce=str,
            default="",
            help="repos/ root; copies are read from <repos_dir>/java/<copy> (default: project repos/).",
        ),
        "snippet_window": OptionSpec(
            coerce=int,
            default=40,
            help="Lines either side of the flagged line in code_snippet (single call); 0 = none.",
        ),
        "strict_hash": OptionSpec(
            coerce=_to_bool,
            default=True,
            help="Refuse a manifest whose .sha256 sidecar is missing or wrong.",
        ),
    }
    install_url = ""
    expected_files = ()

    def __init__(self, dataset_path: Path) -> None:
        self._dataset_path = Path(dataset_path)

    def load(
        self,
        limit: int = 0,
        manifest: str = "",
        repos_dir: str = "",
        snippet_window: int = 40,
        strict_hash: bool = True,
        **_: Any,
    ) -> list[GroundTruthEntry]:
        if not manifest:
            raise ManifestError("pass --dataset-option manifest=<path to manifest.jsonl>")
        path = Path(manifest)
        if not path.is_file():
            raise FileNotFoundError(f"manifest not found: {path}")
        status = verify_sha256_sidecar(path)
        if status != "ok":
            message = f"{path.name}: sha256 sidecar is {status}"
            if strict_hash:
                raise ManifestError(message)
            logger.warning(message)

        repos_root = Path(repos_dir) if repos_dir else _PROJECT_ROOT / "repos"
        entries: list[GroundTruthEntry] = []
        seen: set[str] = set()
        no_source = 0
        with path.open(encoding="utf-8") as fh:
            for number, raw in enumerate(fh, 1):
                if not raw.strip():
                    continue
                where = f"{path.name}:{number}"
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ManifestError(f"{where}: not JSON ({exc.msg})") from exc
                if not isinstance(row, dict):
                    raise ManifestError(f"{where}: a manifest row must be an object")
                entry = row_to_entry(row, where)
                if entry.id in seen:
                    raise ManifestError(f"{where}: duplicate alert_id {entry.id}")
                seen.add(entry.id)
                entry.metadata["manifest_path"] = str(path)
                entry.metadata["manifest_sha256_status"] = status
                if snippet_window > 0 and not self._fill_snippet(entry, repos_root, snippet_window):
                    no_source += 1
                entries.append(entry)
                if limit and len(entries) >= limit:
                    break
        if no_source:
            logger.warning(
                "%d of %d entries have no code_snippet: source file not found under %s "
                "(only the single-call baseline uses it)",
                no_source,
                len(entries),
                repos_root,
            )
        return entries

    @staticmethod
    def _fill_snippet(entry: GroundTruthEntry, repos_root: Path, window: int) -> bool:
        source = resolve_repo_file(repos_root, "java", entry.metadata["repo_name"], entry.file_path)
        if source is None or entry.sink_line is None:
            return False
        try:
            text = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        entry.code_snippet = numbered_window(text, entry.sink_line, window)
        return True
