# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B3c: the alert-manifest adapter (plan v3.3 §5.2). Synthetic manifests only."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from benchmarks.adapters.manifest_adapter import (
    FAMILY_CWE,
    ManifestAdapter,
    ManifestError,
    numbered_window,
)
from benchmarks.adapters.redaction import has_redaction_rules
from benchmarks.adapters.registry import adapters_in_family, get_adapter, load_dataset
from benchmarks.approaches.base import (
    MODEL_VISIBLE_METADATA_KEYS,
    ROUTING_METADATA_KEYS,
    BenchmarkApproach,
    BenchmarkResult,
    entry_to_finding,
    filter_for_approach,
)
from benchmarks.approaches.repo_context import RepoContextApproach

_SENTINEL = "ZZLEAKZZ"
_SOURCE = "\n".join(f"line {i}" for i in range(1, 31)) + "\n"


def _row(n: int = 1, **over) -> dict:
    row = {
        "alert_id": f"a{n:04d}",
        "candidates_for_case": 1,
        "copy_name": "app-01",
        "cwe_ids": ["CWE-564", "CWE-89"],
        "cwe_tags_raw": ["external/cwe/cwe-089", "external/cwe/cwe-564"],
        "data_flow": [
            {"file": "com/acme/A.java", "line": 3},
            {"file": "com/acme/A.java", "line": 9},
        ],
        "family": "sqli",
        "file": "com/acme/A.java",
        "flow_leaves_method": False,
        "label": "genuine",
        "line": 9,
        "message": "Query built from a user-provided value.",
        "rule_id": "java/sql-injection",
        "source_case": f"{_SENTINEL}-BenchmarkTest{n:05d}",
        "source_id": f"{_SENTINEL}-gt{n}",
        "source_cwe": "CWE-89",
        "track": "owasp",
        "source": "owasp",
    }
    row.update(over)
    return row


def _write(
    tmp_path: Path, rows: list[dict], *, sidecar: bool = True, name: str = "m.jsonl"
) -> Path:
    path = tmp_path / name
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    if sidecar:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        (tmp_path / (name + ".sha256")).write_text(f"{digest}  {name}\n", encoding="utf-8")
    return path


def _load(path: Path, **options):
    return load_dataset("alert-manifest", Path("."), options={"manifest": str(path), **options})


# ── registration and mapping ─────────────────────────────────────────────────


def test_registered_without_redaction_rules():
    assert get_adapter("alert-manifest") is ManifestAdapter
    assert "alert-manifest" in adapters_in_family("exp")
    assert not has_redaction_rules("alert-manifest")


def test_one_entry_per_row_in_order(tmp_path):
    rows = [_row(i, label="genuine" if i % 2 else "false_alarm") for i in range(1, 8)]
    entries = _load(_write(tmp_path, rows), snippet_window="0")
    assert [e.id for e in entries] == [r["alert_id"] for r in rows]
    assert [e.label for e in entries] == ["TP", "FP", "TP", "FP", "TP", "FP", "TP"]


@pytest.mark.parametrize(
    ("family", "cwe"), [("sqli", "CWE-89"), ("cmdi", "CWE-78"), ("pathtraver", "CWE-22")]
)
def test_family_maps_to_the_reported_cwe(tmp_path, family, cwe):
    (entry,) = _load(_write(tmp_path, [_row(family=family)]), snippet_window="0")
    assert entry.cwe_id == cwe == FAMILY_CWE[family]


def test_entry_fields(tmp_path):
    (entry,) = _load(_write(tmp_path, [_row()]), snippet_window="0")
    assert (entry.file_path, entry.start_line, entry.sink_line, entry.lang) == (
        "com/acme/A.java",
        9,
        9,
        "java",
    )
    assert entry.rule_id == "java/sql-injection" and entry.is_line_anchored
    meta = entry.metadata
    assert meta["repo_name"] == "app-01" and meta["lang"] == "java"
    assert meta["cwe_ids"] == ["CWE-564", "CWE-89"]
    assert meta["dataflow_path"][1] == {"file": "com/acme/A.java", "line": 9}


# ── the harness contract ─────────────────────────────────────────────────────


def test_every_entry_passes_filter_for_approach_for_vulnhunterx_repo(tmp_path):
    entries = _load(_write(tmp_path, [_row(i) for i in range(1, 6)]), snippet_window="0")
    kept, dropped = filter_for_approach(entries, RepoContextApproach())
    assert dropped == 0 and len(kept) == len(entries) == 5


def test_entry_to_finding_gets_cwe_ids_and_dataflow(tmp_path):
    (entry,) = _load(_write(tmp_path, [_row()]), snippet_window="0")
    finding = entry_to_finding(entry)
    assert finding.cwe_ids == ["CWE-564", "CWE-89"]
    assert finding.dataflow_path == [
        "line 3 (com/acme/A.java)",
        "line 9 (com/acme/A.java)",
    ]
    assert finding.file == "com/acme/A.java" and finding.start_line == 9


# ── no label leakage ─────────────────────────────────────────────────────────


def test_nothing_label_bearing_is_copied_into_the_entry(tmp_path):
    (entry,) = _load(_write(tmp_path, [_row()]), snippet_window="0")
    assert _SENTINEL not in json.dumps({k: v for k, v in entry.to_dict().items() if k != "label"})
    banned = {"source_case", "source_id", "source_cwe", "label"}
    assert not banned & set(entry.metadata)


def test_label_does_not_change_what_a_model_can_see(tmp_path):
    a = _load(_write(tmp_path, [_row(label="genuine")]), snippet_window="0")[0]
    b = _load(_write(tmp_path, [_row(label="false_alarm")], name="n.jsonl"), snippet_window="0")[0]
    assert a.label != b.label
    assert entry_to_finding(a).to_dict() == entry_to_finding(b).to_dict()


def test_approach_reads_only_allow_listed_metadata(tmp_path):
    (entry,) = _load(_write(tmp_path, [_row()]), snippet_window="0")

    class Spy(dict):
        reads: set[str]

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.reads = set()

        def get(self, key, default=None):
            self.reads.add(key)
            return super().get(key, default)

        def __getitem__(self, key):
            self.reads.add(key)
            return super().__getitem__(key)

    entry.metadata = Spy(entry.metadata)
    entry_to_finding(entry)
    assert entry.metadata.reads <= MODEL_VISIBLE_METADATA_KEYS
    assert not (entry.metadata.reads & ROUTING_METADATA_KEYS)  # routing is the approach's read


# ── strictness ───────────────────────────────────────────────────────────────


def test_missing_sidecar_is_refused_but_can_be_waived(tmp_path):
    path = _write(tmp_path, [_row()], sidecar=False)
    with pytest.raises(ManifestError, match="sidecar is absent"):
        _load(path)
    assert len(_load(path, strict_hash="false", snippet_window="0")) == 1


def test_wrong_hash_is_refused(tmp_path):
    path = _write(tmp_path, [_row()])
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")  # now differs
    with pytest.raises(ManifestError, match="mismatch"):
        _load(path)


@pytest.mark.parametrize(
    ("over", "fragment"),
    [
        ({"label": "pending"}, "waiting for a student label"),
        ({"label": "TP"}, "label"),
        ({"family": "xss"}, "family"),
        ({"file": "../etc/passwd"}, "unsafe file path"),
        ({"file": "a\\b.java"}, "unsafe file path"),
        ({"file": "/abs/A.java"}, "unsafe file path"),
        ({"copy_name": "a/b"}, "unsafe copy name"),
        ({"copy_name": ".."}, "unsafe copy name"),
        ({"line": 0}, "line"),
        ({"line": "x"}, "line"),
        ({"data_flow": [{"file": "A.java"}]}, "data_flow"),
        ({"data_flow": [{"file": "../x", "line": 1}]}, "unsafe data_flow"),
    ],
)
def test_bad_rows_are_errors_not_skipped(tmp_path, over, fragment):
    with pytest.raises(ManifestError, match=fragment):
        _load(_write(tmp_path, [_row(1), _row(2, **over)]), snippet_window="0")


def test_missing_required_field_and_duplicate_id(tmp_path):
    bad = _row(2)
    del bad["rule_id"]
    with pytest.raises(ManifestError, match="missing rule_id"):
        _load(_write(tmp_path, [_row(1), bad]), snippet_window="0")
    with pytest.raises(ManifestError, match="duplicate alert_id"):
        _load(_write(tmp_path, [_row(1), _row(1)], name="d.jsonl"), snippet_window="0")


def test_manifest_option_is_required_and_file_must_exist(tmp_path):
    with pytest.raises(ManifestError, match="manifest="):
        load_dataset("alert-manifest", Path("."), options={})
    with pytest.raises(FileNotFoundError):
        _load(tmp_path / "nope.jsonl")


def test_limit_takes_the_first_rows(tmp_path):
    entries = load_dataset(
        "alert-manifest",
        Path("."),
        limit=2,
        options={
            "manifest": str(_write(tmp_path, [_row(i) for i in range(1, 6)])),
            "snippet_window": "0",
        },
    )
    assert [e.id for e in entries] == ["a0001", "a0002"]


# ── code_snippet for the single call ─────────────────────────────────────────


def _copy(tmp_path: Path) -> Path:
    repos = tmp_path / "repos"
    target = repos / "java" / "app-01" / "com" / "acme"
    target.mkdir(parents=True)
    (target / "A.java").write_text(_SOURCE, encoding="utf-8")
    return repos


def test_snippet_is_a_numbered_window_around_the_flagged_line(tmp_path):
    repos = _copy(tmp_path)
    (entry,) = _load(_write(tmp_path, [_row(line=9)]), repos_dir=str(repos), snippet_window="2")
    assert entry.code_snippet.splitlines() == [
        "7: line 7",
        "8: line 8",
        "9: line 9",
        "10: line 10",
        "11: line 11",
    ]


def test_snippet_window_is_clamped_at_file_edges():
    assert numbered_window("a\nb\nc\n", 1, 5) == "1: a\n2: b\n3: c"


def test_missing_source_gives_no_snippet_and_a_warning(tmp_path, caplog):
    import logging

    with caplog.at_level(logging.WARNING):
        (entry,) = _load(_write(tmp_path, [_row()]), repos_dir=str(tmp_path / "none"))
    assert entry.code_snippet == ""
    assert any("no code_snippet" in r.getMessage() for r in caplog.records)


def test_snippet_never_reads_outside_the_copy(tmp_path):
    repos = _copy(tmp_path)
    secret = tmp_path / "secret.java"
    secret.write_text("TOPSECRET\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="unsafe file path"):
        _load(_write(tmp_path, [_row(file="../../../../secret.java")]), repos_dir=str(repos))


# ── through the harness ──────────────────────────────────────────────────────


class _Stub(BenchmarkApproach):
    name = "vulnhunterx-repo"
    line_anchored = True
    seen = 0

    def evaluate(self, entry):
        _Stub.seen += 1
        return BenchmarkResult(
            entry=entry, predicted_label="NMD", confidence="", reasoning="", elapsed_seconds=0.0
        )


@pytest.mark.parametrize("extra", [[], ["--anchor", "none", "--no-redact"]])
def test_harness_entry_count_equals_manifest_lines(tmp_path, monkeypatch, extra):
    from benchmarks.scripts import run_benchmark as rb

    path = _write(tmp_path, [_row(i) for i in range(1, 8)])
    _Stub.seen = 0
    monkeypatch.setattr(rb, "_build_approach", lambda *a, **k: _Stub())
    monkeypatch.setattr(rb, "_setup_logging", lambda _d: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_benchmark.py",
            "--dataset",
            "alert-manifest",
            "--dataset-option",
            f"manifest={path}",
            "--dataset-option",
            "snippet_window=0",
            "--approach",
            "vulnhunterx-repo",
            "--dry-run",
            "--skip-preflight",
            "--quiet",
            "--run-dir",
            str(tmp_path / "run"),
            *extra,
        ],
    )
    assert rb.main() == 0
    assert _Stub.seen == 7  # every manifest row reached the approach
