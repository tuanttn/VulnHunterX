# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""B2 impact: which benchmark entries change route now that CWE ids reach the engine.

Before B2, ``entry_to_finding`` left ``Finding.cwe_ids`` empty, so a family
policy was selected only by a rule-id alias; every other entry took the legacy
path. After B2 the entry's CWE ids are passed on, so an entry whose CWE a family
owns moves to the policy path. Every dataset with such entries gives different
verdicts than its earlier baseline and has to be re-run before its numbers are
compared with anything produced before B2.

The route depends only on ``(lang, rule_id, CWE ids)``, so this check needs no
model and no dataset checkout: it reads entry files (a JSON list in the
``GroundTruthEntry`` format, e.g. ``benchmarks/fixtures/*_sample.json`` or an
exported dataset) and prints, per dataset, language and CWE, the route before
and after. It does not run the verifier.

    python -m scripts.exp.b2_route_impact                       # bundled fixtures
    python -m scripts.exp.b2_route_impact path/to/entries.json ...

Exit code 0 always (it is a report); 2 on unreadable input.
"""

from __future__ import annotations

import argparse
import collections
import sys
from collections.abc import Sequence
from pathlib import Path

from benchmarks.adapters.ground_truth import GroundTruthEntry, load_entries
from benchmarks.approaches.base import _entry_cwes
from vuln_hunter_x.verification.policy.loader import PolicyOverlapError, load_policy_registry

_FIXTURES = Path(__file__).resolve().parents[2] / "benchmarks" / "fixtures"
LEGACY = "legacy"
OVERLAP = "OVERLAP"

Key = tuple[str, str, str, str, str]  # dataset, lang, cwe, before, after


def _owner(registry, *, cwe_ids: list[str], rule_id: str, lang: str) -> str:
    try:
        policy = registry.resolve_family(cwe_ids=cwe_ids, rule_id=rule_id, lang=lang)
    except PolicyOverlapError:
        return OVERLAP
    return policy.family if policy else LEGACY


def route_change(registry, entry: GroundTruthEntry) -> tuple[str, str]:
    """``(route before B2, route after B2)`` for one entry."""
    rule_id = entry.rule_id or f"benchmark/{entry.cwe_id.lower().replace('-', '')}"
    cwe_ids, _ = _entry_cwes(entry)
    before = _owner(registry, cwe_ids=[], rule_id=rule_id, lang=entry.lang)
    after = _owner(registry, cwe_ids=cwe_ids, rule_id=rule_id, lang=entry.lang)
    return before, after


def impact(entries: Sequence[GroundTruthEntry]) -> collections.Counter[Key]:
    registry = load_policy_registry()
    counts: collections.Counter[Key] = collections.Counter()
    for entry in entries:
        before, after = route_change(registry, entry)
        counts[(entry.source_dataset, entry.lang, entry.cwe_id or "-", before, after)] += 1
    return counts


def render(counts: collections.Counter[Key]) -> str:
    lines = ["dataset | lang | cwe | route before -> after | entries | changes route"]
    changed_datasets: set[str] = set()
    for (dataset, lang, cwe, before, after), n in sorted(counts.items()):
        changed = before != after
        if changed:
            changed_datasets.add(dataset)
        lines.append(
            f"{dataset} | {lang} | {cwe} | {before} -> {after} | {n} | {'YES' if changed else 'no'}"
        )
    total = sum(counts.values())
    moved = sum(n for (_, _, _, b, a), n in counts.items() if b != a)
    lines.append("")
    lines.append(f"entries {total}; change route {moved}")
    lines.append("datasets to re-baseline: " + (", ".join(sorted(changed_datasets)) or "none"))
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "entries", nargs="*", type=Path, help="entry JSON files (default: fixtures)"
    )
    args = parser.parse_args(argv)
    paths = args.entries or sorted(_FIXTURES.glob("*_sample.json"))
    entries: list[GroundTruthEntry] = []
    try:
        for path in paths:
            entries.extend(load_entries(path))
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(render(impact(entries)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
