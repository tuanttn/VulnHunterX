# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""B3c: the development manifest (plan v3.3 §3.4, v3.2 §3.3).

Sources, all development data that is never reported as a result:

* **Juliet Java 1.3** (the redacted copy ``suite-java``): per family (SQLi, command
  injection, path traversal = CWE-23 + CWE-36) 100 sampling units that have a CodeQL
  alert, drawn with a fixed seed, at least 50 genuine. A unit is one (file, label)
  pair: the ``bad*`` methods of a file are one test case and its ``good*`` methods
  another, because Juliet scores them independently. One alert per unit (a rule with a
  data-flow path first). Alerts outside every ``bad*``/``good*`` method are left out
  and counted. This reading of "case" is Khoa's; it is the one place the sampling rule
  is interpreted.
* **WebGoat and VulnerableApp**: an alert that lies in a RealVuln ground-truth location
  is genuine. Other alerts of the three families are *pending* (they go to the student
  sheet) and are not in the manifest.

The pooled rule of v3.3 §2 is evaluated here: a family with fewer than 20 development
false alarms is reported as ``pooled``.

Outputs (outside git): ``dev_manifest.jsonl`` (+ ``.sha256``), ``dev_pending.jsonl``,
``dev_report.json``. No model call. Labels come only from the Juliet label map and the
RealVuln ground truth.

    python -m scripts.exp.b3c_dev_manifest --work-root ../exp-data/work \\
        --realvuln ../exp-data/datasets/Real-Vuln-Benchmark --repos-dir repos/java \\
        --out-dir ../exp-data/work/dev
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from scripts.exp.b3a_scan_manifest import FAMILY_CWE, parse_alerts, toolchain, write_manifest
from scripts.exp.b7_build import (
    LABEL_FALSE_ALARM,
    LABEL_GENUINE,
    LABEL_PENDING,
    count_by,
    flow_leaves_for,
    make_row,
)
from scripts.exp.b7_match import (
    alert_family,
    load_ground_truth,
    match_alerts,
    one_alert_per_location,
    scope_alerts,
)
from scripts.exp.dev_data_prep import label_for_line

POOLED_BELOW = 20  # v3.3 §2: fewer false alarms than this in a family -> pooled rule
JULIET_COPY = "suite-java"
APPS = (
    ("webgoat", "webgoat-java", "realvuln-webgoat"),
    ("vulnerableapp", "vulnerableapp-java", "realvuln-vulnerableapp"),
)


def juliet_units(
    sarif: dict[str, Any], name_map: dict[str, Any], label_map: dict[str, Any]
) -> tuple[list[dict[str, Any]], Counter]:
    """One candidate alert per (file, label) unit, with the unit's label attached."""
    alerts, stats = scope_alerts(parse_alerts(sarif))
    dir_family = name_map["dir_family"]
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for alert in alerts:
        parts = alert["file"].split("/")
        if parts[0] != "suite" or len(parts) < 3 or parts[1] not in dir_family:
            stats["alerts_in_support_or_other_files"] += 1
            continue
        if alert_family(alert) != dir_family[parts[1]]:
            stats["alerts_wrong_family_for_dir"] += 1
            continue
        entry = label_map.get(alert["file"])
        label = label_for_line(entry, alert["line"]) if entry else None
        if label is None:
            stats["alerts_outside_bad_and_good"] += 1
            continue
        groups.setdefault((alert["file"], label), []).append(alert)
    units: list[dict[str, Any]] = []
    for (file, label), group in groups.items():
        best = min(group, key=lambda a: (not a["data_flow"], a["rule_id"], a["line"], a["message"]))
        orig = label_map[file].get("orig", file)
        units.append(
            {
                **best,
                "family": dir_family[file.split("/")[1]],
                "candidates": len(group),
                "unit_label": "genuine" if label == "bad" else "false_alarm",
                "source_case": f"{orig}#{label}",
            }
        )
    units.sort(key=lambda u: (u["file"], u["line"], u["rule_id"]))
    return units, stats


def sample_units(
    units: list[dict[str, Any]], seed: str, per_family: int = 100, min_genuine: int = 50
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Per family: up to ``per_family - min_genuine`` false alarms, the rest genuine.

    Draws are seeded per (family, label), so adding a family does not change another.
    Genuine never drops below ``min_genuine`` unless the pool itself is smaller
    (``shortfall`` says so).
    """
    chosen: list[dict[str, Any]] = []
    report: dict[str, Any] = {}
    for family in FAMILY_CWE:
        pools = {
            label: sorted(
                (u for u in units if u["family"] == family and u["unit_label"] == label),
                key=lambda u: (u["file"], u["line"], u["rule_id"]),
            )
            for label in ("genuine", "false_alarm")
        }
        n_false = min(len(pools["false_alarm"]), per_family - min_genuine)
        n_genuine = min(len(pools["genuine"]), per_family - n_false)
        picked = {
            "false_alarm": random.Random(f"{seed}:{family}:false_alarm").sample(
                pools["false_alarm"], n_false
            ),
            "genuine": random.Random(f"{seed}:{family}:genuine").sample(
                pools["genuine"], n_genuine
            ),
        }
        chosen += picked["false_alarm"] + picked["genuine"]
        report[family] = {
            "units_available": {k: len(v) for k, v in pools.items()},
            "units_selected": {k: len(v) for k, v in picked.items()},
            "shortfall": per_family - n_false - n_genuine,
            "genuine_at_least_min": n_genuine >= min_genuine,
        }
    chosen.sort(key=lambda u: (u["file"], u["line"], u["rule_id"]))
    return chosen, report


def juliet_rows(
    chosen: list[dict[str, Any]], copy_name: str, copy_dir: Path
) -> list[dict[str, Any]]:
    cache: dict[str, list] = {}
    return [
        make_row(
            u,
            copy_name=copy_name,
            label=u["unit_label"],
            track="dev",
            source="juliet",
            source_case=u["source_case"],
            flow_leaves=flow_leaves_for(u, copy_dir, cache),
        )
        for u in chosen
    ]


def app_rows(
    sarif: dict[str, Any],
    ground_truth: list[dict[str, Any]],
    *,
    copy_name: str,
    copy_dir: Path,
    source: str,
) -> dict[str, Any]:
    """Genuine rows (alerts in a ground-truth location) and pending rows (the rest)."""
    alerts, stats = scope_alerts(parse_alerts(sarif))
    result = match_alerts(one_alert_per_location(alerts), ground_truth)
    cache: dict[str, list] = {}

    def row(alert: dict[str, Any], label: str) -> dict[str, Any]:
        return make_row(
            alert,
            copy_name=copy_name,
            label=label,
            track="dev",
            source=source,
            source_cwe=alert.get("source_cwe", ""),
            source_id=alert.get("source_id", ""),
            flow_leaves=flow_leaves_for(alert, copy_dir, cache),
        )

    return {
        "genuine": [row(a, LABEL_GENUINE) for a in result["matched"]],
        "pending": [row(a, LABEL_PENDING) for a in result["unmatched"]],
        "gt_entries": len(ground_truth),
        "gt_flagged": len(result["gt_flagged"]),
        "gt_unflagged": [g["id"] for g in result["gt_unflagged"]],
        "stats": dict(stats),
    }


def pooled_rule(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Development false alarms per family and whether v3.3's pooled rule applies."""
    counts = Counter(r["family"] for r in rows if r["label"] == LABEL_FALSE_ALARM)
    per_family = {f: counts.get(f, 0) for f in FAMILY_CWE}
    return {
        "false_alarms_per_family": per_family,
        "threshold": POOLED_BELOW,
        "pooled_families": [f for f, n in per_family.items() if n < POOLED_BELOW],
        "pooled_false_alarms": sum(per_family.values()),
    }


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--work-root", type=Path, required=True, help="exp-data/work")
    ap.add_argument("--realvuln", type=Path, required=True, help="Real-Vuln-Benchmark checkout")
    ap.add_argument("--repos-dir", type=Path, required=True, help="repos/java")
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--seed", default="vhx-dev-v33-seed1")
    args = ap.parse_args(argv)

    juliet_dir = args.work_root / JULIET_COPY
    sarif = json.loads((juliet_dir / f"{JULIET_COPY}.sarif").read_text(encoding="utf-8"))
    name_map = json.loads((juliet_dir / "name_map.json").read_text(encoding="utf-8"))
    label_map = json.loads((juliet_dir / "label_map.json").read_text(encoding="utf-8"))
    units, juliet_stats = juliet_units(sarif, name_map, label_map)
    chosen, sampling = sample_units(units, args.seed)
    rows = juliet_rows(chosen, JULIET_COPY, args.repos_dir / JULIET_COPY)
    report: dict[str, Any] = {
        "seed": args.seed,
        "toolchain": toolchain(sarif["runs"][0]),
        "juliet": {
            "units_total": len(units),
            "stats": dict(juliet_stats),
            "sampling": sampling,
        },
        "apps": {},
    }

    pending: list[dict[str, Any]] = []
    families_json = args.realvuln / "config" / "cwe-families.json"
    for source, copy_name, repo_id in APPS:
        app_sarif = json.loads(
            (args.work_root / copy_name / f"{copy_name}.sarif").read_text(encoding="utf-8")
        )
        gt = load_ground_truth(
            args.realvuln / "ground-truth" / repo_id / "ground-truth.json", families_json
        )
        built = app_rows(
            app_sarif, gt, copy_name=copy_name, copy_dir=args.repos_dir / copy_name, source=source
        )
        rows += built["genuine"]
        pending += built["pending"]
        report["apps"][source] = {
            k: built[k] for k in ("gt_entries", "gt_flagged", "gt_unflagged", "stats")
        } | {"genuine": len(built["genuine"]), "pending": len(built["pending"])}

    rows.sort(key=lambda r: (r["copy_name"], r["file"], r["line"], r["rule_id"]))
    pending.sort(key=lambda r: (r["copy_name"], r["file"], r["line"], r["rule_id"]))
    ids = [r["alert_id"] for r in rows + pending]
    if len(ids) != len(set(ids)):
        print("error: duplicate alert_id in the development rows", file=sys.stderr)
        return 1

    manifest = args.out_dir / "dev_manifest.jsonl"
    report["manifest_sha256"] = write_manifest(rows, manifest)
    report["pending_sha256"] = write_manifest(pending, args.out_dir / "dev_pending.jsonl")
    report["entries"] = len(rows)
    report["by_source_family_label"] = count_by(rows, "source", "family", "label")
    report["pending_by_source_family"] = count_by(pending, "source", "family")
    report["pooled_rule"] = pooled_rule(rows)
    (args.out_dir / "dev_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "entries",
                    "by_source_family_label",
                    "pending_by_source_family",
                    "pooled_rule",
                )
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
