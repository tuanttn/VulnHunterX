"""Day-2 counts for the development tier: alerts by source × family × label (plan v3.3 §3.4).

Juliet     label from the line ranges of bad*/good* methods (label map, kept outside the copy).
           bad → genuine, good → false alarm, outside both → left out and counted.
WebGoat,   an alert that matches a RealVuln ground-truth entry (same file, alert line inside the
VulnerableApp  entry's line range, same family) is genuine. Every other alert is "unlabelled": it
           waits for the two reviewers / handwritten cases and is not counted as false alarm.

Reads SARIF only. No model call.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from scripts.exp.b3a_scan_manifest import EXCLUDED_RULES, parse_alerts
from scripts.exp.dev_data_prep import label_for_line

FAMILY_CWES = {
    "sqli": {"CWE-89", "CWE-564", "CWE-943"},
    "cmdi": {"CWE-78", "CWE-77"},
    "pathtraver": {"CWE-22", "CWE-23", "CWE-36"},
}
# CodeQL tags that identify a family (a rule can carry several CWEs; the main one decides).
ALERT_FAMILY_CWE = {"sqli": {"CWE-89"}, "cmdi": {"CWE-78"}, "pathtraver": {"CWE-22", "CWE-23", "CWE-36"}}


def alert_families(alert: dict) -> set[str]:
    cwes = set(alert["cwe_ids"])
    return {f for f, cs in ALERT_FAMILY_CWE.items() if cwes & cs}


def in_scope(alerts: list[dict]) -> tuple[list[dict], Counter]:
    kept, stats = [], Counter()
    for a in alerts:
        if not alert_families(a):
            stats["outside_three_families"] += 1
        elif a["rule_id"] in EXCLUDED_RULES:
            stats[f"excluded_rule:{a['rule_id']}"] += 1
        else:
            kept.append(a)
    return kept, stats


def count_juliet(sarif: dict, name_map: dict, label_map: dict) -> dict:
    alerts, stats = in_scope(parse_alerts(sarif))
    dir_family = name_map["dir_family"]
    dir_cwe = name_map["dir_cwe_original"]
    cells: Counter = Counter()
    files: dict[tuple, set] = {}
    for a in alerts:
        parts = a["file"].split("/")
        if parts[0] != "suite" or len(parts) < 3 or parts[1] not in dir_family:
            stats["alerts_in_support_or_other_files"] += 1
            continue
        fam = dir_family[parts[1]]
        if fam not in alert_families(a):
            stats["alerts_wrong_family_for_dir"] += 1
            continue
        entry = label_map.get(a["file"])
        label = label_for_line(entry, a["line"]) if entry else None
        name = {"bad": "genuine", "good": "false_alarm", None: "outside_bad_and_good"}[label]
        key = (dir_cwe[parts[1]].split("_")[0], fam, name)
        cells[key] += 1
        files.setdefault(key, set()).add(a["file"])
    table = [
        {"dir": d, "family": f, "label": lab, "alerts": n, "files_with_alert": len(files[(d, f, lab)])}
        for (d, f, lab), n in sorted(cells.items())
    ]
    by_fl: Counter = Counter()
    for (_, f, lab), n in cells.items():
        by_fl[(f, lab)] += n
    return {
        "rows": table,
        "by_family_label": {f"{f}:{lab}": n for (f, lab), n in sorted(by_fl.items())},
        "stats": dict(stats),
    }


def load_ground_truth(path: Path, families_json: Path) -> list[dict]:
    gt = json.loads(path.read_text(encoding="utf-8"))
    fam_cwes = json.loads(families_json.read_text(encoding="utf-8"))["families"]
    cwe_to_family = {}
    for fam, key in (("sqli", "sql_injection"), ("cmdi", "command_injection"), ("pathtraver", "path_traversal")):
        for c in fam_cwes[key]["cwes"]:
            cwe_to_family[c] = fam
    out = []
    for f in gt["findings"]:
        if not f.get("is_vulnerable"):
            continue
        fam = cwe_to_family.get(f.get("primary_cwe"))
        if fam is None:
            continue
        loc = f["location"]
        out.append(
            {
                "id": f["id"],
                "family": fam,
                "file": f["file"].replace("\\", "/"),
                "start": loc["start_line"],
                "end": loc["end_line"],
            }
        )
    return out


def count_app(sarif: dict, gt: list[dict]) -> dict:
    alerts, stats = in_scope(parse_alerts(sarif))
    matched_gt: set[str] = set()
    cells: Counter = Counter()
    for a in alerts:
        fams = alert_families(a)
        hit = [
            g for g in gt
            if g["file"] == a["file"] and g["family"] in fams and g["start"] <= a["line"] <= g["end"]
        ]
        for g in hit:
            matched_gt.add(g["id"])
        fam = sorted(fams)[0]
        cells[(fam, "genuine" if hit else "unlabelled")] += 1
    gt_by_fam = Counter(g["family"] for g in gt)
    gt_hit_by_fam = Counter(g["family"] for g in gt if g["id"] in matched_gt)
    return {
        "by_family_label": {f"{f}:{lab}": n for (f, lab), n in sorted(cells.items())},
        "ground_truth_entries": dict(gt_by_fam),
        "ground_truth_entries_flagged": dict(gt_hit_by_fam),
        "stats": dict(stats),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--work-root", type=Path, required=True, help="exp-data/work")
    ap.add_argument("--realvuln", type=Path, required=True, help="Real-Vuln-Benchmark checkout")
    ap.add_argument("--juliet-copy", default="suite-java")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    report: dict = {}
    jw = args.work_root / args.juliet_copy
    jsarif = jw / f"{args.juliet_copy}.sarif"
    if jsarif.is_file():
        report["juliet"] = count_juliet(
            json.loads(jsarif.read_text(encoding="utf-8")),
            json.loads((jw / "name_map.json").read_text(encoding="utf-8")),
            json.loads((jw / "label_map.json").read_text(encoding="utf-8")),
        )
    for copy, repo_id in (("webgoat-java", "realvuln-webgoat"), ("vulnerableapp-java", "realvuln-vulnerableapp")):
        sarif = args.work_root / copy / f"{copy}.sarif"
        if sarif.is_file():
            gt = load_ground_truth(
                args.realvuln / "ground-truth" / repo_id / "ground-truth.json",
                args.realvuln / "config" / "cwe-families.json",
            )
            report[copy] = count_app(json.loads(sarif.read_text(encoding="utf-8")), gt)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
