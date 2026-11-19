"""B3a: CodeQL scan of the renamed OWASP copy and the alert manifest (plan v3.3 §5.2 B3a).

Two subcommands:

``scan``      codeql database create (build mode none) + analyze (java-security-extended) → SARIF
``manifest``  SARIF + name map + expected results → manifest JSONL, counts and the data-flow
              "leaves the flagged method" share (v3.3 §5.3 hard-condition gate, 30%).

The manifest and every output stay outside the scanned copy. Labels are joined here, from the
expected-results file through the name map; nothing in the copy carries a label.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

from scripts.exp._java_ast import enclosing_method, file_sha256, method_spans
from vuln_hunter_x.sarif.parser import _normalize_cwe

SUITE = "codeql/java-queries:codeql-suites/java-security-extended.qls"
EXCLUDED_RULES = frozenset({"java/exec-tainted-environment", "java/relative-path-command"})
FAMILY_CWE = {"sqli": "CWE-89", "cmdi": "CWE-78", "pathtraver": "CWE-22"}
CWE_FAMILY = {v: k for k, v in FAMILY_CWE.items()}


# ── scan ─────────────────────────────────────────────────────────────────────


def _codeql(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["codeql", *args], capture_output=True, text=True, check=False)


def run_scan(
    source_root: Path, work_dir: Path, sarif_copy: Path | None, threads: int, ram: int
) -> Path:
    db = work_dir / "db"
    sarif = work_dir / f"{source_root.name}.sarif"
    if db.exists():
        shutil.rmtree(db)
    work_dir.mkdir(parents=True, exist_ok=True)
    version = _codeql("version", "--format=json").stdout
    (work_dir / "codeql_version.json").write_text(version, encoding="utf-8")
    steps = [
        (
            "database create",
            [
                "database", "create", str(db), "--language=java", "--build-mode=none",
                f"--source-root={source_root}", f"--threads={threads}", f"--ram={ram}",
            ],
        ),
        (
            "database analyze",
            [
                "database", "analyze", str(db), SUITE, "--format=sarif-latest",
                f"--output={sarif}", f"--threads={threads}", f"--ram={ram}",
            ],
        ),
    ]
    for label, args in steps:
        proc = _codeql(*args)
        (work_dir / f"codeql_{label.replace(' ', '_')}.log").write_text(
            proc.stdout + "\n" + proc.stderr, encoding="utf-8"
        )
        if proc.returncode != 0:
            raise SystemExit(f"codeql {label} failed (rc {proc.returncode}); see {work_dir}")
    if sarif_copy is not None:
        sarif_copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sarif, sarif_copy)
    return sarif


# ── SARIF parsing ────────────────────────────────────────────────────────────


def _loc(physical: dict) -> tuple[str, int]:
    uri = physical.get("artifactLocation", {}).get("uri", "")
    line = physical.get("region", {}).get("startLine", 0)
    return uri.replace("\\", "/"), int(line)


def rule_index(run: dict) -> dict[str, dict]:
    """rule id → {tags, name} gathered from the driver and every extension (query packs)."""
    rules: dict[str, dict] = {}
    comps = [run["tool"]["driver"], *run["tool"].get("extensions", [])]
    for comp in comps:
        for rule in comp.get("rules", []) or []:
            tags = rule.get("properties", {}).get("tags", []) or []
            rules[rule["id"]] = {"tags": tags}
    return rules


def toolchain(run: dict) -> dict:
    out = {"driver": f"{run['tool']['driver'].get('name')} {run['tool']['driver'].get('semanticVersion')}"}
    out["packs"] = {
        e["name"]: e.get("semanticVersion") for e in run["tool"].get("extensions", []) if "name" in e
    }
    return out


def parse_alerts(sarif: dict) -> list[dict]:
    """Flat alert list: rule, message, sink location, normalized CWEs, raw tags, data-flow steps."""
    run = sarif["runs"][0]
    rules = rule_index(run)
    alerts = []
    for res in run.get("results", []):
        rule_id = res.get("ruleId") or res.get("rule", {}).get("id", "")
        tags = rules.get(rule_id, {}).get("tags", [])
        cwe_tags = [t for t in tags if "cwe" in t.lower()]
        cwes = sorted({c for c in (_normalize_cwe(t) for t in cwe_tags) if c})
        locs = res.get("locations") or []
        if not locs:
            continue
        file, line = _loc(locs[0]["physicalLocation"])
        flow: list[dict] = []
        flows = res.get("codeFlows") or []
        if flows and flows[0].get("threadFlows"):
            for step in flows[0]["threadFlows"][0].get("locations", []):
                phys = step.get("location", {}).get("physicalLocation")
                if phys:
                    f, ln = _loc(phys)
                    flow.append({"file": f, "line": ln})
        alerts.append(
            {
                "rule_id": rule_id,
                "message": res.get("message", {}).get("text", ""),
                "file": file,
                "line": line,
                "cwe_ids": cwes,
                "cwe_tags_raw": cwe_tags,
                "data_flow": flow,
            }
        )
    return alerts


# ── selection, labels, metrics ───────────────────────────────────────────────


def load_expected(path: Path) -> dict[str, dict]:
    """``BenchmarkTest00001`` → {category, real (bool)} from expectedresults-1.2.csv."""
    out: dict[str, dict] = {}
    for row in csv.reader(path.open(encoding="utf-8")):
        if not row or row[0].startswith("#"):
            continue
        out[row[0].strip()] = {"category": row[1].strip(), "real": row[2].strip() == "true"}
    return out


def token_to_case(name_map: dict) -> dict[str, str]:
    return {tok: f"BenchmarkTest{num}" for num, tok in name_map["testcases"].items()}


def flow_leaves_method(alert: dict, spans_for: dict[str, list]) -> bool | None:
    """True if any data-flow step is outside the method that contains the sink line.

    None when there is no data-flow path (cannot be decided).
    """
    if not alert["data_flow"]:
        return None
    spans = spans_for[alert["file"]]
    sink = enclosing_method(spans, alert["line"])
    if sink is None:
        return True
    for step in alert["data_flow"]:
        if step["file"] != alert["file"]:
            return True
        if not (sink.start_line <= step["line"] <= sink.end_line):
            return True
    return False


def alert_id(alert: dict) -> str:
    key = f"{alert['rule_id']}|{alert['file']}|{alert['line']}|{alert['message']}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def select_alerts(
    alerts: list[dict], tok_case: dict[str, str], expected: dict[str, dict]
) -> tuple[list[dict], dict]:
    """One alert per test case, of the label's family, preferring a rule with a data-flow path."""
    stats: Counter = Counter()
    by_file: dict[str, list[dict]] = defaultdict(list)
    excluded_files: set[str] = set()
    for a in alerts:
        fams = {CWE_FAMILY[c] for c in a["cwe_ids"] if c in CWE_FAMILY}
        if not fams:
            stats["alerts_outside_three_families"] += 1
            continue
        if a["rule_id"] in EXCLUDED_RULES:
            stats[f"excluded_rule:{a['rule_id']}"] += 1
            excluded_files.add(a["file"])
            continue
        a["_families"] = fams
        by_file[a["file"]].append(a)

    selected: list[dict] = []
    for file, cands in sorted(by_file.items()):
        tok = Path(file).stem
        case = tok_case.get(tok)
        if case is None:
            stats["alerts_in_non_testcase_files"] += len(cands)
            continue
        exp = expected.get(case)
        if exp is None or exp["category"] not in FAMILY_CWE:
            stats["alerts_in_testcases_of_other_categories"] += len(cands)
            continue
        fam = exp["category"]
        in_fam = [c for c in cands if fam in c["_families"]]
        stats["alerts_wrong_family_for_case"] += len(cands) - len(in_fam)
        if not in_fam:
            continue
        in_fam.sort(key=lambda c: (not c["data_flow"], c["rule_id"], c["line"]))
        best = in_fam[0]
        stats["extra_alerts_same_case_dropped"] += len(in_fam) - 1
        selected.append(
            {
                **{k: v for k, v in best.items() if not k.startswith("_")},
                "alert_id": alert_id(best),
                "family": fam,
                "label": "genuine" if exp["real"] else "false_alarm",
                "source_case": case,
                "candidates_for_case": len(in_fam),
            }
        )
    # Test cases whose only in-scope alert came from an excluded rule: lost because of the exclusion.
    kept = {a["file"] for a in selected}
    for file in sorted(excluded_files - kept):
        case = tok_case.get(Path(file).stem)
        exp = expected.get(case) if case else None
        if exp and exp["category"] in FAMILY_CWE:
            label = "genuine" if exp["real"] else "false"
            stats[f"cases_left_out_only_excluded_rule:{exp['category']}:{label}"] += 1
    return selected, dict(stats)


def build_manifest(
    sarif_path: Path,
    copy_dir: Path,
    name_map: dict,
    expected_csv: Path,
    copy_name: str,
) -> tuple[list[dict], dict]:
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    alerts = parse_alerts(sarif)
    expected = load_expected(expected_csv)
    selected, stats = select_alerts(alerts, token_to_case(name_map), expected)

    spans_for: dict[str, list] = {}
    for a in selected:
        spans_for.setdefault(a["file"], method_spans((copy_dir / a["file"]).read_bytes()))
    for a in selected:
        a["flow_leaves_method"] = flow_leaves_method(a, spans_for)
        a["copy_name"] = copy_name
    selected.sort(key=lambda a: (a["file"], a["line"], a["rule_id"]))

    cases_by = Counter((e["category"], e["real"]) for e in expected.values() if e["category"] in FAMILY_CWE)
    got = Counter((a["family"], a["label"] == "genuine") for a in selected)
    leave: dict[str, dict] = {}
    for fam in (*FAMILY_CWE, "all"):
        gen = [a for a in selected if a["label"] == "genuine" and (fam == "all" or a["family"] == fam)]
        leaves = sum(1 for a in gen if a["flow_leaves_method"] is True)
        no_flow = sum(1 for a in gen if a["flow_leaves_method"] is None)
        leave[fam] = {
            "genuine_alerts": len(gen),
            "with_flow": len(gen) - no_flow,
            "no_flow": no_flow,
            "leaves_method": leaves,
            "share_of_genuine": round(leaves / len(gen), 4) if gen else None,
        }
    table = {
        fam: {
            "genuine_alerts": got[(fam, True)],
            "false_alarms": got[(fam, False)],
            "cases_genuine": cases_by[(fam, True)],
            "cases_false": cases_by[(fam, False)],
            "genuine_cases_without_alert": cases_by[(fam, True)] - got[(fam, True)],
            "false_cases_without_alert": cases_by[(fam, False)] - got[(fam, False)],
        }
        for fam in FAMILY_CWE
    }
    report = {
        "alerts_total_in_sarif": len(alerts),
        "alerts_with_code_flows": sum(1 for a in alerts if a["data_flow"]),
        "selection_stats": stats,
        "by_family_label": table,
        "manifest_entries": len(selected),
        "genuine": sum(1 for a in selected if a["label"] == "genuine"),
        "false_alarms": sum(1 for a in selected if a["label"] == "false_alarm"),
        "flow_leaves_method": leave,
        "toolchain": toolchain(sarif["runs"][0]),
        "reference_zerofalse": {"alerts": 868, "genuine": 531, "false_alarms": 337},
    }
    return selected, report


def write_manifest(entries: list[dict], out: Path) -> str:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for e in entries:
            fh.write(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n")
    digest = file_sha256(out)
    out.with_name(out.name + ".sha256").write_text(f"{digest}  {out.name}\n", encoding="utf-8")
    return digest


# ── CLI ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan")
    sc.add_argument("--source-root", type=Path, required=True)
    sc.add_argument("--work-dir", type=Path, required=True)
    sc.add_argument("--sarif-copy", type=Path, help="e.g. output/java/<copy>/<copy>.sarif")
    sc.add_argument("--threads", type=int, default=8)
    sc.add_argument("--ram", type=int, default=16384)

    mf = sub.add_parser("manifest")
    mf.add_argument("--sarif", type=Path, required=True)
    mf.add_argument("--copy-dir", type=Path, required=True)
    mf.add_argument("--name-map", type=Path, required=True)
    mf.add_argument("--expected", type=Path, required=True)
    mf.add_argument("--out", type=Path, required=True, help="manifest .jsonl (outside the copy)")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        sarif = run_scan(args.source_root, args.work_dir, args.sarif_copy, args.threads, args.ram)
        print(f"sarif: {sarif}\nsha256: {file_sha256(sarif)}")
        return 0

    name_map = json.loads(args.name_map.read_text(encoding="utf-8"))
    entries, report = build_manifest(
        args.sarif, args.copy_dir, name_map, args.expected, name_map["copy_name"]
    )
    report["manifest_sha256"] = write_manifest(entries, args.out)
    report["sarif_sha256"] = file_sha256(args.sarif)
    report["name_map_sha256"] = file_sha256(args.name_map)
    report_path = args.out.with_name("b3a_report.json")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
