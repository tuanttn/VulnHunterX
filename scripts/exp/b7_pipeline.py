# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""B7: manifests for the real-application and AI tracks (plan v3.3 §3.2, §3.3).

Sources (datasets outside the repo, under ``exp-data/datasets``):

* RealVuln Java ``human_authored`` (24 repos, WebGoat and VulnerableApp are development
  data and leave the track: 22) and ``llm_generated`` (39 repos);
* OpenVuln CWE-22 projects of ZeroFalse (5), whose own alerts and labels are used.

Stages, each a sub-command, each safe to repeat:

``inventory``  list the repos and the neutral copy names (no change);
``copy``       copy each checkout without ``.git`` to ``repos/java/<copy>`` and write the
               name map (outside the repo);
``scan``       CodeQL (build mode none, java-security-extended) per copy, a few at a time;
``context``    put the SARIF under ``output/java/<copy>/`` and run tree-sitter ``prepare``;
``manifest``   match alerts to ground truth and write the manifests, the pending list, the
               mismatch list, the report and the student sheet.

Copy names are neutral (``app-NN``, ``gen-NN``, ``oss-NN``). A repo's real name can reach
the model through ``Finding.repo_name`` and some names carry the label ("damn vulnerable",
"seeded"); the map back to the real name stays in ``exp-data/work/b7/name_map.json``.

No model is called. Alerts come from CodeQL (or, for OpenVuln, from the dataset's SARIF);
labels come only from the RealVuln ground truth and OpenVuln's ``ground_truth.csv``.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from scripts.exp.b3a_scan_manifest import SUITE, toolchain, write_manifest
from scripts.exp.b7_build import (
    KEY_COLUMNS,
    LABEL_GENUINE,
    LABEL_PENDING,
    SHEET_COLUMNS,
    build_sheet,
    count_by,
    flow_leaves_for,
    make_row,
    openvuln_rows,
    write_csv,
)
from scripts.exp.b7_match import (
    load_ground_truth,
    match_alerts,
    one_alert_per_location,
    parse_alerts_with_regions,
    scope_alerts,
)

DEV_REPO_IDS = frozenset({"realvuln-webgoat", "realvuln-vulnerableapp"})
HEAVY_JAVA_FILES = 5000  # scanned alone, with more memory
# CodeQL's Java ``--build-mode=none`` still calls the repo's build tool to resolve
# dependencies: ``mvnw``/``mvn`` (pom.xml) and ``gradlew`` (build.gradle is Groovy code
# the repo controls). That runs target-controlled code and needs the network. The copies
# are therefore scanned as plain source, like the OWASP and Juliet copies (no pom).
BUILD_FILE_NAMES = frozenset(
    {
        "pom.xml",
        "mvnw",
        "mvnw.cmd",
        "gradlew",
        "gradlew.bat",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    }
)
BUILD_DIR_NAMES = frozenset({".mvn", "buildSrc", ".gradle"})
# The JVM writes these into the source root when it runs out of memory; they are not
# part of the repo and must not stay in a prepared copy.
CRASH_LOG_PATTERNS = ("hs_err_pid*.log", "replay_pid*.log")
# A query that failed (for example out of heap) leaves its alerts out of the SARIF. The
# SARIF is then a partial result that looks complete, so it is never accepted.
FAILED_QUERY_MARKERS = ("Query failed", "OutOfMemoryError", "is out of memory")
CONTEXT_FILES = ("functions.csv", "callers.csv", "classes.csv")
TRACK_OF = {"realvuln_human": "realapp", "realvuln_ai": "ai", "openvuln": "realapp"}
DEFAULT_SEED = "vhx-b7-v33-seed1"


# ── inventory ────────────────────────────────────────────────────────────────


def count_java_files(root: Path, skip_build: bool = False) -> int:
    """``.java`` files under ``root``, without ``.git``; ``skip_build`` also leaves out
    build-tool directories (``.mvn``, ``buildSrc``, ``gradle/wrapper``): the Maven wrapper
    ships ``MavenWrapperDownloader.java`` and buildSrc holds build logic, not the app."""
    total = 0
    for current, dirs, files in os.walk(root):
        keep = []
        for d in dirs:
            if d == ".git":
                continue
            if skip_build and (
                d in BUILD_DIR_NAMES or (d == "wrapper" and Path(current).name == "gradle")
            ):
                continue
            keep.append(d)
        dirs[:] = keep
        total += sum(1 for f in files if f.endswith(".java"))
    return total


def inventory(exp_data: Path) -> list[dict[str, Any]]:
    """Repos of the two tracks with their neutral copy names, in a fixed order."""
    datasets = exp_data / "datasets"
    ground_truth = datasets / "Real-Vuln-Benchmark" / "ground-truth"
    humans: list[dict[str, Any]] = []
    ais: list[dict[str, Any]] = []
    for gt_file in sorted(ground_truth.glob("*/ground-truth.json")):
        data = json.loads(gt_file.read_text(encoding="utf-8"))
        if data.get("language") != "java":
            continue
        repo_id = gt_file.parent.name
        if data.get("authorship") == "human_authored" and repo_id in DEV_REPO_IDS:
            continue
        source = {"human_authored": "realvuln_human", "llm_generated": "realvuln_ai"}.get(
            data.get("authorship", "")
        )
        if source is None:
            continue
        item = {
            "source": source,
            "repo_id": repo_id,
            "checkout": str(datasets / "realvuln-targets" / repo_id),
            "commit_sha": data.get("commit_sha", ""),
            "ground_truth": str(gt_file),
            "dataset_sarif": "",
        }
        (humans if source == "realvuln_human" else ais).append(item)

    open_dir = datasets / "ZeroFalse" / "OpenVuln"
    ossi: list[dict[str, Any]] = []
    with (open_dir / "Projects_info.csv").open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if row["cwe_id"].replace("CWE-", "").lstrip("0") != "22":
                continue
            slug = row["project_slug"]
            ossi.append(
                {
                    "source": "openvuln",
                    "repo_id": slug,
                    "checkout": str(datasets / "openvuln-projects" / slug),
                    "commit_sha": row.get("buggy_commit_id", ""),
                    "ground_truth": str(open_dir / "ground_truth.csv"),
                    "dataset_sarif": str(open_dir / "sarif-files" / f"{slug}.sarif"),
                }
            )

    out: list[dict[str, Any]] = []
    for prefix, group in (("app", humans), ("gen", ais), ("oss", ossi)):
        for number, item in enumerate(group, 1):
            checkout = Path(item["checkout"])
            out.append(
                {
                    **item,
                    "copy": f"{prefix}-{number:02d}",
                    "track": TRACK_OF[item["source"]],
                    "checkout_exists": checkout.is_dir(),
                    "java_files": count_java_files(checkout) if checkout.is_dir() else 0,
                }
            )
    return out


def is_heavy(item: dict[str, Any]) -> bool:
    return item["java_files"] >= HEAVY_JAVA_FILES


# ── build files ──────────────────────────────────────────────────────────────


def _is_build_file(name: str) -> bool:
    return name in BUILD_FILE_NAMES or name.endswith((".gradle", ".gradle.kts"))


def find_build_files(root: Path, limit: int = 0) -> list[str]:
    """Build-tool files and directories under ``root`` (paths relative, ``/`` separated)."""
    found: list[str] = []
    for current, dirs, files in os.walk(root):
        base = Path(current)
        for d in list(dirs):
            wrapper = d == "wrapper" and base.name == "gradle"
            if d in BUILD_DIR_NAMES or wrapper:
                found.append((base / d).relative_to(root).as_posix() + "/")
                dirs.remove(d)
        found += [(base / f).relative_to(root).as_posix() for f in files if _is_build_file(f)]
        if limit and len(found) >= limit:
            return found[:limit]
    return sorted(found)


def strip_build_files(root: Path) -> list[str]:
    """Delete the build-tool files of a **copy** (never of a dataset checkout)."""
    removed = find_build_files(root)
    for rel in removed:
        target = root / rel.rstrip("/")
        if rel.endswith("/"):
            shutil.rmtree(target, ignore_errors=True)
        else:
            target.unlink(missing_ok=True)
    return removed


def remove_crash_logs(root: Path) -> list[str]:
    """Delete JVM crash logs from a **copy**; returns what was removed."""
    removed: list[str] = []
    for pattern in CRASH_LOG_PATTERNS:
        for found in root.rglob(pattern):
            if ".git" not in found.parts:
                removed.append(found.relative_to(root).as_posix())
                found.unlink(missing_ok=True)
    return sorted(removed)


def _tree_paths(root: Path, *, without_build: bool) -> set[str]:
    out: set[str] = set()
    for current, dirs, files in os.walk(root):
        base = Path(current)
        keep = []
        for d in dirs:
            if d == ".git":
                continue
            if without_build and (
                d in BUILD_DIR_NAMES or (d == "wrapper" and base.name == "gradle")
            ):
                continue
            keep.append(d)
        dirs[:] = keep
        for f in files:
            if without_build and _is_build_file(f):
                continue
            out.add((base / f).relative_to(root).as_posix())
    return out


def copy_differences(checkout: Path, copy_dir: Path) -> dict[str, list[str]]:
    """Files the copy has that the checkout (minus build files) lacks, and the reverse."""
    want = _tree_paths(checkout, without_build=True)
    have = _tree_paths(copy_dir, without_build=False)
    return {"extra_in_copy": sorted(have - want), "missing_in_copy": sorted(want - have)}


def verify_copies(name_map: dict[str, Any], repos_dir: Path) -> dict[str, dict[str, list[str]]]:
    """Per RealVuln copy that differs from its checkout (minus build files)."""
    problems: dict[str, dict[str, list[str]]] = {}
    for copy, info in sorted(name_map["repos"].items()):
        if not info["source"].startswith("realvuln") or info.get("copy_status") != "ok":
            continue
        diff = copy_differences(Path(info["checkout"]), repos_dir / copy)
        if diff["extra_in_copy"] or diff["missing_in_copy"]:
            problems[copy] = diff
    return problems


# ── copy ─────────────────────────────────────────────────────────────────────


def copy_tree(src: Path, dst: Path) -> None:
    """Copy ``src`` to ``dst`` without ``.git``. robocopy on Windows (long paths)."""
    dst.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32" and shutil.which("robocopy"):
        proc = subprocess.run(  # noqa: S603
            [
                "robocopy",
                str(src),
                str(dst),
                "/E",
                "/XD",
                ".git",
                "/NFL",
                "/NDL",
                "/NJH",
                "/NJS",
                "/NP",
                "/R:1",
                "/W:1",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode >= 8:  # robocopy: 0-7 are success codes
            raise RuntimeError(f"robocopy failed ({proc.returncode}): {proc.stdout[-300:]}")
        return
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git"), dirs_exist_ok=True)


def run_copy(items: list[dict[str, Any]], repos_dir: Path, work_dir: Path, force: bool) -> dict:
    """Copy every checkout; write the name map. Returns the map."""
    repos: dict[str, Any] = {}
    for item in items:
        target = repos_dir / item["copy"]
        info = {k: v for k, v in item.items() if k != "copy"}
        try:
            if not item["checkout_exists"]:
                raise FileNotFoundError(f"checkout missing: {item['checkout']}")
            if force and target.exists():
                shutil.rmtree(target)
            if not target.exists():
                copy_tree(Path(item["checkout"]), target)
            expected = item["java_files"]
            if item["source"].startswith("realvuln"):
                removed = strip_build_files(target)
                info["build_files_removed"] = len(removed)
                # Java files inside build-tool directories are not application code
                expected = count_java_files(Path(item["checkout"]), skip_build=True)
                info["java_files_checkout"] = item["java_files"]
                info["java_files"] = expected
            copied = count_java_files(target)
            info["copied_java_files"] = copied
            info["copy_status"] = "ok" if copied == expected else "java_file_count_differs"
        except (OSError, RuntimeError) as exc:
            info["copy_status"] = f"error: {exc}"
        repos[item["copy"]] = info
        print(f"{item['copy']:8} {item['repo_id'][:48]:48} {info['copy_status']}", flush=True)
    name_map = {"seed": DEFAULT_SEED, "repos": repos}
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "name_map.json").write_text(
        json.dumps(name_map, indent=2, sort_keys=True), encoding="utf-8"
    )
    return name_map


def load_name_map(work_dir: Path) -> dict[str, Any]:
    return json.loads((work_dir / "name_map.json").read_text(encoding="utf-8"))


# ── scan ─────────────────────────────────────────────────────────────────────

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def scan_repo(
    copy_dir: Path,
    work_dir: Path,
    *,
    threads: int,
    ram: int,
    timeout: int,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """CodeQL create + analyze for one copy. Never raises: the result says what happened.

    On success the SARIF stays at ``work_dir/<copy>.sarif`` and the database is removed
    (it is large and the SARIF is the record); on failure or timeout the log stays.
    """
    name = copy_dir.name
    db = work_dir / "db"
    sarif = work_dir / f"{name}.sarif"
    work_dir.mkdir(parents=True, exist_ok=True)
    if db.exists():
        shutil.rmtree(db, ignore_errors=True)
    started = time.monotonic()
    steps = [
        (
            "create",
            [
                "codeql",
                "database",
                "create",
                str(db),
                "--language=java",
                "--build-mode=none",
                f"--source-root={copy_dir}",
                f"--threads={threads}",
                f"--ram={ram}",
            ],
        ),
        (
            "analyze",
            [
                "codeql",
                "database",
                "analyze",
                str(db),
                SUITE,
                "--format=sarif-latest",
                f"--output={sarif}",
                f"--threads={threads}",
                f"--ram={ram}",
            ],
        ),
    ]
    status: dict[str, Any] = {"status": "ok", "seconds": 0.0}
    for label, cmd in steps:
        try:
            proc = runner(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            status = {"status": "timeout", "stage": label, "timeout_s": timeout}
            break
        except OSError as exc:
            status = {"status": "error", "stage": label, "error": str(exc)}
            break
        (work_dir / f"codeql_{label}.log").write_text(
            (proc.stdout or "") + "\n" + (proc.stderr or ""), encoding="utf-8"
        )
        if proc.returncode != 0:
            status = {"status": "error", "stage": label, "returncode": proc.returncode}
            break
    status["seconds"] = round(time.monotonic() - started, 1)
    if status["status"] == "ok":
        analyze_log = work_dir / "codeql_analyze.log"
        text = (
            analyze_log.read_text(encoding="utf-8", errors="replace")
            if analyze_log.is_file()
            else ""
        )
        failed = [m for m in FAILED_QUERY_MARKERS if m in text]
        if failed:
            status = {
                **status,
                "status": "error",
                "stage": "analyze",
                "error": f"queries failed: {failed}",
            }
    removed_logs = remove_crash_logs(copy_dir)
    if removed_logs:
        status["crash_logs_removed"] = removed_logs
    if status["status"] == "ok":
        shutil.rmtree(db, ignore_errors=True)
        if not sarif.is_file():
            status = {**status, "status": "error", "error": "no SARIF written"}
    return status


def run_scan_all(
    name_map: dict[str, Any],
    repos_dir: Path,
    work_dir: Path,
    *,
    jobs: int,
    threads: int,
    ram: int,
    heavy_ram: int,
    timeout: int,
    only: set[str] | None = None,
    allow_build_tools: bool = False,
) -> dict[str, Any]:
    """Scan the RealVuln copies (OpenVuln uses the dataset's SARIF). Resumable.

    A copy that still holds build-tool files is refused (status ``build_files_present``)
    unless ``allow_build_tools``: CodeQL would run the repo's ``mvnw``/``gradlew``.
    """
    status_path = work_dir / "scan_status.json"
    status: dict[str, Any] = (
        json.loads(status_path.read_text(encoding="utf-8")) if status_path.is_file() else {}
    )
    candidates = [
        (copy, info)
        for copy, info in sorted(name_map["repos"].items())
        if info["source"].startswith("realvuln")
        and info.get("copy_status") == "ok"
        and (only is None or copy in only)
    ]
    for copy, info in candidates:
        left = [] if allow_build_tools else find_build_files(repos_dir / copy, limit=3)
        if info["java_files"] == 0:  # e.g. a Kotlin app: CodeQL java, build mode none, has no input
            status[copy] = {"status": "no_java_files", "seconds": 0.0}
        elif left:
            status[copy] = {"status": "build_files_present", "examples": left, "seconds": 0.0}
        elif status.get(copy, {}).get("status") == "build_files_present":
            del status[copy]  # the files were removed since: scan it now
    todo = [
        (copy, info)
        for copy, info in candidates
        if info["java_files"] > 0
        and status.get(copy, {}).get("status") not in ("ok", "build_files_present")
    ]

    def one(copy: str, info: dict[str, Any], heavy: bool) -> tuple[str, dict[str, Any]]:
        result = scan_repo(
            repos_dir / copy,
            work_dir / copy,
            threads=8 if heavy else threads,
            ram=heavy_ram if heavy else ram,
            timeout=timeout,
        )
        print(f"{copy:8} {result['status']:8} {result['seconds']:8.1f}s", flush=True)
        return copy, result

    def record(copy: str, result: dict[str, Any]) -> None:
        status[copy] = result
        status_path.write_text(json.dumps(status, indent=2, sort_keys=True), encoding="utf-8")

    light = [(c, i) for c, i in todo if i["java_files"] < HEAVY_JAVA_FILES]
    heavy = [(c, i) for c, i in todo if i["java_files"] >= HEAVY_JAVA_FILES]
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for copy, result in pool.map(lambda ci: one(ci[0], ci[1], False), light):
            record(copy, result)
    for copy, info in heavy:  # one at a time, with more memory
        record(*one(copy, info, True))
    return status


# ── context ──────────────────────────────────────────────────────────────────


def context_ok(output_dir: Path, copy: str) -> bool:
    ctx = output_dir / copy / "context"
    return all((ctx / name).is_file() and (ctx / name).stat().st_size > 0 for name in CONTEXT_FILES)


def prepare_context(
    copy: str,
    info: dict[str, Any],
    *,
    project_root: Path,
    repos_dir: Path,
    output_dir: Path,
    work_dir: Path,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """SARIF under ``output/java/<copy>/`` then tree-sitter ``prepare``; verify the CSVs.

    ``prepare`` exits 0 even when it found nothing to do, so success is judged by the
    three context files, not by the exit code.
    """
    if info["java_files"] == 0:
        return {"status": "ok", "skipped": "no_java_files"}
    sarif_src = (
        Path(info["dataset_sarif"])
        if info["source"] == "openvuln"
        else work_dir / copy / f"{copy}.sarif"
    )
    if not sarif_src.is_file():
        return {"status": "no_sarif", "sarif": str(sarif_src)}
    out = output_dir / copy
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(sarif_src, out / f"{copy}.sarif")
    if context_ok(output_dir, copy):
        return {"status": "ok", "reused": True}
    exe = shutil.which("vuln-hunter-x") or str(Path(sys.executable).parent / "vuln-hunter-x")
    proc = runner(
        [
            exe,
            "prepare",
            "--local-path",
            str(repos_dir / copy),
            "--name",
            copy,
            "--lang",
            "java",
            "--skip-db",
            "--backend",
            "treesitter",
        ],
        capture_output=True,
        text=True,
        cwd=project_root,
        check=False,
    )
    ok = context_ok(output_dir, copy)
    return {"status": "ok" if ok else "missing_context_files", "returncode": proc.returncode}


# ── manifests ────────────────────────────────────────────────────────────────


def _openvuln_labels(csv_path: Path, slug: str) -> list[dict[str, str]]:
    with csv_path.open(encoding="utf-8", newline="") as fh:
        return [r for r in csv.DictReader(fh) if r["project_slug"] == slug]


def build_manifests(
    name_map: dict[str, Any],
    *,
    exp_data: Path,
    repos_dir: Path,
    work_dir: Path,
    out_dir: Path,
    seed: str = DEFAULT_SEED,
    extra_pending: Path | None = None,
) -> dict[str, Any]:
    """Write the manifests, the pending list, the mismatch list, the report and the sheet."""
    dirty = verify_copies(name_map, repos_dir)
    if dirty:
        raise ValueError(
            "copies differ from their checkouts (build files aside): "
            + "; ".join(
                f"{c}: +{len(d['extra_in_copy'])} -{len(d['missing_in_copy'])}"
                for c, d in dirty.items()
            )
            + ". Run `verify` for details."
        )
    families_json = exp_data / "datasets" / "Real-Vuln-Benchmark" / "config" / "cwe-families.json"
    scan_status_path = work_dir / "scan_status.json"
    scan_status = (
        json.loads(scan_status_path.read_text(encoding="utf-8"))
        if scan_status_path.is_file()
        else {}
    )
    realapp: list[dict[str, Any]] = []
    ai: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    mismatch: list[dict[str, Any]] = []
    gt_summary: dict[str, dict[str, int]] = {}
    scope_stats: dict[str, int] = {}
    toolchains: set[str] = set()
    unmatched_ai = 0

    for copy, info in sorted(name_map["repos"].items()):
        source = info["source"]
        if info.get("copy_status") != "ok":
            mismatch.append(
                {
                    "kind": "repo_excluded",
                    "copy": copy,
                    "source": source,
                    "reason": f"copy: {info.get('copy_status')}",
                }
            )
            continue
        copy_dir = repos_dir / copy
        cache: dict[str, list] = {}
        if source == "openvuln":
            sarif = json.loads(Path(info["dataset_sarif"]).read_text(encoding="utf-8"))
            labels = _openvuln_labels(Path(info["ground_truth"]), info["repo_id"])
            rows, excluded = openvuln_rows(info["repo_id"], sarif, labels, copy_dir, copy)
            realapp += rows
            mismatch += [{"kind": "openvuln_excluded", "copy": copy, **e} for e in excluded]
            continue
        sarif_path = work_dir / copy / f"{copy}.sarif"
        if not sarif_path.is_file():
            reason = scan_status.get(copy, {}).get("status", "not_run")
            mismatch.append(
                {
                    "kind": "repo_excluded",
                    "copy": copy,
                    "source": source,
                    "reason": f"scan: {reason}",
                }
            )
            not_analysed = load_ground_truth(Path(info["ground_truth"]), families_json)
            mismatch += [
                {
                    "kind": "gt_not_analysed",
                    "copy": copy,
                    "source": source,
                    "gt_id": g["id"],
                    "family": g["family"],
                    "source_cwe": g["source_cwe"],
                    "file": g["file"],
                    "reason": f"repo not scanned ({reason})",
                }
                for g in not_analysed
            ]
            summary = gt_summary.setdefault(source, {})
            for g in not_analysed:
                key = f"{g['family']}:not_analysed"
                summary[key] = summary.get(key, 0) + 1
            continue
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        toolchains.add(json.dumps(toolchain(sarif["runs"][0]), sort_keys=True))
        alerts, stats = scope_alerts(parse_alerts_with_regions(sarif))
        for reason, count in stats.items():
            scope_stats[reason] = scope_stats.get(reason, 0) + count
        ground_truth = load_ground_truth(Path(info["ground_truth"]), families_json)
        result = match_alerts(one_alert_per_location(alerts), ground_truth)

        def row(alert: dict[str, Any], label: str, _copy=copy, _info=info, _dir=copy_dir, _c=cache):
            return make_row(
                alert,
                copy_name=_copy,
                label=label,
                track=TRACK_OF[_info["source"]],
                source=_info["source"],
                source_cwe=alert.get("source_cwe", ""),
                source_id=alert.get("source_id", ""),
                flow_leaves=flow_leaves_for(alert, _dir, _c) if label != LABEL_PENDING else None,
            )

        genuine = [row(a, LABEL_GENUINE) for a in result["matched"]]
        (realapp if source == "realvuln_human" else ai).extend(genuine)
        if source == "realvuln_human":
            pending += [row(a, LABEL_PENDING) for a in result["unmatched"]]
        else:
            unmatched_ai += len(result["unmatched"])
        summary = gt_summary.setdefault(source, {})
        for entry in ground_truth:
            key = f"{entry['family']}:{'flagged' if entry['id'] in result['gt_flagged'] else 'not_flagged'}"
            summary[key] = summary.get(key, 0) + 1
        mismatch += [
            {
                "kind": "gt_not_flagged",
                "copy": copy,
                "source": source,
                "gt_id": g["id"],
                "family": g["family"],
                "source_cwe": g["source_cwe"],
                "file": g["file"],
                "reason": "no CodeQL alert of the same family in the ground-truth location",
            }
            for g in result["gt_unflagged"]
        ]

    def order(rows: list[dict[str, Any]]) -> None:
        rows.sort(key=lambda r: (r["copy_name"], r["file"], r["line"], r["rule_id"]))

    for rows in (realapp, ai, pending):
        order(rows)
    mismatch.sort(
        key=lambda m: (m["kind"], m["copy"], str(m.get("gt_id", m.get("alert_number", ""))))
    )
    if extra_pending is not None and extra_pending.is_file():
        extra = [
            json.loads(line)
            for line in extra_pending.read_text(encoding="utf-8").splitlines()
            if line
        ]
    else:
        extra = []
    ids = [r["alert_id"] for r in realapp + ai + pending + extra]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate alert_id across the B7 rows")

    out_dir.mkdir(parents=True, exist_ok=True)
    hashes = {
        "realapp_manifest.jsonl": write_manifest(realapp, out_dir / "realapp_manifest.jsonl"),
        "ai_manifest.jsonl": write_manifest(ai, out_dir / "ai_manifest.jsonl"),
        "pending_labels.jsonl": write_manifest(pending, out_dir / "pending_labels.jsonl"),
        "mismatch.jsonl": write_manifest(mismatch, out_dir / "mismatch.jsonl"),
    }
    copy_dirs = {c: repos_dir / c for c in {r["copy_name"] for r in pending + extra}}
    sheet, key = build_sheet(pending + extra, copy_dirs, seed=seed)
    hashes["labeling_sheet.csv"] = write_csv(sheet, SHEET_COLUMNS, out_dir / "labeling_sheet.csv")
    hashes["labeling_key.csv"] = write_csv(key, KEY_COLUMNS, out_dir / "labeling_key.csv")

    report = {
        "seed": seed,
        "entries": {"realapp": len(realapp), "ai": len(ai)},
        "realapp_by_source_family_label": count_by(realapp, "source", "family", "label"),
        "ai_by_family_label": count_by(ai, "family", "label"),
        "pending_by_source_family": count_by(pending + extra, "source", "family"),
        "pending_total": len(pending) + len(extra),
        "ai_alerts_not_matched_not_used": unmatched_ai,
        "ground_truth_by_source": gt_summary,
        "scope_stats": scope_stats,
        "mismatch_by_kind": dict(sorted(_count(m["kind"] for m in mismatch).items())),
        "repos": {
            "total": len(name_map["repos"]),
            "excluded": [m for m in mismatch if m["kind"] == "repo_excluded"],
        },
        "toolchains": sorted(toolchains),
        "sha256": hashes,
    }
    (out_dir / "b7_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    return report


def _count(items: Sequence[str] | Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        out[item] = out.get(item, 0) + 1
    return out


# ── CLI ──────────────────────────────────────────────────────────────────────


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "command", choices=["inventory", "copy", "scan", "context", "manifest", "verify", "clean"]
    )
    ap.add_argument("--exp-data", type=Path, required=True, help="exp-data directory")
    ap.add_argument("--repos-dir", type=Path, required=True, help="repos/java")
    ap.add_argument("--output-dir", type=Path, required=True, help="output/java")
    ap.add_argument("--work-dir", type=Path, required=True, help="exp-data/work/b7")
    ap.add_argument("--project-root", type=Path, default=Path.cwd())
    ap.add_argument("--force", action="store_true", help="copy: replace existing copies")
    ap.add_argument(
        "--allow-build-tools",
        action="store_true",
        help="scan: let CodeQL run the repo's mvnw/gradlew (target-controlled code, network)",
    )
    ap.add_argument("--only", default="", help="comma-separated copy names")
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--ram", type=int, default=4096)
    ap.add_argument("--heavy-ram", type=int, default=10240)
    ap.add_argument("--timeout", type=int, default=3600, help="seconds per CodeQL step")
    ap.add_argument("--extra-pending", type=Path, default=None, help="e.g. dev_pending.jsonl")
    ap.add_argument("--seed", default=DEFAULT_SEED)
    args = ap.parse_args(argv)
    only = {c for c in args.only.split(",") if c} or None

    if args.command == "inventory":
        items = inventory(args.exp_data)
        for item in items:
            print(
                f"{item['copy']:8} {item['source']:15} {item['java_files']:6} .java  "
                f"{'ok ' if item['checkout_exists'] else 'MISSING'} {item['repo_id']}"
            )
        print(f"{len(items)} repos")
        return 0
    if args.command == "copy":
        items = [i for i in inventory(args.exp_data) if only is None or i["copy"] in only]
        name_map = run_copy(items, args.repos_dir, args.work_dir, args.force)
        bad = [c for c, i in name_map["repos"].items() if i["copy_status"] != "ok"]
        return 1 if bad else 0
    name_map = load_name_map(args.work_dir)
    if args.command == "clean":  # remove JVM crash logs from the copies
        for copy in sorted(name_map["repos"]):
            target = args.repos_dir / copy
            removed = remove_crash_logs(target) if target.is_dir() else []
            if removed:
                print(f"{copy:8} removed {removed}")
        return 0
    if args.command == "verify":
        problems = verify_copies(name_map, args.repos_dir)
        for copy, diff in problems.items():
            print(
                f"{copy:8} extra {diff['extra_in_copy'][:5]} missing {diff['missing_in_copy'][:5]}"
            )
        print("copies differing from their checkouts:", len(problems))
        return 1 if problems else 0
    if args.command == "scan":
        status = run_scan_all(
            name_map,
            args.repos_dir,
            args.work_dir,
            jobs=args.jobs,
            threads=args.threads,
            ram=args.ram,
            heavy_ram=args.heavy_ram,
            timeout=args.timeout,
            only=only,
            allow_build_tools=args.allow_build_tools,
        )
        return 1 if any(s["status"] != "ok" for s in status.values()) else 0
    if args.command == "context":
        failed = 0
        items = [
            (c, i)
            for c, i in sorted(name_map["repos"].items())
            if i.get("copy_status") == "ok" and (only is None or c in only)
        ]

        def one(ci: tuple[str, dict[str, Any]]) -> tuple[str, dict[str, Any]]:
            return ci[0], prepare_context(
                ci[0],
                ci[1],
                project_root=args.project_root,
                repos_dir=args.repos_dir,
                output_dir=args.output_dir,
                work_dir=args.work_dir,
            )

        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for copy, result in pool.map(one, items):
                print(f"{copy:8} {result['status']}", flush=True)
                failed += result["status"] != "ok"
        return 1 if failed else 0
    report = build_manifests(
        name_map,
        exp_data=args.exp_data,
        repos_dir=args.repos_dir,
        work_dir=args.work_dir,
        out_dir=args.work_dir,
        seed=args.seed,
        extra_pending=args.extra_pending,
    )
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "entries",
                    "realapp_by_source_family_label",
                    "ai_by_family_label",
                    "pending_by_source_family",
                    "pending_total",
                    "ground_truth_by_source",
                    "mismatch_by_kind",
                )
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
