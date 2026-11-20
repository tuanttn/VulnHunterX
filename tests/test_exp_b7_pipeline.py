# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""B7 pipeline on a synthetic ``exp-data`` tree: names, copy, scan status, context,
manifests, mismatch list and the student sheet. No CodeQL, no model, no real dataset."""

from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path

import pytest

from benchmarks.adapters.registry import load_dataset
from scripts.exp import b7_pipeline as p
from tests.test_exp_b3a_manifest import _res

JAVA = "class A {\n  void f(String s) {\n    run(s);\n  }\n  void g() {\n    exec();\n  }\n}\n"
RULES = [
    {"id": "java/sql-injection", "properties": {"tags": ["external/cwe/cwe-089"]}},
    {"id": "java/command-line-injection", "properties": {"tags": ["external/cwe/cwe-078"]}},
    {"id": "java/path-injection", "properties": {"tags": ["external/cwe/cwe-022"]}},
    {"id": "java/exec-tainted-environment", "properties": {"tags": ["external/cwe/cwe-078"]}},
]
FAMILIES = {
    "families": {
        "sql_injection": {"cwes": ["CWE-89"]},
        "command_injection": {"cwes": ["CWE-78", "CWE-77"]},
        "path_traversal": {"cwes": ["CWE-22"]},
    }
}
SLUG = "acme__lib_CVE-2020-0001_1.0"


def _sarif(results):
    return {
        "runs": [
            {
                "tool": {
                    "driver": {"name": "CodeQL", "semanticVersion": "2.27.4"},
                    "extensions": [
                        {"name": "codeql/java-queries", "semanticVersion": "1.12.0", "rules": RULES}
                    ],
                },
                "results": results,
            }
        ]
    }


def _finding(fid, cwe, file, start, end):
    return {
        "id": fid,
        "is_vulnerable": True,
        "primary_cwe": cwe,
        "file": file,
        "location": {"start_line": start, "end_line": end},
        "acceptable_locations": [],
    }


def _gt(repo_id, authorship, findings, commit="abc123"):
    return {
        "repo_id": repo_id,
        "language": "java",
        "authorship": authorship,
        "commit_sha": commit,
        "findings": findings,
    }


@pytest.fixture()
def exp_data(tmp_path):
    root = tmp_path / "exp-data"
    ds = root / "datasets"
    rv = ds / "Real-Vuln-Benchmark"
    (rv / "config").mkdir(parents=True)
    (rv / "config" / "cwe-families.json").write_text(json.dumps(FAMILIES), encoding="utf-8")

    def repo(repo_id, authorship, findings, files=("src/A.java",), java=True):
        (rv / "ground-truth" / repo_id).mkdir(parents=True)
        (rv / "ground-truth" / repo_id / "ground-truth.json").write_text(
            json.dumps(_gt(repo_id, authorship, findings)), encoding="utf-8"
        )
        target = ds / "realvuln-targets" / repo_id
        for name in files:
            f = target / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(JAVA if java else "fun main() {}\n", encoding="utf-8")
        (target / ".git").mkdir(exist_ok=True)
        (target / ".git" / "HEAD").write_text("ref", encoding="utf-8")

    repo(
        "realvuln-alpha",
        "human_authored",
        [
            _finding("gt-a1", "CWE-89", "src/A.java", 3, 3),
            _finding("gt-a2", "CWE-77", "src/A.java", 6, 6),
        ],
    )
    repo("realvuln-beta", "human_authored", [])
    repo("realvuln-webgoat", "human_authored", [_finding("gt-w1", "CWE-22", "src/A.java", 3, 3)])
    repo("vc-gen-one", "llm_generated", [_finding("gt-g1", "CWE-22", "src/A.java", 3, 3)])
    repo(
        "vc-gen-kotlin",
        "llm_generated",
        [_finding("gt-k1", "CWE-89", "src/A.kt", 3, 3)],
        files=("src/A.kt",),
        java=False,
    )

    oz = ds / "ZeroFalse" / "OpenVuln"
    (oz / "sarif-files").mkdir(parents=True)
    with (oz / "Projects_info.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["project_slug", "cve_id", "cwe_id", "buggy_commit_id"])
        w.writerow([SLUG, "CVE-2020-0001", "CWE-022", "deadbeef"])
        w.writerow(["other__x_CVE-2021-1_2.0", "CVE-2021-1", "CWE-079", "feed"])
    with (oz / "ground_truth.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["project_slug", "alert_number", "cve_id", "filename", "is_vulnerable"])
        w.writerow([SLUG, 1, "CVE-2020-0001", "vulnerability_java_path-injection_1.txt", "True"])
        w.writerow([SLUG, 2, "CVE-2020-0001", "vulnerability_java_path-injection_2.txt", "False"])
    (oz / "sarif-files" / f"{SLUG}.sarif").write_text(
        json.dumps(
            _sarif(
                [
                    _res(
                        "java/path-injection",
                        "src/A.java",
                        3,
                        flow=[("src/A.java", 2), ("src/A.java", 3)],
                    ),
                    _res("java/path-injection", "src/A.java", 6),
                ]
            )
        ),
        encoding="utf-8",
    )
    proj = ds / "openvuln-projects" / SLUG / "src"
    proj.mkdir(parents=True)
    (proj / "A.java").write_text(JAVA, encoding="utf-8")
    return root


# ── inventory ────────────────────────────────────────────────────────────────


def test_inventory_names_are_neutral_ordered_and_leave_out_the_dev_repos(exp_data):
    items = p.inventory(exp_data)
    assert [(i["copy"], i["repo_id"]) for i in items] == [
        ("app-01", "realvuln-alpha"),
        ("app-02", "realvuln-beta"),
        ("gen-01", "vc-gen-kotlin"),
        ("gen-02", "vc-gen-one"),
        ("oss-01", SLUG),
    ]
    assert "realvuln-webgoat" not in {i["repo_id"] for i in items}
    assert {i["copy"] for i in items if i["source"] == "openvuln"} == {
        "oss-01"
    }  # CWE-79 project out
    by = {i["copy"]: i for i in items}
    assert by["gen-01"]["java_files"] == 0 and by["app-01"]["java_files"] == 1
    assert by["app-01"]["track"] == "realapp" and by["gen-02"]["track"] == "ai"
    assert by["oss-01"]["commit_sha"] == "deadbeef"


def test_no_copy_name_carries_the_repo_name(exp_data):
    for item in p.inventory(exp_data):
        assert item["repo_id"].split("_")[0].lower() not in item["copy"]


# ── copy ─────────────────────────────────────────────────────────────────────


def test_copy_skips_git_writes_the_name_map_and_is_repeatable(exp_data, tmp_path):
    repos, work = tmp_path / "repos", tmp_path / "work"
    items = p.inventory(exp_data)
    name_map = p.run_copy(items, repos, work, force=False)
    assert (repos / "app-01" / "src" / "A.java").is_file()
    assert not (repos / "app-01" / ".git").exists()
    assert {i["copy_status"] for i in name_map["repos"].values()} == {"ok"}
    assert p.load_name_map(work)["repos"]["app-01"]["repo_id"] == "realvuln-alpha"
    p.run_copy(items, repos, work, force=False)  # second run changes nothing
    assert p.count_java_files(repos / "app-01") == 1


def test_a_missing_checkout_is_recorded_not_raised(exp_data, tmp_path):
    items = p.inventory(exp_data)
    items[0] = {**items[0], "checkout": str(tmp_path / "nowhere"), "checkout_exists": False}
    name_map = p.run_copy(items, tmp_path / "repos", tmp_path / "work", force=False)
    assert name_map["repos"]["app-01"]["copy_status"].startswith("error: ")


# ── scan ─────────────────────────────────────────────────────────────────────


class _Fake:
    def __init__(self, fail_at=None, timeout_at=None, write_sarif=True):
        self.calls, self.fail_at, self.timeout_at, self.write_sarif = (
            [],
            fail_at,
            timeout_at,
            write_sarif,
        )

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        stage = cmd[2]
        if stage == self.timeout_at:
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])
        if stage == "create":
            Path(cmd[3]).mkdir(parents=True, exist_ok=True)
            (Path(cmd[3]) / "big.bin").write_bytes(b"x")
        if stage == "analyze" and self.write_sarif:
            out = next(a for a in cmd if a.startswith("--output=")).split("=", 1)[1]
            Path(out).write_text("{}", encoding="utf-8")
        rc = 1 if stage == self.fail_at else 0
        return subprocess.CompletedProcess(cmd, rc, stdout="out", stderr="err")


def test_scan_keeps_the_sarif_and_removes_the_database(tmp_path):
    runner = _Fake()
    status = p.scan_repo(
        tmp_path / "app-01", tmp_path / "w" / "app-01", threads=2, ram=512, timeout=5, runner=runner
    )
    assert status["status"] == "ok"
    assert (tmp_path / "w" / "app-01" / "app-01.sarif").is_file()
    assert not (tmp_path / "w" / "app-01" / "db").exists()
    assert [c[2] for c in runner.calls] == ["create", "analyze"]
    assert "--build-mode=none" in runner.calls[0] and p.SUITE in runner.calls[1]


@pytest.mark.parametrize(
    ("fake", "expected"),
    [
        (_Fake(fail_at="create"), "error"),
        (_Fake(fail_at="analyze"), "error"),
        (_Fake(timeout_at="analyze"), "timeout"),
        (_Fake(write_sarif=False), "error"),
    ],
)
def test_scan_failures_are_reported_never_raised(tmp_path, fake, expected):
    status = p.scan_repo(tmp_path / "x", tmp_path / "w", threads=1, ram=256, timeout=1, runner=fake)
    assert status["status"] == expected


def test_scan_all_skips_repos_without_java_and_resumes(exp_data, tmp_path, monkeypatch):
    repos, work = tmp_path / "repos", tmp_path / "work"
    name_map = p.run_copy(p.inventory(exp_data), repos, work, force=False)
    seen: list[str] = []
    monkeypatch.setattr(
        p,
        "scan_repo",
        lambda copy_dir, *a, **k: seen.append(copy_dir.name) or {"status": "ok", "seconds": 0.1},
    )
    status = p.run_scan_all(name_map, repos, work, jobs=2, threads=1, ram=1, heavy_ram=2, timeout=1)
    assert sorted(seen) == ["app-01", "app-02", "gen-02"]
    assert status["gen-01"]["status"] == "no_java_files"
    assert "oss-01" not in status  # OpenVuln keeps the dataset's own SARIF
    seen.clear()
    p.run_scan_all(name_map, repos, work, jobs=2, threads=1, ram=1, heavy_ram=2, timeout=1)
    assert seen == []  # finished repos are not scanned again


# ── context ──────────────────────────────────────────────────────────────────


def _prep_runner(write):
    def run(cmd, **kw):
        if write:
            ctx = Path(kw["cwd"]) / "output" / "java" / cmd[cmd.index("--name") + 1] / "context"
            ctx.mkdir(parents=True, exist_ok=True)
            for name in p.CONTEXT_FILES:
                (ctx / name).write_text("h\n1\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")  # exit 0 either way

    return run


def test_context_succeeds_only_when_the_three_files_exist(exp_data, tmp_path):
    repos, work, out = tmp_path / "repos", tmp_path / "work", tmp_path / "output" / "java"
    name_map = p.run_copy(p.inventory(exp_data), repos, work, force=False)
    (work / "app-01").mkdir(parents=True)
    (work / "app-01" / "app-01.sarif").write_text("{}", encoding="utf-8")
    kw = {"project_root": tmp_path, "repos_dir": repos, "output_dir": out, "work_dir": work}
    info = name_map["repos"]["app-01"]
    assert (
        p.prepare_context("app-01", info, runner=_prep_runner(False), **kw)["status"]
        == "missing_context_files"
    )
    assert p.prepare_context("app-01", info, runner=_prep_runner(True), **kw)["status"] == "ok"
    assert p.prepare_context("app-01", info, runner=_prep_runner(False), **kw)["reused"] is True


def test_context_without_sarif_or_java_is_explicit(exp_data, tmp_path):
    repos, work, out = tmp_path / "repos", tmp_path / "work", tmp_path / "output" / "java"
    name_map = p.run_copy(p.inventory(exp_data), repos, work, force=False)
    kw = {
        "project_root": tmp_path,
        "repos_dir": repos,
        "output_dir": out,
        "work_dir": work,
        "runner": _prep_runner(True),
    }
    assert p.prepare_context("app-02", name_map["repos"]["app-02"], **kw)["status"] == "no_sarif"
    assert (
        p.prepare_context("gen-01", name_map["repos"]["gen-01"], **kw)["skipped"] == "no_java_files"
    )
    # OpenVuln uses the dataset SARIF
    assert p.prepare_context("oss-01", name_map["repos"]["oss-01"], **kw)["status"] == "ok"
    assert (out / "oss-01" / "oss-01.sarif").is_file()


# ── manifests ────────────────────────────────────────────────────────────────


@pytest.fixture()
def built(exp_data, tmp_path):
    repos, work = tmp_path / "repos" / "java", tmp_path / "work"  # copies live at repos/java/<copy>
    name_map = p.run_copy(p.inventory(exp_data), repos, work, force=False)
    scans = {
        "app-01": [  # alpha: sqli in gt, an extra sqli, a cmdi at the CWE-77 location
            _res(
                "java/sql-injection", "src/A.java", 3, flow=[("src/A.java", 2), ("src/A.java", 3)]
            ),
            _res("java/sql-injection", "src/A.java", 8),
            _res("java/command-line-injection", "src/A.java", 6),
            _res("java/exec-tainted-environment", "src/A.java", 6),
        ],
        "app-02": [_res("java/path-injection", "src/A.java", 3)],  # beta: no ground truth at all
        "gen-02": [
            _res("java/path-injection", "src/A.java", 3),
            _res("java/path-injection", "src/A.java", 8),
        ],
    }
    for copy, results in scans.items():
        (work / copy).mkdir(parents=True, exist_ok=True)
        (work / copy / f"{copy}.sarif").write_text(json.dumps(_sarif(results)), encoding="utf-8")
    (work / "scan_status.json").write_text(
        json.dumps({"gen-01": {"status": "no_java_files"}}), encoding="utf-8"
    )
    report = p.build_manifests(
        name_map, exp_data=exp_data, repos_dir=repos, work_dir=work, out_dir=work
    )
    return report, work, repos


def _rows(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


def test_realapp_manifest_has_matched_genuine_alerts_and_the_openvuln_labels(built):
    report, work, _ = built
    rows = _rows(work / "realapp_manifest.jsonl")
    assert {(r["source"], r["family"], r["label"]) for r in rows} == {
        ("realvuln_human", "sqli", "genuine"),
        ("realvuln_human", "cmdi", "genuine"),
        ("openvuln", "pathtraver", "genuine"),
        ("openvuln", "pathtraver", "false_alarm"),
    }
    human = {r["source_id"]: r for r in rows if r["source"] == "realvuln_human"}
    assert human["gt-a2"]["source_cwe"] == "CWE-77" and human["gt-a2"]["family"] == "cmdi"
    assert all(r["track"] == "realapp" for r in rows)
    assert report["realapp_by_source_family_label"]["openvuln:pathtraver:false_alarm"] == 1


def test_ai_manifest_only_has_alerts_that_match_ground_truth(built):
    report, work, _ = built
    rows = _rows(work / "ai_manifest.jsonl")
    assert [(r["copy_name"], r["line"], r["label"], r["track"]) for r in rows] == [
        ("gen-02", 3, "genuine", "ai")
    ]
    assert report["ai_alerts_not_matched_not_used"] == 1


def test_unmatched_human_alerts_are_pending_and_stay_out_of_the_manifest(built):
    report, work, _ = built
    pending = _rows(work / "pending_labels.jsonl")
    assert {(r["copy_name"], r["line"], r["label"]) for r in pending} == {
        ("app-01", 8, "pending"),
        ("app-02", 3, "pending"),
    }
    manifest_ids = {r["alert_id"] for r in _rows(work / "realapp_manifest.jsonl")}
    assert manifest_ids.isdisjoint({r["alert_id"] for r in pending})
    assert report["pending_total"] == 2
    assert report["scope_stats"]["excluded_rule:java/exec-tainted-environment"] == 1


def test_mismatch_list_names_every_unflagged_or_unanalysed_entry_with_a_reason(built):
    report, work, _ = built
    mismatch = _rows(work / "mismatch.jsonl")
    kinds = {(m["kind"], m.get("copy"), m.get("gt_id")) for m in mismatch}
    assert ("repo_excluded", "gen-01", None) in kinds
    assert ("gt_not_analysed", "gen-01", "gt-k1") in kinds
    assert all(m["reason"] for m in mismatch if m["kind"] != "openvuln_excluded")
    summary = report["ground_truth_by_source"]
    assert summary["realvuln_human"] == {"cmdi:flagged": 1, "sqli:flagged": 1}
    assert (
        summary["realvuln_ai"]["sqli:not_analysed"] == 1
        and summary["realvuln_ai"]["pathtraver:flagged"] == 1
    )


def test_manifests_load_through_the_adapter_and_have_hashes(built):
    report, work, repos = built
    for name in ("realapp_manifest.jsonl", "ai_manifest.jsonl"):
        entries = load_dataset(
            "alert-manifest",
            Path("."),
            options={"manifest": str(work / name), "repos_dir": str(repos.parent)},
        )
        assert len(entries) == len(_rows(work / name)) > 0
        assert all(e.code_snippet for e in entries)
    assert (work / "pending_labels.jsonl.sha256").is_file()
    assert report["sha256"]["realapp_manifest.jsonl"]


def test_the_sheet_has_the_pending_alerts_and_no_source_or_repo(built):
    _, work, _ = built
    with (work / "labeling_sheet.csv").open(encoding="utf-8-sig", newline="") as fh:
        sheet = list(csv.DictReader(fh))
    assert len(sheet) == 2
    blob = json.dumps(sheet)
    for forbidden in ("realvuln", "app-0", "gen-0", "gt-", "genuine", "pending"):
        assert forbidden not in blob, forbidden
    with (work / "labeling_key.csv").open(encoding="utf-8-sig", newline="") as fh:
        assert {r["source"] for r in csv.DictReader(fh)} == {"realvuln_human"}


# ── build files: CodeQL must not run the repo's own build tools ──────────────


def _with_build_files(root: Path) -> None:
    for rel in (
        "pom.xml",
        "mvnw",
        "mvnw.cmd",
        "gradlew",
        "build.gradle",
        "app/build.gradle.kts",
        "deps.gradle",
        ".mvn/wrapper/maven-wrapper.properties",
        "gradle/wrapper/gradle-wrapper.properties",
        "buildSrc/Plugin.java",
    ):
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x", encoding="utf-8")
    (root / "gradle" / "libs.versions.toml").write_text("[versions]", encoding="utf-8")  # kept


def test_find_and_strip_build_files_keep_the_source(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "A.java").write_text(JAVA, encoding="utf-8")
    (tmp_path / "pom.properties").write_text("keep", encoding="utf-8")
    _with_build_files(tmp_path)
    found = p.find_build_files(tmp_path)
    assert {
        "pom.xml",
        "mvnw",
        "mvnw.cmd",
        "gradlew",
        "build.gradle",
        "app/build.gradle.kts",
        "deps.gradle",
        ".mvn/",
        "gradle/wrapper/",
        "buildSrc/",
    } <= set(found)
    assert not any("A.java" in f or "pom.properties" in f or "libs.versions" in f for f in found)
    removed = p.strip_build_files(tmp_path)
    assert set(removed) == set(found) and p.find_build_files(tmp_path) == []
    assert (tmp_path / "src" / "A.java").is_file() and (tmp_path / "pom.properties").is_file()
    assert (tmp_path / "gradle" / "libs.versions.toml").is_file()


def test_copy_strips_build_files_of_realvuln_copies_only(exp_data, tmp_path):
    ds = exp_data / "datasets"
    _with_build_files(ds / "realvuln-targets" / "realvuln-alpha")
    _with_build_files(ds / "openvuln-projects" / SLUG)
    repos = tmp_path / "repos"
    name_map = p.run_copy(p.inventory(exp_data), repos, tmp_path / "work", force=False)
    assert name_map["repos"]["app-01"]["build_files_removed"] > 0
    assert p.find_build_files(repos / "app-01") == []
    assert "build_files_removed" not in name_map["repos"]["oss-01"]
    assert p.find_build_files(ds / "realvuln-targets" / "realvuln-alpha")  # checkout untouched


def test_scan_refuses_a_copy_that_still_has_build_files_then_scans_it_once_stripped(
    exp_data, tmp_path, monkeypatch
):
    repos, work = tmp_path / "repos", tmp_path / "work"
    name_map = p.run_copy(p.inventory(exp_data), repos, work, force=False)
    _with_build_files(repos / "app-01")
    seen: list[str] = []
    monkeypatch.setattr(
        p,
        "scan_repo",
        lambda copy_dir, *a, **k: seen.append(copy_dir.name) or {"status": "ok", "seconds": 0.1},
    )
    kw = {"jobs": 1, "threads": 1, "ram": 1, "heavy_ram": 2, "timeout": 1}
    status = p.run_scan_all(name_map, repos, work, **kw)
    assert status["app-01"]["status"] == "build_files_present" and "app-01" not in seen
    assert status["app-01"]["examples"]
    p.strip_build_files(repos / "app-01")
    status = p.run_scan_all(name_map, repos, work, **kw)
    assert status["app-01"]["status"] == "ok" and "app-01" in seen  # stale refusal cleared


def test_the_guard_can_be_waived_explicitly(exp_data, tmp_path, monkeypatch):
    repos, work = tmp_path / "repos", tmp_path / "work"
    name_map = p.run_copy(p.inventory(exp_data), repos, work, force=False)
    _with_build_files(repos / "app-01")
    seen: list[str] = []
    monkeypatch.setattr(
        p,
        "scan_repo",
        lambda copy_dir, *a, **k: seen.append(copy_dir.name) or {"status": "ok", "seconds": 0.1},
    )
    p.run_scan_all(
        name_map,
        repos,
        work,
        jobs=1,
        threads=1,
        ram=1,
        heavy_ram=2,
        timeout=1,
        allow_build_tools=True,
    )
    assert "app-01" in seen


def test_java_files_inside_build_directories_are_not_counted_as_lost(exp_data, tmp_path):
    target = exp_data / "datasets" / "realvuln-targets" / "realvuln-alpha"
    wrapper = target / ".mvn" / "wrapper"
    wrapper.mkdir(parents=True)
    (wrapper / "MavenWrapperDownloader.java").write_text("class D {}", encoding="utf-8")
    assert p.count_java_files(target) == 2 and p.count_java_files(target, skip_build=True) == 1
    name_map = p.run_copy(p.inventory(exp_data), tmp_path / "repos", tmp_path / "work", force=False)
    info = name_map["repos"]["app-01"]
    assert info["copy_status"] == "ok"
    assert (info["java_files_checkout"], info["java_files"], info["copied_java_files"]) == (2, 1, 1)
    again = p.run_copy(p.inventory(exp_data), tmp_path / "repos", tmp_path / "work", force=False)
    assert again["repos"]["app-01"]["copy_status"] == "ok"  # idempotent


# ── copy integrity ───────────────────────────────────────────────────────────


def test_crash_logs_are_removed_and_other_files_stay(tmp_path):
    (tmp_path / "src").mkdir()
    for rel in ("hs_err_pid12.log", "src/replay_pid9.log", "src/keep.log", "src/A.java"):
        (tmp_path / rel).write_text("x", encoding="utf-8")
    assert p.remove_crash_logs(tmp_path) == ["hs_err_pid12.log", "src/replay_pid9.log"]
    assert (tmp_path / "src" / "keep.log").is_file() and (tmp_path / "src" / "A.java").is_file()


def test_verify_finds_a_stray_file_and_a_missing_one(exp_data, tmp_path):
    repos, work = tmp_path / "repos", tmp_path / "work"
    name_map = p.run_copy(p.inventory(exp_data), repos, work, force=False)
    assert p.verify_copies(name_map, repos) == {}
    (repos / "app-01" / "hs_err_pid1.log").write_text("x", encoding="utf-8")
    (repos / "app-02" / "src" / "A.java").unlink()
    problems = p.verify_copies(name_map, repos)
    assert problems["app-01"]["extra_in_copy"] == ["hs_err_pid1.log"]
    assert problems["app-02"]["missing_in_copy"] == ["src/A.java"]


def test_build_files_do_not_count_as_a_difference(exp_data, tmp_path):
    ds = exp_data / "datasets"
    _with_build_files(ds / "realvuln-targets" / "realvuln-alpha")
    repos = tmp_path / "repos"
    name_map = p.run_copy(p.inventory(exp_data), repos, tmp_path / "work", force=False)
    assert p.verify_copies(name_map, repos) == {}


def test_manifest_refuses_a_dirty_copy(exp_data, tmp_path):
    repos, work = tmp_path / "repos", tmp_path / "work"
    name_map = p.run_copy(p.inventory(exp_data), repos, work, force=False)
    (repos / "app-01" / "hs_err_pid1.log").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="copies differ from their checkouts"):
        p.build_manifests(name_map, exp_data=exp_data, repos_dir=repos, work_dir=work, out_dir=work)


def test_scan_removes_the_crash_logs_it_caused(tmp_path):
    copy = tmp_path / "app-01"
    copy.mkdir()

    def runner(cmd, **kw):
        (copy / "hs_err_pid77.log").write_text(
            "oom", encoding="utf-8"
        )  # JVM crash in the source root
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    status = p.scan_repo(copy, tmp_path / "w", threads=1, ram=1, timeout=1, runner=runner)
    assert status["status"] == "error" and status["crash_logs_removed"] == ["hs_err_pid77.log"]
    assert not (copy / "hs_err_pid77.log").exists()


def test_a_scan_with_failed_queries_is_an_error_even_with_exit_code_zero(tmp_path):
    class Fake(_Fake):
        def __call__(self, cmd, **kw):
            proc = super().__call__(cmd, **kw)
            if cmd[2] == "analyze":
                proc.stdout = "WARNING: [9/124 eval 16.5s] Query failed: TaintedPath.ql (ran out of Java heap)"
            return proc

    status = p.scan_repo(
        tmp_path / "app-01", tmp_path / "w", threads=1, ram=1, timeout=1, runner=Fake()
    )
    assert status["status"] == "error" and "queries failed" in status["error"]
