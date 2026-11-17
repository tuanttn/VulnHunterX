"""Tests for scripts/exp/b3b_owasp_copy.py (synthetic fixtures, no dataset, no model)."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.exp import _java_ast as ja
from scripts.exp import b3b_owasp_copy as b3b

TESTCASE = """\
/**
 * OWASP Benchmark v1.2
 * See https://owasp.org/www-project-benchmark/
 */
package org.owasp.benchmark.testcode;

import org.owasp.esapi.ESAPI;

@WebServlet(value = "/sqli-00/BenchmarkTest00008")
public class BenchmarkTest00008 extends HttpServlet {
    // some code
    public void doPost(HttpServletRequest request) {
        String p = request.getHeader("BenchmarkTest00008"); /* inline */
        String s = ESAPI.encoder().encodeForHTML(p);
        org.owasp.benchmark.helpers.DatabaseHelper.run(s);
        System.out.println("Problem executing cmdi - TestCase");
        props.load("benchmark.properties");
    }
}
"""

HELPER = """\
package org.owasp.benchmark.helpers;

// Used by the Benchmark JAVA test cases
public class DatabaseHelper {
    public static void run(String s) { benchmarkprops.get(s); }
}
"""

REPORT = "package org.owasp.benchmark.report;\npublic class Report {}\n"


@pytest.fixture
def src_tree(tmp_path: Path) -> Path:
    root = tmp_path / "java"
    base = root / "org/owasp/benchmark"
    for rel, text in (
        ("testcode/BenchmarkTest00008.java", TESTCASE),
        ("helpers/DatabaseHelper.java", HELPER),
        ("report/Report.java", REPORT),
    ):
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_blank_comments_keeps_line_count_and_code():
    src = TESTCASE.encode()
    out = ja.blank_comments(src)
    assert out.count(b"\n") == src.count(b"\n")
    assert len(out) == len(src)
    text = out.decode()
    assert "owasp.org" not in text and "some code" not in text and "inline" not in text
    assert "ESAPI.encoder().encodeForHTML(p)" in text
    assert ja.count_errors(out) == 0


def test_build_copy_renames_consistently_and_keeps_esapi(src_tree: Path, tmp_path: Path):
    out = tmp_path / "repos/java/shopapp"
    nm = b3b.build_copy(src_tree, out, seed="s1")

    tok = nm["testcases"]["00008"]
    r = b3b.Renamer("s1")
    tc_dir, helper_dir = r.subpackage("testcode"), r.subpackage("helpers")
    assert (out / f"com/acme/app/{tc_dir}/{tok}.java").is_file()
    assert (out / f"com/acme/app/{helper_dir}/DatabaseHelper.java").is_file()
    for name in ("testcode", "helpers", "service"):
        assert not (out / "com/acme/app" / name).exists()
    assert not (out / "org/owasp/benchmark").exists()
    assert nm["excluded_report_files"] == 1
    assert not any("Report" in v for v in nm["files"].values())

    text = (out / f"com/acme/app/{tc_dir}/{tok}.java").read_text()
    assert f"class {tok} " in text
    assert f'getHeader("{tok}")' in text  # same token inside strings
    assert f"/svc/{tok}" in text
    assert f"package com.acme.app.{tc_dir};" in text
    assert f"com.acme.app.{helper_dir}.DatabaseHelper.run" in text
    assert "testcode" not in text and "helpers" not in text
    assert "org.owasp.esapi.ESAPI" in text  # whitelisted library kept
    assert "Operation failed" in text and "appprops" not in text
    assert "app.properties" in text


def test_verify_passes_on_clean_copy(src_tree: Path, tmp_path: Path):
    out = tmp_path / "repos/java/shopapp"
    nm = b3b.build_copy(src_tree, out, seed="s1")
    res = b3b.verify_copy(src_tree, out, nm)
    assert res["ok"], res["problems"]
    assert res["leak_hits"] == 0


def test_leak_search_flags_leftovers_but_not_esapi(tmp_path: Path):
    root = tmp_path / "c"
    root.mkdir()
    (root / "A.java").write_text("import org.owasp.esapi.ESAPI;\n")
    assert b3b.leak_search(root) == []
    (root / "B.java").write_text('String s = "Benchmark";\n')
    (root / "owasp_Case.java").write_text("class X {}\n")
    hits = {h[0] for h in b3b.leak_search(root)}
    assert hits == {"B.java", "owasp_Case.java"}


def test_build_is_deterministic_and_seed_dependent(src_tree: Path, tmp_path: Path):
    a, b, c = (tmp_path / n for n in ("a", "b", "c"))
    na = b3b.build_copy(src_tree, a, seed="s1")
    nb = b3b.build_copy(src_tree, b, seed="s1")
    nc = b3b.build_copy(src_tree, c, seed="s2")
    assert ja.tree_hash(a) == ja.tree_hash(b)
    assert na == nb
    assert nc["testcases"]["00008"] != na["testcases"]["00008"]


def test_verify_detects_line_count_change(src_tree: Path, tmp_path: Path):
    out = tmp_path / "repos/java/shopapp"
    nm = b3b.build_copy(src_tree, out, seed="s1")
    victim = next(out.rglob("DatabaseHelper.java"))
    victim.write_text(victim.read_text() + "\n\n")
    res = b3b.verify_copy(src_tree, out, nm)
    assert not res["ok"] and any("line count" in p for p in res["problems"])


def test_method_spans_and_enclosing():
    src = b"class A {\n  void f() {\n    int x;\n  }\n  void g() {}\n}\n"
    spans = ja.method_spans(src)
    assert [(s.name, s.start_line, s.end_line) for s in spans] == [("f", 2, 4), ("g", 5, 5)]
    assert ja.enclosing_method(spans, 3).name == "f"
    assert ja.enclosing_method(spans, 1) is None


def test_verify_detects_leftover_subpackage_dir(src_tree: Path, tmp_path: Path):
    out = tmp_path / "repos/java/shopapp"
    nm = b3b.build_copy(src_tree, out, seed="s1")
    (out / "com/acme/app/testcode").mkdir()
    res = b3b.verify_copy(src_tree, out, nm)
    assert not res["ok"] and any("sub-package" in p for p in res["problems"])


def test_subpackage_names_are_stable_distinct_and_neutral():
    a, b = b3b.Renamer("s1"), b3b.Renamer("s1")
    names = {n: a.subpackage(n) for n in b3b.SUBPACKAGES}
    assert names == {n: b.subpackage(n) for n in b3b.SUBPACKAGES}
    assert len(set(names.values())) == 3
    assert all(v[0].isalpha() and v.isalnum() and not b3b.LEAK_TERMS.search(v) for v in names.values())
    assert names != {n: b3b.Renamer("s2").subpackage(n) for n in b3b.SUBPACKAGES}
