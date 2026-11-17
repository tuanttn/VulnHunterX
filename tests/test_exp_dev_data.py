"""Tests for scripts/exp/dev_data_prep.py (synthetic Juliet-like fixtures)."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.exp import _java_ast as ja
from scripts.exp import dev_data_prep as dd

PRIMARY = """\
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE89_SQL_Injection__Environment_execute_01.java
*/
package testcases.CWE89_SQL_Injection.s01;

import testcasesupport.*;

public class CWE89_SQL_Injection__Environment_execute_01 extends AbstractTestCase
{
    public void bad() throws Throwable
    {
        /* POTENTIAL FLAW: Read data from an environment variable */
        String data = System.getenv("ADD");
        badSink(data);
    }

    private void badSink(String data)
    {
        run("select " + data);
    }

    public void good() throws Throwable
    {
        goodG2B();
    }

    private void goodG2B() throws Throwable
    {
        String data = "Benign, fixed string";
        run(data);
    }
}
"""

BAD81 = """\
package testcases.CWE89_SQL_Injection.s01;
public class CWE89_SQL_Injection__Environment_execute_81_bad extends CWE89_SQL_Injection__Environment_execute_81_base
{
    public void action(String data) throws Throwable
    {
        run(data);
    }
}
"""

SUPPORT = """\
package testcasesupport;
public abstract class AbstractTestCase
{
    public abstract void bad() throws Throwable;
    public abstract void good() throws Throwable;
}
"""


@pytest.fixture
def juliet_src(tmp_path: Path) -> Path:
    src = tmp_path / "Java/src"
    case_dir = src / "testcases/CWE89_SQL_Injection/s01"
    case_dir.mkdir(parents=True)
    (case_dir / "CWE89_SQL_Injection__Environment_execute_01.java").write_text(PRIMARY)
    (case_dir / "CWE89_SQL_Injection__Environment_execute_81_bad.java").write_text(BAD81)
    (src / "testcasesupport").mkdir()
    (src / "testcasesupport/AbstractTestCase.java").write_text(SUPPORT)
    return src


def test_label_ranges_cover_bad_and_good_methods():
    lr = dd.label_ranges(PRIMARY.encode(), "CWE89_SQL_Injection__Environment_execute_01")
    # bad(): 10-15, badSink: 17-20 ; good(): 22-25, goodG2B: 27-31
    assert lr["bad"] == [[10, 15], [17, 20]]
    assert lr["good"] == [[22, 25], [27, 31]]
    assert dd.label_for_line(lr, 12) == "bad"
    assert dd.label_for_line(lr, 18) == "bad"
    assert dd.label_for_line(lr, 29) == "good"
    assert dd.label_for_line(lr, 8) is None  # class header: outside both


def test_81_file_name_rule():
    lr = dd.label_ranges(BAD81.encode(), "CWE89_SQL_Injection__Environment_execute_81_bad")
    assert lr["file_rule"] == "bad"
    assert dd.label_for_line(lr, 5) == "bad"
    good = dd.label_ranges(b"class A {}", "CWE89_SQL_Injection__X_81_goodG2B")
    assert dd.label_for_line(good, 1) == "good"


def test_build_copy_redacts_consistently(juliet_src: Path, tmp_path: Path):
    out = tmp_path / "repos/java/suite"
    name_map, label_map = dd.build_juliet_copy(juliet_src, out, seed="s")

    rels = sorted(p.relative_to(out).as_posix() for p in out.rglob("*.java"))
    assert any(r.startswith("testcasesupport/") for r in rels)
    assert all("CWE" not in r and "bad" not in r.lower() for r in rels)
    assert dd.juliet_leak_search(out) == []

    # one class token shared by file name, class declaration and the subclass reference
    stem = "CWE89_SQL_Injection__Environment_execute_81_base"
    base_tok = name_map["words"][stem]
    all_text = "\n".join(p.read_text() for p in out.rglob("*.java"))
    assert f"extends {base_tok}" in all_text

    # abstract method and its override use the same replaced name
    tok_bad = name_map["words"]["bad"]
    assert f"abstract void {tok_bad}()" in all_text
    assert f"void {tok_bad}()" in all_text
    assert "constant text" in all_text and "Benign" not in all_text

    # label map keyed by redacted path, line ranges unchanged because lines are kept
    primary = next(k for k, v in label_map.items() if v["orig"].endswith("execute_01.java"))
    assert label_map[primary]["bad"] == [[10, 15], [17, 20]]
    res = dd.verify_juliet(juliet_src, out, name_map)
    assert res["ok"], res["problems"]


def test_build_is_deterministic(juliet_src: Path, tmp_path: Path):
    a, b = tmp_path / "repos/a", tmp_path / "repos/b"
    dd.build_juliet_copy(juliet_src, a, seed="s")
    dd.build_juliet_copy(juliet_src, b, seed="s")
    assert ja.tree_hash(a) == ja.tree_hash(b)


def test_tokens_cannot_spell_label_words():
    r = dd.JulietRenamer("x")
    toks = [r._tok(f"w{i}", "m") for i in range(5000)]
    assert not any(dd.JULIET_LEAK_RE.search(t) for t in toks)
