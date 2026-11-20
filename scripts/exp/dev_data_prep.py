"""Development-tier data preparation (plan v3.3 §3.4, day 2).

``juliet``    Juliet Java 1.3 (CWE89, CWE78, CWE23, CWE36 + testcasesupport): label map from the
              line ranges of every ``bad*`` / ``good*`` method, then an on-disk redaction that is
              consistent across the whole copy (comments blanked, names of methods, classes,
              files and directories replaced). Not ``benchmarks/adapters/redaction.py``: that one
              is in-memory and per entry.
``app-copy``  Copy of an application checkout (WebGoat, VulnerableApp) without ``.git``.

Labels and name maps are written outside the copy. Nothing here calls a model.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

from scripts.exp._java_ast import (
    blank_comments,
    count_errors,
    file_sha256,
    method_spans,
    token,
    tree_hash,
)

JULIET_DIRS = {
    "CWE89_SQL_Injection": "sqli",
    "CWE78_OS_Command_Injection": "cmdi",
    "CWE23_Relative_Path_Traversal": "pathtraver",
    "CWE36_Absolute_Path_Traversal": "pathtraver",
}
SUPPORT_DIR = "testcasesupport"
NEW_ROOT = "suite"

_FILE_RULE_RE = re.compile(r"_81_(bad|good\w*)$")
_METHOD_BAD_RE = re.compile(r"^bad")
_METHOD_GOOD_RE = re.compile(r"^good")

# words renamed with a consistent token across the whole copy
_CWE_WORD_RE = re.compile(r"\b\w*CWE\d\w*\b")
_BADGOOD_RE = re.compile(r"\b(?:bad|good)\w*|\b\w+(?:Bad|Good)\w*\b")
_TESTCASES_RE = re.compile(r"\btestcases\b")
_SAFE_ALPHABET = str.maketrans("abcdef", "kmnpqr")
_BENIGN = "Benign, fixed string"
_BENIGN_NEW = "constant text"

# Leak search: label hints that must not survive on disk.
JULIET_LEAK_RE = re.compile(r"bad|good|flaw|benign|CWE\d|potential|@description", re.IGNORECASE)


# ── label map ────────────────────────────────────────────────────────────────


def label_ranges(source: bytes, stem: str) -> dict:
    """Line ranges (1-based, inclusive) of bad and good methods, plus the file-name rule for _81."""
    total_lines = source.count(b"\n") + 1
    rule = _FILE_RULE_RE.search(stem)
    if rule:
        kind = "bad" if rule.group(1) == "bad" else "good"
        return {"file_rule": kind, "bad": [], "good": [], "lines": total_lines}
    bad, good = [], []
    for span in method_spans(source):
        if _METHOD_BAD_RE.match(span.name):
            bad.append([span.start_line, span.end_line])
        elif _METHOD_GOOD_RE.match(span.name):
            good.append([span.start_line, span.end_line])
    return {"file_rule": None, "bad": bad, "good": good, "lines": total_lines}


def label_for_line(entry: dict, line: int) -> str | None:
    """'bad' (genuine), 'good' (false alarm) or None (outside both: excluded and counted)."""
    if entry["file_rule"]:
        return entry["file_rule"]
    # innermost wins: a good* method can nest inside nothing bad, but check good first only if
    # the ranges overlap (they do not in Juliet; this keeps the function total).
    in_bad = any(s <= line <= e for s, e in entry["bad"])
    in_good = any(s <= line <= e for s, e in entry["good"])
    if in_bad and not in_good:
        return "bad"
    if in_good and not in_bad:
        return "good"
    return None


# ── redaction ────────────────────────────────────────────────────────────────


class JulietRenamer:
    def __init__(self, seed: str) -> None:
        self.seed = seed
        self.words: dict[str, str] = {}

    def _tok(self, word: str, prefix: str) -> str:
        if word not in self.words:
            # hex a-f -> k,m,n,p,q,r so a token can never spell "bad", "good" or "flaw"
            raw = token(self.seed, word, prefix="", length=8).translate(_SAFE_ALPHABET)
            self.words[word] = prefix + raw
        return self.words[word]

    def apply(self, text: str) -> str:
        text = text.replace(_BENIGN, _BENIGN_NEW)
        text = _TESTCASES_RE.sub(NEW_ROOT, text)
        # Keep the support classes (AbstractTestCase*, testcasesupport) untouched, but rename every
        # bad*/good*/CWE* word. Order: CWE words first so a stem containing "bad" maps as one unit.
        text = _CWE_WORD_RE.sub(lambda m: self._tok(m.group(0), "C"), text)
        return _BADGOOD_RE.sub(lambda m: self._tok(m.group(0), "m"), text)

    def path(self, rel: Path) -> Path:
        return Path(*[self.apply(part) for part in rel.parts])


def _java_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.java"))


def build_juliet_copy(juliet_src: Path, out_dir: Path, seed: str) -> tuple[dict, dict]:
    """``juliet_src`` is ``Juliet-Java-1.3/Java/src``. Returns (name_map, label_map)."""
    renamer = JulietRenamer(seed)
    label_map: dict[str, dict] = {}
    files: dict[str, str] = {}
    families: dict[str, str] = {}

    sources: list[tuple[Path, Path]] = []  # (absolute, path relative to src/)
    for d, fam in JULIET_DIRS.items():
        for f in _java_files(juliet_src / "testcases" / d):
            sources.append((f, f.relative_to(juliet_src)))
            families[d] = fam
    for f in _java_files(juliet_src / SUPPORT_DIR):
        sources.append((f, f.relative_to(juliet_src)))

    # Pre-register stems so a class and its file share one token regardless of file order.
    for _, rel in sources:
        for part in rel.with_suffix("").parts:
            if "CWE" in part:
                renamer.apply(part)

    for abs_path, rel in sources:
        data = abs_path.read_bytes()
        is_case = rel.parts[0] == "testcases"
        lr = label_ranges(data, abs_path.stem) if is_case else None
        text = renamer.apply(blank_comments(data).decode("utf-8", "replace"))
        new_rel = renamer.path(rel)
        if is_case:
            new_rel = Path(NEW_ROOT, *new_rel.parts[1:])
        target = out_dir / new_rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
        files[rel.as_posix()] = new_rel.as_posix()
        if lr is not None:
            label_map[new_rel.as_posix()] = {**lr, "orig": rel.as_posix()}

    name_map = {
        "files": files,
        "words": dict(sorted(renamer.words.items())),
        "dir_family": {renamer.apply(d): fam for d, fam in JULIET_DIRS.items()},
        "dir_cwe_original": {renamer.apply(d): d for d in JULIET_DIRS},
    }
    return name_map, label_map


def juliet_leak_search(root: Path) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        for where, target in (("path", rel), ("content", path.read_text(encoding="utf-8"))):
            cleaned = re.sub(r"AbstractTestCase\w*", "", target)
            m = JULIET_LEAK_RE.search(cleaned)
            if m:
                hits.append((rel, f"{where}: {m.group(0)}"))
    return hits


def verify_juliet(juliet_src: Path, out_dir: Path, name_map: dict) -> dict:
    problems: list[str] = []
    leaks = juliet_leak_search(out_dir)
    if leaks:
        problems.append(f"{len(leaks)} leak hits, first: {leaks[0]}")
    line_mismatch = new_errors = 0
    for orig, new in name_map["files"].items():
        src = (juliet_src / orig).read_bytes()
        out = (out_dir / new).read_bytes()
        if src.count(b"\n") != out.count(b"\n"):
            line_mismatch += 1
        if count_errors(out) > count_errors(src):
            new_errors += 1
    if line_mismatch:
        problems.append(f"{line_mismatch} files changed line count")
    if new_errors:
        problems.append(f"{new_errors} files gained parse errors")
    return {"ok": not problems, "problems": problems, "files": len(name_map["files"]), "leak_hits": len(leaks)}


# ── CLI ──────────────────────────────────────────────────────────────────────


def _guard_repos(out: Path) -> None:
    if "repos" not in out.parts:
        raise SystemExit(f"refusing to write/delete {out}: not under a 'repos' directory")


def _write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
    path.with_name(path.name + ".sha256").write_text(
        f"{file_sha256(path)}  {path.name}\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    j = sub.add_parser("juliet")
    j.add_argument("--juliet-src", type=Path, required=True, help="Juliet-Java-1.3/Java/src")
    j.add_argument("--out", type=Path, required=True, help="repos/java/<copy>")
    j.add_argument("--work-dir", type=Path, required=True)
    j.add_argument("--seed", required=True)
    j.add_argument("--force", action="store_true")

    a = sub.add_parser("app-copy")
    a.add_argument("--src", type=Path, required=True)
    a.add_argument("--out", type=Path, required=True)
    a.add_argument("--force", action="store_true")

    args = ap.parse_args(argv)
    _guard_repos(args.out)
    if args.out.exists():
        if not args.force:
            raise SystemExit(f"{args.out} exists; use --force")
        shutil.rmtree(args.out)

    if args.cmd == "app-copy":
        shutil.copytree(args.src, args.out, ignore=shutil.ignore_patterns(".git"))
        print(json.dumps({"copy": str(args.out), "tree_sha256": tree_hash(args.out)}, indent=2))
        return 0

    args.work_dir.mkdir(parents=True, exist_ok=True)
    name_map, label_map = build_juliet_copy(args.juliet_src, args.out, args.seed)
    result = verify_juliet(args.juliet_src, args.out, name_map)
    name_map["seed"] = args.seed
    name_map["tree_sha256"] = tree_hash(args.out)
    _write_json(args.work_dir / "name_map.json", name_map)
    _write_json(args.work_dir / "label_map.json", label_map)
    result["tree_sha256"] = name_map["tree_sha256"]
    result["cases_with_label_ranges"] = len(label_map)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
