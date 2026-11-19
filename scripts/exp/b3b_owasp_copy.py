"""B3b: source-only, renamed copy of OWASP Benchmark Java (plan v3.3 §5.2, plan.md §7 day 2).

Builds ``repos/java/<copy name>`` from ``<BenchmarkJava>/src/main/java``:

* only Java sources, without ``org/owasp/benchmark/report``; no expected results, metadata,
  git history, resources;
* every comment blanked (license header included), line numbers kept;
* test-case names (``BenchmarkTestNNNNN``), the ``org.owasp.benchmark`` package **and its
  sub-packages** ``helpers``, ``testcode``, ``service`` (v3.2 B3b, reading A), servlet paths,
  properties names and strings that name the benchmark replaced by neutral names;
* ``org.owasp.esapi`` kept (real sanitizer library, whitelisted in the leak search);
* the map of replaced names written *outside* the copy.

No label is read. Output is deterministic for a given (commit, seed).

Usage:
    python -m scripts.exp.b3b_owasp_copy --benchmark-dir <BenchmarkJava> --pin <sha> \
        --out repos/java/<copy> --work-dir <exp-data/work/copy> --seed <text>
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from scripts.exp._java_ast import (
    blank_comments,
    count_errors,
    file_sha256,
    token,
    tree_hash,
)

SRC_SUBDIR = Path("src/main/java")
SRC_PACKAGE_DIR = Path("org/owasp/benchmark")
NEW_PACKAGE = "com.acme.app"
NEW_PACKAGE_DIR = Path("com/acme/app")
EXCLUDED_SUBDIRS = ("report",)
SUBPACKAGES = ("helpers", "testcode", "service")
KEEP_PREFIX = "org.owasp.esapi"

_SERVLET_PATH_RE = re.compile(r"/[a-z]+-\d{2}/BenchmarkTest(\d{5})")
_TESTCASE_RE = re.compile(r"BenchmarkTest(\d{5})")
_PROBLEM_RE = re.compile(r"Problem executing[^\"]*")
_PACKAGE_RE = re.compile(r"org\.owasp\.benchmark")
_SUBPACKAGE_DOT_RE = re.compile(r"org\.owasp\.benchmark\.(helpers|testcode|service)\b")
_SUBPACKAGE_SLASH_RE = re.compile(r"org/owasp/benchmark/(helpers|testcode|service)\b")
_BENCHMARK_RE = re.compile(r"benchmark", re.IGNORECASE)
_TESTCASE_WORD_RE = re.compile(r"test ?cases?", re.IGNORECASE)
_OWASP_RESIDUAL_RE = re.compile(r"owasp(?!\.esapi)", re.IGNORECASE)

# Leak search: anything below must be absent after removing the whitelist.
LEAK_TERMS = re.compile(
    r"owasp|benchmark|test ?cases?|expectedresults|real vulnerability|"
    r"sqli-|cmdi-|pathtraver|problem executing",
    re.IGNORECASE,
)


def _case_preserving_app(match: re.Match[str]) -> str:
    text = match.group(0)
    if text.isupper():
        return "APP"
    return "App" if text[0].isupper() else "app"


@dataclass
class Renamer:
    seed: str
    testcases: dict[str, str] = field(default_factory=dict)  # "00001" -> token

    def tok(self, number: str) -> str:
        if number not in self.testcases:
            self.testcases[number] = token(self.seed, number)
        return self.testcases[number]

    def subpackage(self, name: str) -> str:
        """Neutral, seed-derived name for a sub-package (letters and digits, starts with a letter)."""
        return token(self.seed, f"pkg:{name}", prefix="m", length=6)

    def apply(self, text: str) -> str:
        text = _SUBPACKAGE_DOT_RE.sub(lambda m: f"{NEW_PACKAGE}.{self.subpackage(m.group(1))}", text)
        text = _SUBPACKAGE_SLASH_RE.sub(
            lambda m: f"{NEW_PACKAGE_DIR.as_posix()}/{self.subpackage(m.group(1))}", text
        )
        text = _SERVLET_PATH_RE.sub(lambda m: f"/svc/{self.tok(m.group(1))}", text)
        text = _TESTCASE_RE.sub(lambda m: self.tok(m.group(1)), text)
        text = _PROBLEM_RE.sub("Operation failed", text)
        text = _PACKAGE_RE.sub(NEW_PACKAGE, text)
        text = _BENCHMARK_RE.sub(_case_preserving_app, text)
        text = _TESTCASE_WORD_RE.sub("scenario", text)
        return _OWASP_RESIDUAL_RE.sub("acme", text)


def check_pin(benchmark_dir: Path, pin: str) -> str:
    """Return the full HEAD SHA of ``benchmark_dir``; raise if it does not match ``pin``."""
    head = subprocess.run(
        ["git", "-C", str(benchmark_dir), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if not head.startswith(pin):
        raise SystemExit(f"BenchmarkJava HEAD {head} does not match pin {pin}")
    return head


def _target_rel(rel: Path, renamer: Renamer) -> Path:
    """Map a source-relative path (under src/main/java) to its path in the copy."""
    try:
        sub = rel.relative_to(SRC_PACKAGE_DIR)
    except ValueError:
        return Path(renamer.apply(rel.as_posix()))
    first = renamer.subpackage(sub.parts[0]) if sub.parts[0] in SUBPACKAGES else sub.parts[0]
    new = NEW_PACKAGE_DIR / first / Path(*sub.parts[1:])
    return Path(renamer.apply(new.as_posix()))


def build_copy(src_root: Path, out_dir: Path, seed: str) -> dict:
    """Copy ``src_root`` (a ``src/main/java`` tree) to ``out_dir`` with blanking and renaming."""
    renamer = Renamer(seed)
    files: dict[str, str] = {}
    skipped = 0
    for path in sorted(src_root.rglob("*.java")):
        rel = path.relative_to(src_root)
        parts = rel.parts
        if len(parts) > 3 and Path(*parts[:3]) == SRC_PACKAGE_DIR and parts[3] in EXCLUDED_SUBDIRS:
            skipped += 1
            continue
        data = path.read_bytes()
        blanked = blank_comments(data)
        text = renamer.apply(blanked.decode("utf-8"))
        target = out_dir / _target_rel(rel, renamer)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))
        files[rel.as_posix()] = target.relative_to(out_dir).as_posix()
    return {
        "testcases": dict(sorted(renamer.testcases.items())),
        "files": files,
        "excluded_report_files": skipped,
    }


def leak_search(root: Path) -> list[tuple[str, str]]:
    """Case-insensitive leak search over file paths and contents (whitelist: org.owasp.esapi)."""
    hits: list[tuple[str, str]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        for target, label in ((rel, "path"), (path.read_text(encoding="utf-8"), "content")):
            cleaned = target.replace(KEEP_PREFIX, "")
            match = LEAK_TERMS.search(cleaned)
            if match:
                hits.append((rel, f"{label}: {match.group(0)}"))
    return hits


def verify_copy(src_root: Path, out_dir: Path, name_map: dict) -> dict:
    """Checks required by v3.3 §5.2 B3b. Returns a result dict; ``ok`` is the overall verdict."""
    problems: list[str] = []
    leaks = leak_search(out_dir)
    if leaks:
        problems.append(f"{len(leaks)} leak hits, first: {leaks[0]}")

    line_mismatch = 0
    new_parse_errors = 0
    missing_imports = 0
    import_re = re.compile(rf"^import\s+({re.escape(NEW_PACKAGE)}\.[\w.]+);", re.MULTILINE)
    for src_rel, out_rel in name_map["files"].items():
        src_bytes = (src_root / src_rel).read_bytes()
        out_bytes = (out_dir / out_rel).read_bytes()
        if src_bytes.count(b"\n") != out_bytes.count(b"\n"):
            line_mismatch += 1
        if count_errors(out_bytes) > count_errors(src_bytes):
            new_parse_errors += 1
        for imp in import_re.findall(out_bytes.decode("utf-8")):
            if not (out_dir / (imp.replace(".", "/") + ".java")).is_file():
                missing_imports += 1
    if line_mismatch:
        problems.append(f"{line_mismatch} files changed line count")
    if new_parse_errors:
        problems.append(f"{new_parse_errors} files gained parse errors")
    if missing_imports:
        problems.append(f"{missing_imports} imports point to missing files")

    for name in SUBPACKAGES:
        if (out_dir / NEW_PACKAGE_DIR / name).exists():
            problems.append(f"sub-package directory {name!r} still present")
    leftover = [p for p in out_dir.rglob("*") if p.is_dir() and p.name in SUBPACKAGES]
    if leftover:
        problems.append(f"{len(leftover)} directories still named like an original sub-package")

    tokens = list(name_map["testcases"].values())
    if len(set(tokens)) != len(tokens):
        problems.append("token collision")
    return {
        "ok": not problems,
        "problems": problems,
        "files": len(name_map["files"]),
        "leak_hits": len(leaks),
    }


def _safe_reset(out_dir: Path) -> None:
    if out_dir.exists():
        if "repos" not in out_dir.parts:
            raise SystemExit(f"refusing to delete {out_dir}: not under a 'repos' directory")
        shutil.rmtree(out_dir)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--benchmark-dir", type=Path, required=True)
    ap.add_argument("--pin", required=True, help="BenchmarkJava commit (full or prefix)")
    ap.add_argument("--out", type=Path, required=True, help="repos/java/<copy name>")
    ap.add_argument("--work-dir", type=Path, required=True, help="outside the repo")
    ap.add_argument("--seed", required=True)
    ap.add_argument("--force", action="store_true", help="replace an existing copy")
    args = ap.parse_args(argv)

    head = check_pin(args.benchmark_dir, args.pin)
    if args.out.exists():
        if not args.force:
            raise SystemExit(f"{args.out} exists; use --force to rebuild")
        _safe_reset(args.out)
    args.work_dir.mkdir(parents=True, exist_ok=True)

    src_root = args.benchmark_dir / SRC_SUBDIR
    name_map = build_copy(src_root, args.out, args.seed)
    result = verify_copy(src_root, args.out, name_map)

    name_map.update(
        {
            "source_commit": head,
            "seed": args.seed,
            "copy_name": args.out.name,
            "tree_sha256": tree_hash(args.out),
        }
    )
    map_path = args.work_dir / "name_map.json"
    map_path.write_text(json.dumps(name_map, indent=2, sort_keys=True), encoding="utf-8")
    (args.work_dir / "name_map.json.sha256").write_text(
        f"{file_sha256(map_path)}  name_map.json\n", encoding="utf-8"
    )
    report = {k: result[k] for k in ("ok", "problems", "files", "leak_hits")}
    report["tree_sha256"] = name_map["tree_sha256"]
    report["excluded_report_files"] = name_map["excluded_report_files"]
    report["testcases"] = len(name_map["testcases"])
    print(json.dumps(report, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
