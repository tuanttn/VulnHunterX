"""Shared Java helpers for the paper-experiment data scripts (day 2).

Pure functions on bytes/str. No network, no model calls. Tree-sitter is used to
find comments and methods so that blanking and line mapping are exact.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import tree_sitter
import tree_sitter_java


@lru_cache(maxsize=1)
def _parser() -> tree_sitter.Parser:
    return tree_sitter.Parser(tree_sitter.Language(tree_sitter_java.language()))


def parse(source: bytes) -> tree_sitter.Tree:
    return _parser().parse(source)


def count_errors(source: bytes) -> int:
    """Number of ERROR or MISSING nodes in the parse tree (0 = parses cleanly)."""
    tree = parse(source)
    if not tree.root_node.has_error:
        return 0
    count = 0
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            count += 1
        stack.extend(node.children)
    return max(count, 1)


def _walk(node: tree_sitter.Node) -> Iterator[tree_sitter.Node]:
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(cur.children))


def blank_comments(source: bytes) -> bytes:
    """Replace every comment byte with a space, keeping CR/LF.

    Byte length and line count are unchanged, so line numbers in the original
    still point at the same code.
    """
    out = bytearray(source)
    for node in _walk(parse(source).root_node):
        if node.type in ("line_comment", "block_comment"):
            for i in range(node.start_byte, node.end_byte):
                if out[i] not in (0x0A, 0x0D):
                    out[i] = 0x20
    return bytes(out)


@dataclass(frozen=True)
class MethodSpan:
    name: str
    start_line: int  # 1-based, inclusive
    end_line: int  # 1-based, inclusive


def method_spans(source: bytes) -> list[MethodSpan]:
    """All method and constructor declarations with their 1-based line range."""
    spans: list[MethodSpan] = []
    for node in _walk(parse(source).root_node):
        if node.type in ("method_declaration", "constructor_declaration"):
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            spans.append(
                MethodSpan(
                    name=source[name_node.start_byte : name_node.end_byte].decode(
                        "utf-8", "replace"
                    ),
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                )
            )
    return spans


def enclosing_method(spans: list[MethodSpan], line: int) -> MethodSpan | None:
    """Innermost method whose range contains ``line``."""
    best: MethodSpan | None = None
    for span in spans:
        if span.start_line <= line <= span.end_line and (
            best is None or (span.end_line - span.start_line) < (best.end_line - best.start_line)
        ):
            best = span
    return best


def token(seed: str, key: str, prefix: str = "T", length: int = 10) -> str:
    """Deterministic pseudo-random identifier token from a seed and a key."""
    return prefix + hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()[:length]


def tree_hash(root: Path) -> str:
    """SHA-256 over sorted (relative path, content hash) pairs of every file."""
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        h.update(rel.encode())
        h.update(b"\0")
        h.update(hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
