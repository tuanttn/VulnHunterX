# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Per-call JSONL log for model completions.

One line per ``litellm.completion`` made by an ``LLMClient`` that has a call
logger: run labels, the requested and the **returned** model ID, client
version, token counts, latency and which sampling parameters were sent. Prompt
and response text are never written; error records keep only the exception
type and HTTP status, because provider error bodies can echo request data.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

CallLogger = Callable[[dict[str, Any]], None]


def litellm_version() -> str:
    """Installed litellm version (the model client version), or "" if unknown."""
    try:
        return metadata.version("litellm")
    except metadata.PackageNotFoundError:
        return ""


def utc_now() -> str:
    return datetime.now(tz=UTC).isoformat()


class JsonlCallLog:
    """Thread-safe append-only JSONL writer usable as an ``LLMClient`` call logger.

    Several clients (one per verified alert, possibly in parallel workers) may
    share one instance; each record is written as a single line under a lock.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def __call__(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")


_SHARED: dict[Path, JsonlCallLog] = {}
_SHARED_LOCK = threading.Lock()


def shared_call_log(path: str | Path) -> JsonlCallLog:
    """Return the process-wide writer for ``path`` so all workers share one lock."""
    resolved = Path(path).resolve()
    with _SHARED_LOCK:
        log = _SHARED.get(resolved)
        if log is None:
            log = _SHARED[resolved] = JsonlCallLog(resolved)
        return log
