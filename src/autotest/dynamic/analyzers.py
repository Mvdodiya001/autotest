"""Analyzer interface (M4.0 skeleton).

Each analyzer maps a static slice + dynamic report to Verifications.
M4.1 fills in: logcat leak, exported launch, cleartext, debuggable.
M4.2 adds: crypto hooks, permission-API map.
"""

from __future__ import annotations

from typing import Any, Protocol

from ..models import Verification


class Analyzer(Protocol):
    name: str

    def analyze(
        self, static_report: dict[str, Any], dynamic_report: dict[str, Any]
    ) -> list[Verification]: ...


ANALYZERS: list[Analyzer] = []


def register(analyzer: Analyzer) -> Analyzer:
    ANALYZERS.append(analyzer)
    return analyzer


def run_all(static_report: dict[str, Any], dynamic_report: dict[str, Any]) -> list[Verification]:
    out: list[Verification] = []
    for analyzer in ANALYZERS:
        out.extend(analyzer.analyze(static_report, dynamic_report))
    return out
