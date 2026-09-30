"""Scanner abstraction (DIP/OCP): pipeline depends on this, not on MobSF.

Add a backend by subclassing Scanner and extending `for_settings` — no
pipeline changes needed (this is how the vendored-tree `LocalScanner` lands).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from .config import Settings
from .mobsf import MobSFTransport, StaticAnalysisClient


class Scanner(ABC):
    name: str = "base"

    @abstractmethod
    def analyze(self, apk: str | Path) -> tuple[dict[str, Any], str]:
        """Run static analysis. Returns (report_dict, mobsf_hash)."""


class NullScanner(Scanner):
    """Ingest-only backend: no static analysis (M0 behavior, offline tests)."""

    name = "none"

    def analyze(self, apk: str | Path) -> tuple[dict[str, Any], str]:
        return {}, ""


class ApiScanner(Scanner):
    """MobSF Docker REST backend."""

    name = "api"

    def __init__(self, settings: Settings):
        transport = MobSFTransport(
            settings.mobsf_url,
            settings.mobsf_api_key,
            settings.request_timeout,
            settings.mobsf_scan_timeout,
        )
        self.client = StaticAnalysisClient(transport)

    def analyze(self, apk: str | Path) -> tuple[dict[str, Any], str]:
        return self.client.full_static_report(apk)


def for_settings(settings: Settings) -> Scanner:
    if settings.scanner_backend == "api":
        return ApiScanner(settings)
    if settings.scanner_backend == "none":
        return NullScanner()
    raise ValueError(f"unknown scanner backend: {settings.scanner_backend}")
