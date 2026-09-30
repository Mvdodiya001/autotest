"""Backward-compatible facade over the split MobSF clients (DIP seam).

New code should depend on mobsf.transport / mobsf.static_client /
mobsf.dynamic_client (or the Scanner abstraction) instead of this class.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .mobsf import DynamicAnalysisClient, MobSFError, MobSFTransport, StaticAnalysisClient

__all__ = ["MobSFClient", "MobSFError"]


class MobSFClient:
    """Legacy combined client: static + dynamic over one transport."""

    def __init__(self, base_url: str, api_key: str, timeout: int = 20, scan_timeout: int = 600):
        transport = MobSFTransport(base_url, api_key, timeout, scan_timeout)
        self._static = StaticAnalysisClient(transport)
        self._dynamic = DynamicAnalysisClient(transport)

    def _post(self, path: str, timeout: int | None = None, **kwargs: Any) -> Any:
        return self._static.transport.post(path, timeout=timeout, **kwargs)

    def upload(self, apk: str | Path) -> dict:
        return self._static.upload(apk)

    def scan(self, file_name: str, file_hash: str) -> dict:
        return self._static.scan(file_name, file_hash)

    def report_json(self, file_hash: str) -> dict:
        return self._static.report_json(file_hash)

    def full_static_report(self, apk: str | Path) -> tuple[dict, str]:
        return self._static.full_static_report(apk)

    def dynamic_start(self, file_hash: str) -> dict:
        return self._dynamic.start(file_hash)

    def dynamic_stop(self, file_hash: str) -> dict:
        return self._dynamic.stop(file_hash)

    def dynamic_report(self, file_hash: str) -> dict:
        return self._dynamic.report(file_hash)
