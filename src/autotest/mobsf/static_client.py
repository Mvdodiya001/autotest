"""MobSF static-analysis client (SRP: upload/scan/report only)."""

from __future__ import annotations

from pathlib import Path

from .transport import MobSFTransport


class StaticAnalysisClient:
    def __init__(self, transport: MobSFTransport):
        self.transport = transport

    def upload(self, apk: str | Path) -> dict:
        apk = Path(apk)
        with open(apk, "rb") as f:
            return self.transport.post(
                "/api/v1/upload",
                files={"file": (apk.name, f, "application/octet-stream")},
            )

    def scan(self, file_name: str, file_hash: str) -> dict:
        return self.transport.post(
            "/api/v1/scan",
            timeout=self.transport.scan_timeout,
            data={"scan_type": "apk", "file_name": file_name, "hash": file_hash},
        )

    def report_json(self, file_hash: str) -> dict:
        return self.transport.post(
            "/api/v1/report_json",
            timeout=self.transport.scan_timeout,
            data={"hash": file_hash},
        )

    def full_static_report(self, apk: str | Path) -> tuple[dict, str]:
        """Upload + scan + fetch report. Returns (report, md5 hash)."""
        up = self.upload(apk)
        file_hash = up["hash"]
        self.scan(Path(apk).name, file_hash)
        return self.report_json(file_hash), file_hash
