"""MobSF dynamic-analysis client (SRP: session endpoints only)."""

from __future__ import annotations

from .transport import MobSFTransport


class DynamicAnalysisClient:
    def __init__(self, transport: MobSFTransport):
        self.transport = transport

    def start(self, file_hash: str) -> dict:
        return self.transport.post(
            "/api/v1/dynamic/start_analysis",
            timeout=self.transport.scan_timeout,
            data={"hash": file_hash},
        )

    def stop(self, file_hash: str) -> dict:
        return self.transport.post(
            "/api/v1/dynamic/stop_analysis",
            timeout=self.transport.scan_timeout,
            data={"hash": file_hash},
        )

    def report(self, file_hash: str) -> dict:
        return self.transport.post(
            "/api/v1/dynamic/report_json",
            timeout=self.transport.scan_timeout,
            data={"hash": file_hash},
        )
