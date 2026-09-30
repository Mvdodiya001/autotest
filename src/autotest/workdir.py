"""Workdir layout (M0): one dir per scan, stable file names."""

from __future__ import annotations

from pathlib import Path

FINDINGS = "findings.json"
MOBSF_REPORT = "mobsf_report.json"
UNPACKED = "unpacked"


class Workdir:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def create(self) -> Workdir:
        (self.root / UNPACKED).mkdir(parents=True, exist_ok=True)
        return self

    @property
    def findings_path(self) -> Path:
        return self.root / FINDINGS

    @property
    def mobsf_report_path(self) -> Path:
        return self.root / MOBSF_REPORT

    @property
    def unpacked_dir(self) -> Path:
        return self.root / UNPACKED
