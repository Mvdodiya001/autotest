"""Dynamic session (M4.0): install -> start_analysis -> interact -> report -> stop."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..mobsf_client import MobSFClient
from . import env as env_mod


@dataclass
class DynamicSession:
    client: MobSFClient
    apk: Path
    file_hash: str = ""
    package: str = ""
    report: dict[str, Any] = field(default_factory=dict)

    def setup(self) -> DynamicSession:
        env_mod.ensure_emulator()
        env_mod.install_apk(self.apk)
        up = self.client.upload(self.apk)
        self.file_hash = up["hash"]
        self.client.dynamic_start(self.file_hash)
        return self

    def collect(self) -> dict[str, Any]:
        self.report = self.client.dynamic_report(self.file_hash)
        return self.report

    def teardown(self) -> None:
        try:
            if self.file_hash:
                self.client.dynamic_stop(self.file_hash)
        except Exception:  # noqa: BLE001,S110 - best-effort cleanup on teardown path
            pass
