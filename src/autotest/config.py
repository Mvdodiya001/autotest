"""Configuration (M0): env vars + explicit flags, pydantic-validated."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTOTEST_", extra="ignore")

    mobsf_url: str = Field(default="http://127.0.0.1:8000")
    mobsf_api_key: str = Field(default="")
    request_timeout: int = Field(default=20, ge=1, le=300)
    # Static analysis of a fresh APK can take minutes -> separate budget.
    mobsf_scan_timeout: int = Field(default=600, ge=30, le=3600)
    workdir: Path = Field(default=Path("/tmp/opencode/autotest"))
    # External mobsf-lab checkout (start-emulator.sh). Not vendored in this repo.
    lab_dir: Path = Field(default_factory=lambda: Path.home() / "mobsf-lab")
    # Bound for the read-only UI pass and Frida hook collection. 0 skips taps.
    dynamic_dwell: int = Field(default=60, ge=0, le=3600)

    # Scanner backend: "api" (docker REST), "local" (vendored tree, later), "none" (ingest only).
    scanner_backend: str = Field(default="api")


def load(overrides: dict | None = None) -> Settings:
    return Settings(**(overrides or {}))
