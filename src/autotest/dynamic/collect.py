"""Autotest-owned dynamic collection (M4.1): adb logcat pull + MobSF report merge.

MobSF's dynamic report covers urls/domains; logcat and probes come from adb
(first-party evidence, no reliance on MobSF's test cycle).
"""

from __future__ import annotations

from typing import Any

from . import env as env_mod


def pull_logcat(package: str, max_lines: int = 4000, serial: str = "") -> list[str]:
    """Last logcat lines mentioning the package (or its log TAGs)."""
    try:
        out = env_mod._adb("logcat", "-d", "-v", "brief", serial=serial, timeout=60)
    except env_mod.DynamicEnvError:
        return []
    lines = out.splitlines()[-max_lines:]
    tag = package.split(".")[-1].upper()
    return [ln for ln in lines if package in ln or tag in ln or "FAM_CTF" in ln]


def merge_reports(
    mobsf_report: dict[str, Any], logcat: list[str], probes: dict[str, Any]
) -> dict[str, Any]:
    merged = dict(mobsf_report)
    merged["logcat"] = logcat
    merged.setdefault("autotest", {})["probes"] = probes
    urls = {u for u in merged.get("urls", []) if isinstance(u, str)}
    merged["urls"] = sorted(urls)
    return merged
