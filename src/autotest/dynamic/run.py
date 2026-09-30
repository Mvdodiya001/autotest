"""Dynamic run orchestration (M4.1): session + probes + analyzers.

Interaction in M4.1 is minimal (launch main activity, dwell for callbacks);
the scripted tap matrix lands with the hybrid interaction step.
"""

from __future__ import annotations

import subprocess
from typing import Any

from . import analyzers, probe
from .collect import merge_reports, pull_logcat
from .session import DynamicSession


def collect_probes(package: str, components: list[str]) -> dict[str, Any]:
    return {
        "exported": probe.probe_exported(components),
        "jdwp": probe.jdwp_packages(),
    }


def launch_main(package: str, activity: str) -> bool:
    try:
        proc = subprocess.run(
            ["adb", "shell", "am", "start", "-n", f"{package}/{activity}"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def run_dynamic(
    session: DynamicSession, static_report: dict[str, Any], main_activity: str = ""
) -> tuple[dict[str, Any], list]:
    """Full dynamic pass. Returns (dynamic_report, verifications)."""
    package = str(static_report.get("package_name", ""))
    session.setup()
    try:
        if package and main_activity:
            launch_main(package, main_activity)
        exported = [c for c in static_report.get("exported_activities", []) if c]
        mobsf_report = session.collect()
        report = merge_reports(
            mobsf_report, pull_logcat(package), collect_probes(package, exported)
        )
        return report, analyzers.run_all(static_report, report)
    finally:
        session.teardown()
