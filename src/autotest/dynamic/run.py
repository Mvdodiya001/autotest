"""Dynamic run orchestration: exercise the app, then collect logcat and probes.

Observe-only Frida hooks are spawned before launch and stay attached through
the exercise. They stop when that pass returns, so startup crypto is in the
window. A missing Frida toolchain is inconclusive for the two hook checks only.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ..models import Verdict, Verification
from . import analyzers, exercise, frida_run, probe
from . import env as env_mod
from .collect import merge_reports, pull_logcat
from .session import DynamicSession


def collect_probes(package: str, components: list[str], serial: str = "") -> dict[str, Any]:
    return {
        "exported": probe.probe_exported(components, serial=serial),
        "jdwp": probe.jdwp_packages(serial=serial),
    }


def launch_main(package: str, activity: str, serial: str = "") -> bool:
    try:
        proc = subprocess.run(
            ["adb", "shell", "am", "start", "-n", f"{package}/{activity}"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=env_mod.adb_environ(serial),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _activity_probes(interaction: dict[str, Any]) -> list[dict[str, Any]]:
    activities = (interaction.get("exported") or {}).get("activities") or []
    return [
        {
            "component": row.get("component", ""),
            "launched": row.get("result") == "started",
            "evidence": row.get("evidence", ""),
        }
        for row in activities
        if isinstance(row, dict)
    ]


_OBSERVE_SCRIPTS = ("crypto_hooks.js", "api_map.js")


def _frida_gaps(verdicts: list[Verification], error: str) -> list[Verification]:
    """Inconclusive stand-ins so a missing Frida does not drop the two hook checks."""
    if not error:
        return []
    missing: list[Verification] = []
    covered = {v.verifier for v in verdicts}
    if "dynamic:crypto-hooks" not in covered:
        missing.append(
            Verification(
                candidate_id="dyn:crypto:unavailable",
                verifier="dynamic:crypto-hooks",
                verdict=Verdict.INCONCLUSIVE,
                evidence=f"frida unavailable: {error}"[:300],
            )
        )
    if "dynamic:perm-api-map" not in covered:
        missing.append(
            Verification(
                candidate_id="dyn:permapi:unavailable",
                verifier="dynamic:perm-api-map",
                verdict=Verdict.INCONCLUSIVE,
                evidence=f"frida unavailable: {error}"[:300],
            )
        )
    return missing


def run_dynamic(
    session: DynamicSession,
    static_report: dict[str, Any],
    main_activity: str = "",
    lab_dir: str | Path | None = None,
    dwell: int = 60,
    skip_frida: bool = False,
) -> tuple[dict[str, Any], list]:
    """Full dynamic pass. Returns (dynamic_report, verifications)."""
    package = str(static_report.get("package_name", ""))
    session.setup(lab_dir=lab_dir)
    serial = session.serial
    hooks: frida_run.HookSession | None = None
    frida_error = ""
    try:
        if package and not skip_frida:
            try:
                hooks = frida_run.start_hooks(
                    package, _OBSERVE_SCRIPTS, dwell=dwell, serial=serial
                )
            except frida_run.FridaUnavailable as exc:
                frida_error = str(exc)
        if package and main_activity:
            launch_main(package, main_activity, serial=serial)
        interaction = exercise.exercise_app(static_report, serial=serial, dwell=dwell)
        hits: list[dict[str, Any]] = []
        if hooks is not None:
            found, stop_error = hooks.finish()
            hits = [{"hook": hit.hook, "detail": hit.detail} for hit in found]
            if stop_error:
                frida_error = frida_error or stop_error
        mobsf_report = session.collect()
        report = merge_reports(
            mobsf_report,
            pull_logcat(package, serial=serial),
            {"exported": _activity_probes(interaction), "jdwp": probe.jdwp_packages(serial=serial)},
        )
        report["exported"] = interaction["exported"]
        report["deeplinks"] = interaction["deeplinks"]
        report["ui"] = interaction["ui"]
        if package and not skip_frida:
            report.setdefault("autotest", {})["hooks"] = hits
            if frida_error:
                report["autotest"]["frida_error"] = frida_error
        verdicts = analyzers.run_all(static_report, report)
        if not skip_frida:
            verdicts = [*verdicts, *_frida_gaps(verdicts, frida_error)]
        return report, verdicts
    finally:
        if hooks is not None:
            try:
                hooks.finish()
            except Exception:  # noqa: BLE001,S110 - teardown must still run
                pass
        session.teardown()
