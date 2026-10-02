"""Live probers (M4.1): read-only adb checks whose results feed the analyzers.

- probe_exported: `am start` each exported component, parse success from output.
- probe_jdwp: `adb jdwp` lists debuggable PIDs; map PID -> package via ps.
"""

from __future__ import annotations

import re
import subprocess

from . import env as env_mod


def am_start(component: str, serial: str = "") -> tuple[bool, str]:
    """Try launching COMPONENT (pkg/.Activity). Returns (launched, one-line evidence)."""
    try:
        proc = subprocess.run(
            ["adb", "shell", "am", "start", "-n", component],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=env_mod.adb_environ(serial),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"probe error: {type(e).__name__}"
    out = (proc.stdout + proc.stderr).strip().replace("\n", " ")
    if re.search(r"Error|Exception|not found|does not exist|Permission Denial", out, re.IGNORECASE):
        return False, out[:200]
    if re.search(r"Starting|Status: ok", out, re.IGNORECASE):
        return True, out[:200]
    return False, out[:200] or "no output"


def probe_exported(components: list[str], serial: str = "") -> list[dict[str, object]]:
    return [
        {"component": c, "launched": ok, "evidence": ev}
        for c in components
        for ok, ev in [am_start(c, serial=serial)]
    ]


def jdwp_packages(serial: str = "") -> list[str]:
    """Packages with a JDWP (debuggable) process. Empty list = none / adb down."""
    try:
        pids = env_mod._adb("jdwp", serial=serial, timeout=30).split()
    except env_mod.DynamicEnvError:
        return []
    if not pids:
        return []
    try:
        ps = env_mod._adb("shell ps -A -o PID,NAME", serial=serial, timeout=30)
    except env_mod.DynamicEnvError:
        return []
    pid_to_name = {}
    for line in ps.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            pid_to_name[parts[0]] = parts[-1]
    return sorted({pid_to_name[p] for p in pids if p in pid_to_name})
